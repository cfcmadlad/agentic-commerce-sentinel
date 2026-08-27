"""FastAPI service: submit a session, get a verdict and an audit trail back.

Wraps the full four-layer pipeline behind three endpoints: register an
agent's signing key, submit a session for a decision, and read back the
append-only audit record a decision produced. Everything here is a thin
adapter over the same modules the offline evaluation harness uses --
`detect.baseline`, `detect.ensemble`, `detect.attribution`,
`reasoning.narrate` -- not a second implementation of any of them.

Run locally:

    uvicorn service.main:app --reload

The first request after startup (or the startup itself, depending on
`--reload` behavior) pays the cost of fitting Layer 3 against the same
20,000-session corpus `run_milestone_b.py` reports on -- see
`service/state.py` for why that tradeoff is deliberate.
"""

from __future__ import annotations

import base64
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID, uuid4

import numpy as np
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from detect.attribution import compute_attribution
from detect.baseline import BaselineDecision
from detect.ensemble import ensemble_decide
from detect.scope import enforce_scope
from features.session import feature_names
from mandate.verification import verify_mandate
from reasoning.narrate import build_narration_input, narrate
from reasoning.schema import AuditRecord
from service.demo_seed import seed_demo_history
from service.middleware import RateLimitMiddleware, RequestLoggingMiddleware
from service.schemas import (
    AttributionRowOut,
    DecideRequest,
    SessionDecisionResponse,
    attribution_row_to_out,
    baseline_to_out,
    ensemble_to_out,
    narration_to_out,
)
from service.state import AppState, build_app_state

logger = logging.getLogger(__name__)

NARRATION_UNAVAILABLE_TEXT = (
    "Narration unavailable: this service instance has no GROQ_API_KEY configured, "
    "so Layer 4 was not consulted. The verdict above is unaffected -- narration is "
    "always best-effort and never a precondition for a decision."
)
NARRATION_UNAVAILABLE_MODEL = "none (narration disabled)"

_DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


def _cors_origins() -> list[str]:
    """Reads allowed CORS origins from the environment, with a local-dev default.

    Returns:
        The configured origin list.
    """
    raw = os.environ.get("SENTINEL_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Builds the shared application state once, at process startup.

    Args:
        app: The FastAPI application.

    Yields:
        Control back to FastAPI for the process's serving lifetime.
    """
    app.state.app_state = build_app_state()
    seed_demo_history(app.state.app_state)
    yield


app = FastAPI(title="Agentic-Commerce Transaction Sentinel API", version="0.1.0", lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Maps any unhandled exception to a generic 500, never a raw stack trace.

    Args:
        request: The request that triggered the exception.
        exc: The exception raised.

    Returns:
        A 500 response with a generic message. The full exception is
        logged server-side via `logging.exception` for operator visibility.
    """
    logger.exception("unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse({"detail": "internal error"}, status_code=500)


def get_state(request: Request) -> AppState:
    """FastAPI dependency returning the shared application state.

    Args:
        request: The current request, used to reach `app.state`.

    Returns:
        The application state built at startup.
    """
    state: AppState = request.app.state.app_state
    return state


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check.

    Returns:
        A constant status payload.
    """
    return {"status": "ok"}


class DemoAgentOut(BaseModel):
    """One demo agent's identity and signing key, for exploratory testing."""

    agent_id: str
    key_id: str
    private_key_hex: str


@app.get("/agents/demo", response_model=list[DemoAgentOut])
def list_demo_agents(state: AppState = Depends(get_state)) -> list[DemoAgentOut]:
    """Lists the agents registered at startup, private keys included.

    Args:
        state: The shared application state.

    Returns:
        Every demo agent. See `service.state.DemoAgent` for why exposing
        the private key here is safe: it is deterministically derivable
        from a public seed string, not a secret, and every session in this
        project is synthetic and defense-only.
    """
    return [
        DemoAgentOut(agent_id=a.agent_id, key_id=a.key_id, private_key_hex=a.private_key.private_bytes_raw().hex())
        for a in state.demo_agents
    ]


class RegisterAgentRequest(BaseModel):
    """A request to register a new agent's public signing key."""

    agent_id: str
    key_id: str
    public_key_base64: str


class RegisterAgentResponse(BaseModel):
    """Confirmation that an agent's key was registered."""

    agent_id: str
    key_id: str
    registered: bool


@app.post("/agents/register", response_model=RegisterAgentResponse)
def register_agent(payload: RegisterAgentRequest, state: AppState = Depends(get_state)) -> RegisterAgentResponse:
    """Registers a public key as valid for a given agent.

    Args:
        payload: The agent identity and public key to register.
        state: The shared application state.

    Returns:
        Confirmation of the registration.

    Raises:
        HTTPException: 400, if `public_key_base64` is not valid base64 or
            not a valid Ed25519 public key -- a caller error, reported
            clearly rather than surfacing as a 500.
    """
    try:
        raw = base64.b64decode(payload.public_key_base64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, InvalidKey) as error:
        raise HTTPException(status_code=400, detail=f"invalid Ed25519 public key: {error}") from error

    state.registry.register(payload.agent_id, payload.key_id, public_key)
    logger.info("registered agent %s (%s)", payload.agent_id, payload.key_id)
    return RegisterAgentResponse(agent_id=payload.agent_id, key_id=payload.key_id, registered=True)


@app.post("/sessions/decide", response_model=SessionDecisionResponse)
def decide(payload: DecideRequest, state: AppState = Depends(get_state)) -> SessionDecisionResponse:
    """Runs one session through all four layers and returns the full decision.

    Args:
        payload: The session and the mandate presented alongside it.
        state: The shared application state.

    Returns:
        The full decision record: Layer 1/2 verdict, the combined
        ensemble verdict, per-feature attribution (if Layer 3 was
        consulted), and a Layer 4 narrative (if a narration client is
        configured for this service instance).
    """
    trace = payload.trace
    signed = payload.signed_mandate

    if signed is None:
        scope_result = enforce_scope(trace, None)
        baseline = BaselineDecision(
            session_id=trace.session_id, blocked=True, verification_reasons=(), scope_reasons=scope_result.reasons
        )
    else:
        verification = verify_mandate(signed, state.registry, state.ledger, now=trace.started_at)
        scope_result = enforce_scope(trace, signed)
        blocked = not verification.valid or not scope_result.in_scope
        if not blocked:
            state.ledger.record_usage(signed.mandate.mandate_id)
        baseline = BaselineDecision(
            session_id=trace.session_id,
            blocked=blocked,
            verification_reasons=verification.reasons,
            scope_reasons=scope_result.reasons,
        )

    feature_values = state.extractor.extract(trace)
    ordered = [[feature_values[name] for name in feature_names()]]
    design_matrix = np.array(ordered, dtype=np.float64)

    behavioral_score = None if baseline.blocked else float(state.model.predict_proba(design_matrix)[0])
    ensemble = ensemble_decide(baseline, behavioral_score, state.threshold)

    attribution_out: list[AttributionRowOut] | None = None
    attribution_result = None
    if behavioral_score is not None:
        attribution_result = compute_attribution(state.model, design_matrix)
        attribution_out = attribution_row_to_out(attribution_result, 0)

    narrative_out = None
    if state.narration_client is not None:
        narration_input = build_narration_input(
            trace,
            baseline,
            ensemble,
            attribution=attribution_result,
            row_index=0 if attribution_result is not None else None,
            threshold=state.threshold,
        )
        narration = narrate(narration_input, state.narration_client, model=state.narration_model)
        narrative_out = narration_to_out(narration)
        narrative_text = narration.narrative
        narrated_by = narration.model
    else:
        narrative_text = NARRATION_UNAVAILABLE_TEXT
        narrated_by = NARRATION_UNAVAILABLE_MODEL

    top_features = tuple(
        (row.feature, row.shap_value) for row in (attribution_out or [])
    )
    state.audit_log.append(
        AuditRecord(
            record_id=uuid4(),
            session_id=trace.session_id,
            mandate_id=trace.mandate_id,
            blocked=ensemble.blocked,
            source=ensemble.source,
            rules_fired=ensemble.rules_fired,
            behavioral_score=ensemble.behavioral_score,
            top_features=top_features,
            narrative=narrative_text,
            narrated_by_model=narrated_by,
            created_at=datetime.now(UTC),
        )
    )

    return SessionDecisionResponse(
        session_id=trace.session_id,
        baseline=baseline_to_out(baseline),
        ensemble=ensemble_to_out(ensemble),
        attribution=attribution_out,
        narrative=narrative_out,
    )


class AuditRecordOut(BaseModel):
    """Wire form of one `reasoning.audit_log.AuditRecord`."""

    record_id: UUID
    session_id: UUID
    mandate_id: UUID | None
    blocked: bool
    source: str
    rules_fired: list[str]
    behavioral_score: float | None
    top_features: list[tuple[str, float]]
    narrative: str
    narrated_by_model: str
    created_at: datetime


@app.get("/audit/{session_id}", response_model=list[AuditRecordOut])
def get_audit(session_id: UUID, state: AppState = Depends(get_state)) -> list[AuditRecordOut]:
    """Returns every audit record for a given session, oldest first.

    Args:
        session_id: The session to look up.
        state: The shared application state.

    Returns:
        Every matching record. Usually zero or one; more than one is
        possible if a session was decided more than once (see
        `reasoning.schema.AuditRecord`'s docstring on why `record_id` is
        distinct from `session_id`).
    """
    records = [r for r in state.audit_log.read_all() if r.session_id == session_id]
    return [
        AuditRecordOut(
            record_id=r.record_id,
            session_id=r.session_id,
            mandate_id=r.mandate_id,
            blocked=r.blocked,
            source=r.source,
            rules_fired=list(r.rules_fired),
            behavioral_score=r.behavioral_score,
            top_features=list(r.top_features),
            narrative=r.narrative,
            narrated_by_model=r.narrated_by_model,
            created_at=r.created_at,
        )
        for r in records
    ]
