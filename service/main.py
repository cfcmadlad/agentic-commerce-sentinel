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
20,000-session corpus `run_full_eval.py` reports on -- see
`service/state.py` for why that tradeoff is deliberate.
"""

from __future__ import annotations

import base64
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import numpy as np
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from common.schema import SessionTrace
from counterfactual.deterministic import Counterfactual as DeterministicCounterfactual
from counterfactual.deterministic import scope_counterfactual, verification_counterfactual
from detect.attribution import compute_attribution
from detect.baseline import BaselineDecision
from detect.ensemble import SOURCE_BEHAVIORAL, SOURCE_RULES, EnsembleDecision, ensemble_decide
from detect.scope import enforce_scope
from escalation.queue import EscalationNotFoundError, HumanActionRequiredError, InvalidTransitionError
from escalation.schema import EscalationStatus, ResolutionDecision
from features.session import feature_names
from mandate.verification import KeyRevocation, KeyRevocationReason, verify_mandate
from reasoning.narrate import build_narration_input, narrate
from reasoning.schema import AuditRecord, Counterfactual, CounterfactualEdit
from service.delegation_chain import build_delegation_chain
from service.demo_seed import seed_demo_history
from service.middleware import (
    DEFAULT_MAX_REQUESTS_PER_WINDOW,
    DEFAULT_WINDOW_SECONDS,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
)
from service.schemas import (
    AttributionRowOut,
    CircuitBreakerResetRequest,
    CircuitBreakerStatusOut,
    CounterfactualOut,
    DecideRequest,
    DelegationChainOut,
    EscalationOut,
    KeyRevocationOut,
    ResolveEscalationRequest,
    ReviewEscalationRequest,
    RevokeKeyRequest,
    RotateKeyRequest,
    SessionDecisionResponse,
    attribution_row_to_out,
    baseline_to_out,
    counterfactual_to_out,
    ensemble_to_out,
    escalation_to_out,
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

NARRATION_FAILED_TEXT = (
    "Narration unavailable: the Layer 4 call failed (provider error, rate limit, or "
    "timeout). The verdict above is unaffected -- narration is always best-effort and "
    "never a precondition for a decision."
)
NARRATION_FAILED_MODEL = "none (narration call failed)"

# Not one of detect.ensemble's SOURCE_* constants -- the circuit breaker is
# a service-layer gate on top of the four-layer pipeline, not a fifth
# detection layer, and `detect/ensemble.py` is deliberately never touched
# for an addition like this (see the module's own docstring on why the
# ensemble's combination rule stays narrow). `EnsembleDecision.source` and
# `EnsembleDecisionOut.source` are both plain `str` fields, so this needs
# no change to either type.
SOURCE_CIRCUIT_BREAKER = "circuit_breaker"
CIRCUIT_BREAKER_RULE_NAME = "circuit_breaker:agent_suspended"
CIRCUIT_BREAKER_NARRATIVE_TEMPLATE = (
    "This session was blocked before Layers 1-3 ran: agent {agent_id} is currently suspended by the "
    "circuit breaker after accumulating too many escalated verdicts within its rolling window. "
    "Suspension only lifts via an explicit human review action at POST "
    "/agents/{agent_id}/circuit-breaker/reset -- never automatically."
)

_DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


def _cors_origins() -> list[str]:
    """Reads allowed CORS origins from the environment, with a local-dev default.

    Returns:
        The configured origin list.
    """
    raw = os.environ.get("SENTINEL_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _rate_limit_config() -> tuple[int, float]:
    """Reads the rate limit from the environment, with `RateLimitMiddleware`'s own documented defaults.

    Same pattern as `_cors_origins` -- an operational knob a real
    deployment might reasonably want to tune, not only a way for
    `tests/conftest.py` to raise the limit so a large, ever-growing test
    suite sharing one session-scoped `TestClient` (see `tests/test_service
    .py`'s own module docstring on why it is session-scoped) does not trip
    the same rate limiter a real client would.

    Returns:
        `(max_requests, window_seconds)`.
    """
    max_requests = int(os.environ.get("SENTINEL_RATE_LIMIT_MAX_REQUESTS", DEFAULT_MAX_REQUESTS_PER_WINDOW))
    window_seconds = float(os.environ.get("SENTINEL_RATE_LIMIT_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS))
    return max_requests, window_seconds


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
_rate_limit_max_requests, _rate_limit_window_seconds = _rate_limit_config()
app.add_middleware(
    RateLimitMiddleware, max_requests=_rate_limit_max_requests, window_seconds=_rate_limit_window_seconds
)
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


def _revocation_to_out(revocation: KeyRevocation) -> KeyRevocationOut:
    """Renders a `mandate.verification.KeyRevocation` as its wire form.

    Args:
        revocation: The revocation to render.

    Returns:
        The wire-form model.
    """
    return KeyRevocationOut(
        agent_id=revocation.agent_id,
        key_id=revocation.key_id,
        reason=revocation.reason.value,
        revoked_by=revocation.revoked_by,
        revoked_at=revocation.revoked_at,
        effective_at=revocation.effective_at,
    )


@app.post("/agents/{agent_id}/keys/{key_id}/revoke", response_model=KeyRevocationOut)
def revoke_key(
    agent_id: str, key_id: str, payload: RevokeKeyRequest, state: AppState = Depends(get_state)
) -> KeyRevocationOut:
    """Revokes one of an agent's registered keys, effective immediately. Always a human action.

    Args:
        agent_id: The agent whose key is being revoked.
        key_id: The key fingerprint to revoke.
        payload: The structured reason and the revoking actor.
        state: The shared application state.

    Returns:
        The recorded revocation.

    Raises:
        HTTPException: 422, if `payload.reason` is not a recognized
            `KeyRevocationReason` value.
    """
    try:
        reason = KeyRevocationReason(payload.reason)
    except ValueError as error:
        valid = [r.value for r in KeyRevocationReason]
        detail = f"invalid reason {payload.reason!r}; must be one of {valid}"
        raise HTTPException(status_code=422, detail=detail) from error
    revocation = state.registry.revoke(
        agent_id, key_id, reason=reason, revoked_by=payload.revoked_by, at=datetime.now(UTC)
    )
    return _revocation_to_out(revocation)


@app.post("/agents/{agent_id}/keys/{old_key_id}/rotate", response_model=KeyRevocationOut)
def rotate_key(
    agent_id: str, old_key_id: str, payload: RotateKeyRequest, state: AppState = Depends(get_state)
) -> KeyRevocationOut:
    """Rotates an agent's key: registers the new one immediately, schedules the old one's revocation.

    Both the old and new key verify for any session presented before the
    overlap window ends; only the old key stops verifying once it does.

    Args:
        agent_id: The agent whose key is being rotated.
        old_key_id: The key fingerprint being rotated out.
        payload: The incoming key, the overlap window length, and the
            rotating actor.
        state: The shared application state.

    Returns:
        The old key's scheduled revocation (its `effective_at` is the end
        of the overlap window, not now).

    Raises:
        HTTPException: 400, if `payload.new_public_key_base64` is not
            valid base64 or not a valid Ed25519 public key.
    """
    try:
        raw = base64.b64decode(payload.new_public_key_base64, validate=True)
        new_public_key = Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, InvalidKey) as error:
        raise HTTPException(status_code=400, detail=f"invalid Ed25519 public key: {error}") from error

    now = datetime.now(UTC)
    overlap_until = now + timedelta(hours=payload.overlap_hours)
    revocation = state.registry.rotate(
        agent_id,
        old_key_id,
        payload.new_key_id,
        new_public_key,
        overlap_until=overlap_until,
        rotated_by=payload.rotated_by,
        at=now,
    )
    return _revocation_to_out(revocation)


@app.get("/agents/{agent_id}/keys/{key_id}/revocation", response_model=KeyRevocationOut | None)
def get_key_revocation(agent_id: str, key_id: str, state: AppState = Depends(get_state)) -> KeyRevocationOut | None:
    """Looks up a key's revocation record, if any. Read-only.

    Args:
        agent_id: The agent identity to look up.
        key_id: The key ID to look up.
        state: The shared application state.

    Returns:
        The revocation, regardless of whether its `effective_at` has
        passed yet (a scheduled-but-not-yet-effective rotation still shows
        here), or None if this key was never revoked.
    """
    revocation = state.registry.revocation_for(agent_id, key_id)
    return _revocation_to_out(revocation) if revocation is not None else None


def _deterministic_to_schema(cf: DeterministicCounterfactual) -> Counterfactual:
    """Converts a `counterfactual.deterministic.Counterfactual` to its audit/wire form.

    Args:
        cf: The counterfactual to convert.

    Returns:
        The equivalent `reasoning.schema.Counterfactual`, dropping only
        `solver_verified` -- an internal correctness detail of how `cf` was
        computed, not part of what a caller or the audit trail needs.
    """
    return Counterfactual(
        layer=cf.layer,
        feasible=cf.feasible,
        edits=tuple(CounterfactualEdit(e.field, e.real_value, e.suggested_value) for e in cf.edits),
        explanation=cf.explanation,
    )


def _circuit_breaker_response(trace: SessionTrace, state: AppState) -> SessionDecisionResponse:
    """Builds the short-circuited response for a session from a suspended agent.

    Layers 1-3 never run at all -- a suspended agent is categorically not
    authorized to transact, so evaluating whether this particular session
    would otherwise have been fine is moot. Still produces a full audit
    record, same as every other decision this service makes; append-only
    means no decision, including this one, skips the trail.

    Args:
        trace: The session under evaluation.
        state: The shared application state.

    Returns:
        The response, with `ensemble.source == SOURCE_CIRCUIT_BREAKER`.
    """
    baseline = BaselineDecision(session_id=trace.session_id, blocked=True, verification_reasons=(), scope_reasons=())
    ensemble = EnsembleDecision(
        session_id=trace.session_id,
        blocked=True,
        source=SOURCE_CIRCUIT_BREAKER,
        behavioral_score=None,
        rules_fired=(CIRCUIT_BREAKER_RULE_NAME,),
    )
    narrative_text = CIRCUIT_BREAKER_NARRATIVE_TEMPLATE.format(agent_id=trace.agent_id)
    state.audit_log.append(
        AuditRecord(
            record_id=uuid4(),
            session_id=trace.session_id,
            mandate_id=trace.mandate_id,
            blocked=True,
            source=ensemble.source,
            rules_fired=ensemble.rules_fired,
            behavioral_score=None,
            top_features=(),
            counterfactual=None,
            narrative=narrative_text,
            narrated_by_model="none (circuit breaker short-circuit, narration not consulted)",
            created_at=datetime.now(UTC),
        )
    )
    return SessionDecisionResponse(
        session_id=trace.session_id,
        baseline=baseline_to_out(baseline),
        ensemble=ensemble_to_out(ensemble),
        attribution=None,
        narrative=None,
        counterfactual=None,
    )


@app.post("/sessions/decide", response_model=SessionDecisionResponse)
def decide(payload: DecideRequest, state: AppState = Depends(get_state)) -> SessionDecisionResponse:
    """Runs one session through all four layers and returns the full decision.

    Args:
        payload: The session and the mandate presented alongside it.
        state: The shared application state.

    Returns:
        The full decision record: Layer 1/2 verdict, the combined
        ensemble verdict, per-feature attribution (if Layer 3 was
        consulted), a Layer 4 narrative (if a narration client is
        configured for this service instance), and, for a blocked session,
        a minimal-edit counterfactual explanation (see
        `counterfactual.deterministic` and `counterfactual.behavioral`).
        Short-circuited entirely -- Layers 1-3 never run -- if the session's
        agent is currently suspended by the escalation queue's circuit
        breaker (`escalation/circuit_breaker.py`).
    """
    trace = payload.trace
    signed = payload.signed_mandate
    decision_now = datetime.now(UTC)

    if state.escalation_queue.is_agent_suspended(trace.agent_id):
        return _circuit_breaker_response(trace, state)

    if signed is None:
        scope_result = enforce_scope(trace, None)
        baseline = BaselineDecision(
            session_id=trace.session_id, blocked=True, verification_reasons=(), scope_reasons=scope_result.reasons
        )
    else:
        state.mandate_store.add(signed.mandate)
        verification = verify_mandate(
            signed, state.registry, state.ledger, now=trace.started_at, revocation_checked_at=decision_now
        )
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

    if ensemble.source == SOURCE_BEHAVIORAL:
        assert ensemble.behavioral_score is not None  # SOURCE_BEHAVIORAL implies a score was computed
        state.escalation_queue.open_escalation(
            session_id=trace.session_id,
            agent_id=trace.agent_id,
            reason=f"behavioral score {ensemble.behavioral_score:.4f} >= threshold {state.threshold:.4f}",
            at=trace.started_at,
        )

    attribution_out: list[AttributionRowOut] | None = None
    attribution_result = None
    if behavioral_score is not None:
        attribution_result = compute_attribution(state.model, design_matrix)
        attribution_out = attribution_row_to_out(attribution_result, 0)

    # Layer 3's counterfactual (counterfactual.behavioral) is deliberately not
    # computed here, even though the library function exists and is tested
    # directly (tests/test_counterfactual_behavioral.py). Every response this
    # endpoint returns is HTTP-reachable, including by the same caller whose
    # session was just blocked -- attaching a real per-session "which feature
    # to change, by how much, to flip this to allowed" recipe to that
    # response would hand that caller a live evasion recipe for their own
    # next attempt, not just an explanation. The deterministic counterfactual
    # below carries no equivalent risk: it restates what the mandate already
    # says, nothing about the caller could not already read off Layer 2's
    # own comparison. See docs/adr/0008's disclosure note.
    counterfactual: Counterfactual | None = None
    if ensemble.blocked and ensemble.source == SOURCE_RULES:
        det_cf = None
        if signed is not None:
            det_cf = verification_counterfactual(
                signed, state.registry, state.ledger, now=trace.started_at, revocation_checked_at=decision_now
            )
        if det_cf is None:
            det_cf = scope_counterfactual(trace, signed)
        if det_cf is not None:
            counterfactual = _deterministic_to_schema(det_cf)

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
        try:
            narration = narrate(narration_input, state.narration_client, model=state.narration_model)
        except Exception:
            logger.warning("session %s: Layer 4 narration call failed, falling back", trace.session_id, exc_info=True)
            narrative_text = NARRATION_FAILED_TEXT
            narrated_by = NARRATION_FAILED_MODEL
        else:
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
            counterfactual=counterfactual,
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
        counterfactual=counterfactual_to_out(counterfactual) if counterfactual is not None else None,
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
    counterfactual: CounterfactualOut | None
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
            counterfactual=counterfactual_to_out(r.counterfactual) if r.counterfactual is not None else None,
            narrative=r.narrative,
            narrated_by_model=r.narrated_by_model,
            created_at=r.created_at,
        )
        for r in records
    ]


@app.get("/escalations", response_model=list[EscalationOut])
def list_escalations(
    status: str | None = None, agent_id: str | None = None, state: AppState = Depends(get_state)
) -> list[EscalationOut]:
    """Lists escalations, optionally filtered. Read-only.

    Args:
        status: If given, one of `"open"`, `"reviewed"`, `"resolved"`.
        agent_id: If given, only escalations for this agent.
        state: The shared application state.

    Returns:
        Matching escalations.

    Raises:
        HTTPException: 400, if `status` is not a recognized value.
    """
    parsed_status: EscalationStatus | None = None
    if status is not None:
        try:
            parsed_status = EscalationStatus(status)
        except ValueError as error:
            valid = [s.value for s in EscalationStatus]
            raise HTTPException(status_code=400, detail=f"invalid status {status!r}; must be one of {valid}") from error
    escalations = state.escalation_queue.list_all(status=parsed_status, agent_id=agent_id)
    return [escalation_to_out(e) for e in escalations]


@app.get("/escalations/{escalation_id}", response_model=EscalationOut)
def get_escalation(escalation_id: UUID, state: AppState = Depends(get_state)) -> EscalationOut:
    """Looks up one escalation. Read-only.

    Args:
        escalation_id: The escalation to look up.
        state: The shared application state.

    Returns:
        The escalation.

    Raises:
        HTTPException: 404, if no such escalation exists.
    """
    escalation = state.escalation_queue.get(escalation_id)
    if escalation is None:
        raise HTTPException(status_code=404, detail=f"no escalation {escalation_id}")
    return escalation_to_out(escalation)


@app.post("/escalations/{escalation_id}/review", response_model=EscalationOut)
def review_escalation(
    escalation_id: UUID, payload: ReviewEscalationRequest, state: AppState = Depends(get_state)
) -> EscalationOut:
    """Marks an open escalation reviewed. Mutates escalation state only -- never a mandate or a payment.

    Args:
        escalation_id: The escalation to review.
        payload: The reviewing actor and their notes.
        state: The shared application state.

    Returns:
        The updated escalation.

    Raises:
        HTTPException: 404 if no such escalation exists, 409 if it is not
            currently open, 422 if `payload.actor` is the system actor.
    """
    try:
        escalation = state.escalation_queue.review(
            escalation_id, actor=payload.actor, note=payload.note, at=datetime.now(UTC)
        )
    except EscalationNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except InvalidTransitionError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except HumanActionRequiredError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return escalation_to_out(escalation)


@app.post("/escalations/{escalation_id}/resolve", response_model=EscalationOut)
def resolve_escalation(
    escalation_id: UUID, payload: ResolveEscalationRequest, state: AppState = Depends(get_state)
) -> EscalationOut:
    """Resolves a reviewed escalation. Mutates escalation state only -- never a mandate or a payment.

    Args:
        escalation_id: The escalation to resolve.
        payload: The resolving actor, their notes, and the decision.
        state: The shared application state.

    Returns:
        The updated escalation.

    Raises:
        HTTPException: 404 if no such escalation exists, 409 if it has not
            been reviewed yet, 422 if `payload.actor` is the system actor
            or `payload.decision` is not a recognized value.
    """
    try:
        decision = ResolutionDecision(payload.decision)
    except ValueError as error:
        valid = [d.value for d in ResolutionDecision]
        detail = f"invalid decision {payload.decision!r}; must be one of {valid}"
        raise HTTPException(status_code=422, detail=detail) from error
    try:
        escalation = state.escalation_queue.resolve(
            escalation_id, actor=payload.actor, note=payload.note, decision=decision, at=datetime.now(UTC)
        )
    except EscalationNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except InvalidTransitionError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except HumanActionRequiredError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return escalation_to_out(escalation)


@app.get("/agents/{agent_id}/circuit-breaker", response_model=CircuitBreakerStatusOut)
def get_circuit_breaker_status(agent_id: str, state: AppState = Depends(get_state)) -> CircuitBreakerStatusOut:
    """Reports whether an agent is currently suspended. Read-only.

    Args:
        agent_id: The agent to check.
        state: The shared application state.

    Returns:
        The agent's current suspension status.
    """
    return CircuitBreakerStatusOut(agent_id=agent_id, suspended=state.escalation_queue.is_agent_suspended(agent_id))


@app.post("/agents/{agent_id}/circuit-breaker/reset", response_model=CircuitBreakerStatusOut)
def reset_circuit_breaker(
    agent_id: str, payload: CircuitBreakerResetRequest, state: AppState = Depends(get_state)
) -> CircuitBreakerStatusOut:
    """Lifts an agent's suspension -- the only way one is ever lifted.

    Never touches a mandate, a session, or a payment: this endpoint's only
    effect is on the circuit breaker's own suspension state for one agent.

    Args:
        agent_id: The agent to reset.
        payload: The resetting actor and their notes.
        state: The shared application state.

    Returns:
        The agent's suspension status after the reset (always `False`).

    Raises:
        HTTPException: 409 if the agent is not currently suspended, 422 if
            `payload.actor` is the system actor.
    """
    try:
        state.escalation_queue.reset_circuit_breaker(
            agent_id, actor=payload.actor, note=payload.note, at=datetime.now(UTC)
        )
    except InvalidTransitionError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except HumanActionRequiredError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return CircuitBreakerStatusOut(agent_id=agent_id, suspended=False)


@app.get("/mandates/{mandate_id}/chain", response_model=DelegationChainOut)
def get_mandate_chain(mandate_id: UUID, state: AppState = Depends(get_state)) -> DelegationChainOut:
    """Returns a mandate's full delegation chain, each node's containment verdict included. Read-only.

    Args:
        mandate_id: The mandate to build the chain for.
        state: The shared application state.

    Returns:
        The chain -- see `service.delegation_chain.build_delegation_chain`.

    Raises:
        HTTPException: 404, if no such mandate has been presented to this
            service instance yet.
    """
    mandate = state.mandate_store.get(mandate_id)
    if mandate is None:
        raise HTTPException(status_code=404, detail=f"no mandate {mandate_id} known to this service instance")
    return build_delegation_chain(mandate, state.mandate_store)
