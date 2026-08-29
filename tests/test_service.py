"""Tests for `service.main`: the API service wrapping the full pipeline.

Every `decide`-path test generates its own fresh Ed25519 keypair and
registers a never-before-used agent ID, rather than reusing one of the
service's own seeded demo agents. `service.state.AppState`'s feature
extractor and mandate ledger are real shared, accumulating state across the
whole test session (matching what a live service actually does); a fresh
agent per test means each session's `agent_prior_session_count` and
similar causal features start at zero deterministically, so no test's
assertions depend on what order tests happen to run in.

The client fixture is session-scoped because building it fits the real
Layer 3 model once (the same cost `run_full_eval.py` pays) -- fine to do
once for the whole test session, wasteful to repeat per test.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from common.schema import EventType, SessionEvent, SessionTrace
from mandate.schema import Mandate, MandateScope
from mandate.signing import generate_keypair, key_id_for_public_key, sign_mandate
from service.main import app
from tests.factories import REFERENCE_NOW, build_scope


@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    """A `TestClient` whose lifespan runs the real pipeline fit once."""
    with TestClient(app) as c:
        yield c


def _register_fresh_agent(client: TestClient) -> tuple[str, str, Ed25519PrivateKey]:
    """Generates a keypair and registers it as a brand-new agent.

    Args:
        client: The test client.

    Returns:
        (agent_id, key_id, private_key) for the newly registered agent.
    """
    private_key, public_key = generate_keypair()
    agent_id = f"test-agent-{uuid4().hex}"
    key_id = key_id_for_public_key(public_key)
    response = client.post(
        "/agents/register",
        json={
            "agent_id": agent_id,
            "key_id": key_id,
            "public_key_base64": base64.b64encode(public_key.public_bytes_raw()).decode("ascii"),
        },
    )
    assert response.status_code == 200
    return agent_id, key_id, private_key


def _signed_mandate_json(
    agent_id: str, private_key: Ed25519PrivateKey, *, scope: MandateScope | None = None, **mandate_overrides: object
) -> dict[str, Any]:
    """Builds and signs a mandate for a freshly registered agent, as JSON.

    Args:
        agent_id: The agent the mandate authorizes.
        private_key: That agent's registered private key.
        scope: The scope to attach. Defaults to `build_scope()`.
        **mandate_overrides: Field overrides for the mandate itself.

    Returns:
        The signed mandate, JSON-encoded the same way a real client would.
    """
    key_id = key_id_for_public_key(private_key.public_key())
    defaults: dict[str, object] = {
        "mandate_id": uuid4(),
        "agent_id": agent_id,
        "user_id": "user-0001",
        "parent_mandate_id": None,
        "issued_at": REFERENCE_NOW - timedelta(days=1),
        "expires_at": REFERENCE_NOW + timedelta(days=7),
        "nonce": uuid4().hex,
        "scope": scope if scope is not None else build_scope(),
        "signer_key_id": key_id,
    }
    defaults.update(mandate_overrides)
    mandate = Mandate(**defaults)  # type: ignore[arg-type]
    signed = sign_mandate(mandate, private_key)
    return signed.model_dump(mode="json")


def _trace_json(agent_id: str, mandate_id: object, **overrides: object) -> dict[str, Any]:
    """Builds a session trace for the given agent/mandate, as JSON.

    Args:
        agent_id: The agent presenting the session.
        mandate_id: The mandate presented, or None.
        **overrides: Field overrides.

    Returns:
        The trace, JSON-encoded the same way a real client would.
    """
    default_event = SessionEvent(event_type=EventType.PAYMENT_RESULT, timestamp=REFERENCE_NOW)
    defaults: dict[str, object] = {
        "session_id": uuid4(),
        "agent_id": agent_id,
        "user_id": "user-0001",
        "mandate_id": mandate_id,
        "merchant_id": "bigbasket",
        "merchant_category": "grocery",
        "item_category": "packaged_food",
        "amount": "450.00",
        "currency": "INR",
        "events": [default_event],
        "started_at": REFERENCE_NOW,
        "completed_at": REFERENCE_NOW,
    }
    defaults.update(overrides)
    trace = SessionTrace(**defaults)  # type: ignore[arg-type]
    return trace.model_dump(mode="json")


def test_health(client: TestClient) -> None:
    """The liveness endpoint reports ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_lists_seeded_demo_agents(client: TestClient) -> None:
    """The service seeds a handful of demo agents at startup."""
    response = client.get("/agents/demo")
    assert response.status_code == 200
    agents = response.json()
    assert len(agents) >= 1
    assert all({"agent_id", "key_id", "private_key_hex"} <= set(a) for a in agents)


def test_register_agent_rejects_invalid_key(client: TestClient) -> None:
    """A malformed public key is a clear 400, not a 500."""
    response = client.post(
        "/agents/register",
        json={"agent_id": "bad-agent", "key_id": "ed25519:deadbeef", "public_key_base64": "not-valid-base64!!!"},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_decide_allows_a_clean_session(client: TestClient) -> None:
    """A session fully within its mandate's scope is allowed."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    body = response.json()
    assert body["baseline"]["blocked"] is False
    assert body["ensemble"]["blocked"] is False
    assert body["attribution"] is not None  # Layer 3 was consulted


def test_decide_blocks_amount_over_ceiling(client: TestClient) -> None:
    """A transaction over the mandate's ceiling is blocked by Layer 2, not Layer 3."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(max_amount="1000.00"))
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id, amount="5000.00")

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    body = response.json()
    assert body["baseline"]["blocked"] is True
    assert "amount_over_ceiling" in body["baseline"]["scope_reasons"]
    assert body["ensemble"]["source"] == "rules"
    assert body["attribution"] is None  # Layer 3 never consulted


def test_decide_with_no_mandate_is_blocked(client: TestClient) -> None:
    """A session presenting no mandate at all is a Layer 2 finding, not a request error."""
    agent_id = f"test-agent-{uuid4().hex}"
    trace_json = _trace_json(agent_id, None)

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": None})
    assert response.status_code == 200
    body = response.json()
    assert body["baseline"]["blocked"] is True
    assert "no_mandate_presented" in body["baseline"]["scope_reasons"]


def test_decide_rejects_malformed_request_with_clear_4xx(client: TestClient) -> None:
    """A structurally invalid request body is a 422 with field detail, not a stack trace."""
    response = client.post("/sessions/decide", json={"trace": {"not": "a valid trace"}})
    assert response.status_code == 422
    assert "detail" in response.json()


def test_decide_without_narration_client_still_produces_an_audit_record(client: TestClient) -> None:
    """Narration is best-effort: no GROQ_API_KEY still leaves a real audit record behind."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)
    session_id = trace_json["session_id"]

    decide_response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert decide_response.status_code == 200

    audit_response = client.get(f"/audit/{session_id}")
    assert audit_response.status_code == 200
    records = audit_response.json()
    assert len(records) == 1
    assert records[0]["session_id"] == session_id
    assert records[0]["narrative"]  # non-empty, real or the honest placeholder either way


def test_audit_for_unknown_session_is_empty_not_an_error(client: TestClient) -> None:
    """Looking up a session that was never decided returns an empty list, not a 404 or 500."""
    response = client.get(f"/audit/{uuid4()}")
    assert response.status_code == 200
    assert response.json() == []


def test_rate_limit_middleware_returns_429_over_the_limit() -> None:
    """The rate limiter itself, tested in isolation with a low threshold.

    Exercising the real service's default 60-req/60s limit would mean
    firing 61 real requests through the fully-fitted pipeline; this checks
    the middleware's own counting logic directly instead, against a
    minimal app with a limit low enough to hit in three requests.
    """
    from fastapi import FastAPI

    from service.middleware import RateLimitMiddleware

    mini_app = FastAPI()

    @mini_app.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "ok"}

    mini_app.add_middleware(RateLimitMiddleware, max_requests=2, window_seconds=60.0)

    with TestClient(mini_app) as mini_client:
        assert mini_client.get("/ping").status_code == 200
        assert mini_client.get("/ping").status_code == 200
        third = mini_client.get("/ping")
        assert third.status_code == 429
        assert "rate limit" in third.json()["detail"].lower()


@pytest.mark.parametrize(
    "trace_overrides,scope_overrides,expected_reason",
    [
        ({"merchant_category": "electronics"}, {}, "merchant_category_not_allowed"),
        ({"item_category": "laptops"}, {}, "item_category_not_allowed"),
        ({"currency": "USD"}, {}, "currency_mismatch"),
    ],
)
def test_decide_reports_each_scope_violation_by_name(
    client: TestClient, trace_overrides: dict[str, object], scope_overrides: dict[str, object], expected_reason: str
) -> None:
    """Each scope rule is reported by its own real name, not a generic 'blocked'."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(**scope_overrides))
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id, **trace_overrides)

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    assert expected_reason in response.json()["baseline"]["scope_reasons"]
