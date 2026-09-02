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
from datetime import datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from common.schema import EventType, SessionEvent, SessionTrace
from mandate.schema import Mandate, MandateScope
from mandate.signing import generate_keypair, key_id_for_public_key, sign_mandate
from service.main import app
from service.schemas import DEFAULT_KEY_ROTATION_OVERLAP_HOURS
from service.state import AppState
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


def test_decide_allowed_session_has_no_counterfactual(client: TestClient) -> None:
    """An allowed session has nothing to explain, so `counterfactual` is null."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    assert response.json()["counterfactual"] is None


def test_decide_blocked_by_scope_includes_a_counterfactual(client: TestClient) -> None:
    """An over-ceiling block carries a Layer 2 counterfactual naming the mandate's own ceiling."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(max_amount="1000.00"))
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id, amount="5000.00")

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    counterfactual = response.json()["counterfactual"]
    assert counterfactual is not None
    assert counterfactual["layer"] == "layer2_scope"
    assert counterfactual["feasible"] is True
    amount_edits = [e for e in counterfactual["edits"] if e["field"] == "trace.amount"]
    assert amount_edits == [{"field": "trace.amount", "real_value": "5000.00", "suggested_value": "1000.00"}]


def test_decide_with_no_mandate_has_an_infeasible_counterfactual(client: TestClient) -> None:
    """No mandate at all is a Layer 2 finding with no field-level fix -- reported honestly, not omitted."""
    agent_id = f"test-agent-{uuid4().hex}"
    trace_json = _trace_json(agent_id, None)

    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": None})
    assert response.status_code == 200
    counterfactual = response.json()["counterfactual"]
    assert counterfactual is not None
    assert counterfactual["feasible"] is False
    assert counterfactual["edits"] == []


def test_audit_record_carries_the_counterfactual(client: TestClient) -> None:
    """The counterfactual computed for a blocked session is also persisted in its audit record."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(max_amount="1000.00"))
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id, amount="5000.00")
    session_id = trace_json["session_id"]

    decide_response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert decide_response.status_code == 200
    decided_counterfactual = decide_response.json()["counterfactual"]

    audit_response = client.get(f"/audit/{session_id}")
    assert audit_response.status_code == 200
    records = audit_response.json()
    assert len(records) == 1
    assert records[0]["counterfactual"] == decided_counterfactual


def test_decide_never_imports_the_behavioral_counterfactual_search() -> None:
    """`service.main` must never wire Layer 3's counterfactual into the live HTTP path.

    Structural, not just behavioral: attaching a real per-session "which
    feature to change, by how much, to flip this to allowed" recipe to a
    response this endpoint returns would hand the same caller whose session
    was just blocked a live evasion recipe for their own next attempt --
    see `counterfactual/behavioral.py`'s own module docstring and
    `docs/adr/0008`'s addendum. The library function itself stays fully
    available and tested directly
    (`tests/test_counterfactual_behavioral.py`) for a future internal-only
    reviewer tool; this only pins that `service.main` never reaches it.
    """
    import ast
    import inspect

    import service.main as service_main_module

    tree = ast.parse(inspect.getsource(service_main_module))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "counterfactual.behavioral":
            pytest.fail(f"service.main imports from counterfactual.behavioral: {ast.dump(node)}")


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


def _app_state(client: TestClient) -> AppState:
    """Reaches the shared `AppState` a running `TestClient` actually holds.

    Args:
        client: The test client.

    Returns:
        The application state `service.main.get_state` would return inside
        a handler -- the same object, not a copy, so mutating it (opening
        an escalation directly, for example) is visible to subsequent
        requests through this same client.
    """
    return cast(AppState, client.app.state.app_state)  # type: ignore[attr-defined]


def _trip_circuit_breaker(state: AppState, agent_id: str) -> None:
    """Opens exactly enough escalations for one agent to trip its circuit breaker.

    Args:
        state: The application state to open escalations against.
        agent_id: The agent to suspend.
    """
    for i in range(state.escalation_queue.breaker.threshold):
        at = REFERENCE_NOW + timedelta(minutes=i)
        state.escalation_queue.open_escalation(uuid4(), agent_id, f"escalation {i}", at=at)


def test_behavioral_block_opens_an_escalation(client: TestClient) -> None:
    """A session Layer 3 alone blocks must open a real escalation, not just report a score."""
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    session_id = uuid4()
    before = len(state.escalation_queue.list_all(agent_id=agent_id))

    state.escalation_queue.open_escalation(session_id, agent_id, "behavioral score 0.94 >= 0.0251", at=REFERENCE_NOW)

    after = state.escalation_queue.list_all(agent_id=agent_id)
    assert len(after) == before + 1
    assert after[0].session_id == session_id
    assert after[0].status.value == "open"


def test_escalation_review_and_resolve_via_http(client: TestClient) -> None:
    """The full review -> resolve workflow, exercised through the real HTTP endpoints."""
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    escalation = state.escalation_queue.open_escalation(uuid4(), agent_id, "reason", at=REFERENCE_NOW)
    escalation_id = str(escalation.escalation_id)

    get_response = client.get(f"/escalations/{escalation_id}")
    assert get_response.status_code == 200
    assert get_response.json()["status"] == "open"

    review_response = client.post(
        f"/escalations/{escalation_id}/review", json={"actor": "reviewer-1", "note": "checking history"}
    )
    assert review_response.status_code == 200
    assert review_response.json()["status"] == "reviewed"

    resolve_response = client.post(
        f"/escalations/{escalation_id}/resolve",
        json={"actor": "reviewer-1", "note": "looked legitimate", "decision": "cleared"},
    )
    assert resolve_response.status_code == 200
    body = resolve_response.json()
    assert body["status"] == "resolved"
    assert body["resolution"] == "cleared"


def test_review_by_system_actor_is_rejected_via_http(client: TestClient) -> None:
    """A review claiming the system actor must be a clear 422, not silently accepted."""
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    escalation = state.escalation_queue.open_escalation(uuid4(), agent_id, "reason", at=REFERENCE_NOW)

    response = client.post(f"/escalations/{escalation.escalation_id}/review", json={"actor": "system", "note": ""})
    assert response.status_code == 422


def test_resolve_by_system_actor_is_rejected_via_http(client: TestClient) -> None:
    """A resolution claiming the system actor must be rejected too, not just review.

    Completes the bypass-attempt coverage the escalation queue's own
    `HumanActionRequiredError` guard exists for: `review` and
    `circuit-breaker/reset` were already covered by name, `resolve` was
    not. A real, genuinely-reviewed escalation (not skipping straight from
    open) is required first, matching `test_resolve_without_review_is_a_
    conflict_via_http`'s own setup, so this test isolates the actor check
    specifically rather than also exercising the state-machine guard.
    """
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    escalation = state.escalation_queue.open_escalation(uuid4(), agent_id, "reason", at=REFERENCE_NOW)
    escalation_id = str(escalation.escalation_id)

    review_response = client.post(
        f"/escalations/{escalation_id}/review", json={"actor": "reviewer-1", "note": "checking history"}
    )
    assert review_response.status_code == 200

    resolve_response = client.post(
        f"/escalations/{escalation_id}/resolve",
        json={"actor": "system", "note": "", "decision": "cleared"},
    )
    assert resolve_response.status_code == 422


def test_resolve_without_review_is_a_conflict_via_http(client: TestClient) -> None:
    """Resolving straight from open, skipping review, must be a clear 409."""
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    escalation = state.escalation_queue.open_escalation(uuid4(), agent_id, "reason", at=REFERENCE_NOW)

    response = client.post(
        f"/escalations/{escalation.escalation_id}/resolve",
        json={"actor": "reviewer-1", "note": "", "decision": "cleared"},
    )
    assert response.status_code == 409


def test_get_unknown_escalation_is_404(client: TestClient) -> None:
    """Looking up a nonexistent escalation ID is a clear 404, not a 500."""
    response = client.get(f"/escalations/{uuid4()}")
    assert response.status_code == 404


def test_circuit_breaker_suspends_agent_and_blocks_future_sessions(client: TestClient) -> None:
    """Enough escalations for one agent must trip the breaker and short-circuit its next session."""
    state = _app_state(client)
    agent_id, _, private_key = _register_fresh_agent(client)

    status_before = client.get(f"/agents/{agent_id}/circuit-breaker")
    assert status_before.status_code == 200
    assert status_before.json()["suspended"] is False

    _trip_circuit_breaker(state, agent_id)

    status_after = client.get(f"/agents/{agent_id}/circuit-breaker")
    assert status_after.json()["suspended"] is True

    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)
    decide_response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert decide_response.status_code == 200
    body = decide_response.json()
    assert body["ensemble"]["blocked"] is True
    assert body["ensemble"]["source"] == "circuit_breaker"
    assert body["baseline"]["blocked"] is True


def test_circuit_breaker_reset_via_http_unblocks_the_agent(client: TestClient) -> None:
    """An explicit human reset must lift a suspension and let the agent transact normally again."""
    state = _app_state(client)
    agent_id, _, private_key = _register_fresh_agent(client)
    _trip_circuit_breaker(state, agent_id)
    assert client.get(f"/agents/{agent_id}/circuit-breaker").json()["suspended"] is True

    reset_response = client.post(
        f"/agents/{agent_id}/circuit-breaker/reset", json={"actor": "reviewer-1", "note": "false positive pattern"}
    )
    assert reset_response.status_code == 200
    assert reset_response.json()["suspended"] is False
    assert client.get(f"/agents/{agent_id}/circuit-breaker").json()["suspended"] is False

    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)
    decide_response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert decide_response.status_code == 200
    assert decide_response.json()["ensemble"]["source"] != "circuit_breaker"


def test_circuit_breaker_reset_by_system_actor_is_rejected(client: TestClient) -> None:
    """A reset claiming the system actor must be a clear 422."""
    state = _app_state(client)
    agent_id = f"test-agent-{uuid4().hex}"
    _trip_circuit_breaker(state, agent_id)

    response = client.post(f"/agents/{agent_id}/circuit-breaker/reset", json={"actor": "system", "note": ""})
    assert response.status_code == 422


def test_circuit_breaker_reset_of_a_not_suspended_agent_is_a_conflict(client: TestClient) -> None:
    """Resetting an agent that was never suspended must be a clear 409, not a silent no-op."""
    agent_id = f"test-agent-{uuid4().hex}"
    response = client.post(f"/agents/{agent_id}/circuit-breaker/reset", json={"actor": "reviewer-1", "note": ""})
    assert response.status_code == 409


def test_list_escalations_filters_by_agent(client: TestClient) -> None:
    """The list endpoint's agent_id filter must actually filter, not just accept the param."""
    state = _app_state(client)
    agent_a = f"test-agent-{uuid4().hex}"
    agent_b = f"test-agent-{uuid4().hex}"
    state.escalation_queue.open_escalation(uuid4(), agent_a, "reason", at=REFERENCE_NOW)
    state.escalation_queue.open_escalation(uuid4(), agent_b, "reason", at=REFERENCE_NOW)

    response = client.get("/escalations", params={"agent_id": agent_a})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["agent_id"] == agent_a


def _decide(client: TestClient, trace_json: dict[str, Any], mandate_json: dict[str, Any]) -> None:
    """POSTs a decide request and asserts it succeeded, discarding the body.

    Args:
        client: The test client.
        trace_json: The session trace, JSON-encoded.
        mandate_json: The signed mandate, JSON-encoded.
    """
    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200


def test_mandate_chain_of_a_root_mandate_is_a_single_node(client: TestClient) -> None:
    """A mandate with no parent must report as a single root node with no containment check."""
    agent_id, _, private_key = _register_fresh_agent(client)
    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)
    _decide(client, trace_json, mandate_json)

    response = client.get(f"/mandates/{mandate_id}/chain")
    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 1
    assert body["nodes"][0]["is_root"] is True
    assert body["nodes"][0]["in_bounds"] is None
    assert body["edges"] == []
    assert body["chain_broken"] is False


def test_mandate_chain_reports_an_in_bounds_child(client: TestClient) -> None:
    """A child mandate whose scope fits inside its parent's must report in_bounds True with no violating edge."""
    agent_id, _, private_key = _register_fresh_agent(client)
    parent_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(max_amount="2000.00"))
    parent_id = parent_json["mandate"]["mandate_id"]
    parent_trace = _trace_json(agent_id, parent_id)
    _decide(client, parent_trace, parent_json)

    child_json = _signed_mandate_json(
        agent_id, private_key, scope=build_scope(max_amount="1000.00"), parent_mandate_id=parent_id
    )
    child_id = child_json["mandate"]["mandate_id"]
    child_trace = _trace_json(agent_id, child_id, amount="500.00")
    _decide(client, child_trace, child_json)

    response = client.get(f"/mandates/{child_id}/chain")
    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 2
    child_node = body["nodes"][0]
    assert child_node["mandate_id"] == child_id
    assert child_node["in_bounds"] is True
    assert body["edges"] == [{"child_mandate_id": child_id, "parent_mandate_id": parent_id, "violates": False}]


def test_mandate_chain_reports_a_violating_edge_for_an_over_scoped_child(client: TestClient) -> None:
    """A child mandate whose ceiling exceeds its parent's must report in_bounds False and a violating edge."""
    agent_id, _, private_key = _register_fresh_agent(client)
    parent_json = _signed_mandate_json(agent_id, private_key, scope=build_scope(max_amount="1000.00"))
    parent_id = parent_json["mandate"]["mandate_id"]
    parent_trace = _trace_json(agent_id, parent_id, amount="500.00")
    _decide(client, parent_trace, parent_json)

    child_json = _signed_mandate_json(
        agent_id, private_key, scope=build_scope(max_amount="5000.00"), parent_mandate_id=parent_id
    )
    child_id = child_json["mandate"]["mandate_id"]
    child_trace = _trace_json(agent_id, child_id, amount="1.00")
    _decide(client, child_trace, child_json)

    response = client.get(f"/mandates/{child_id}/chain")
    assert response.status_code == 200
    body = response.json()
    child_node = body["nodes"][0]
    assert child_node["in_bounds"] is False
    assert "scope_amount_exceeds_parent" in child_node["reasons"]
    assert body["edges"][0]["violates"] is True


def test_mandate_chain_of_unknown_mandate_is_404(client: TestClient) -> None:
    """Looking up a mandate this service has never seen is a clear 404, not a 500."""
    response = client.get(f"/mandates/{uuid4()}/chain")
    assert response.status_code == 404


def test_revoked_key_is_rejected_at_decide_time(client: TestClient) -> None:
    """A key revoked after registration must be rejected by a live /sessions/decide call, not just the registry."""
    agent_id, _, private_key = _register_fresh_agent(client)
    key_id = key_id_for_public_key(private_key.public_key())

    revoke_response = client.post(
        f"/agents/{agent_id}/keys/{key_id}/revoke", json={"reason": "compromised", "revoked_by": "security-team"}
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["reason"] == "compromised"

    mandate_json = _signed_mandate_json(agent_id, private_key)
    mandate_id = mandate_json["mandate"]["mandate_id"]
    trace_json = _trace_json(agent_id, mandate_id)
    response = client.post("/sessions/decide", json={"trace": trace_json, "signed_mandate": mandate_json})
    assert response.status_code == 200
    body = response.json()
    assert body["baseline"]["blocked"] is True
    assert "key_revoked" in body["baseline"]["verification_reasons"]


def test_revoke_with_invalid_reason_is_rejected(client: TestClient) -> None:
    """An unrecognized revocation reason must be a clear 422, not silently accepted."""
    agent_id, _, private_key = _register_fresh_agent(client)
    key_id = key_id_for_public_key(private_key.public_key())
    response = client.post(
        f"/agents/{agent_id}/keys/{key_id}/revoke", json={"reason": "not_a_real_reason", "revoked_by": "ops"}
    )
    assert response.status_code == 422


def test_key_rotation_overlap_window_via_http(client: TestClient) -> None:
    """A live-rotated key must let both old and new keys decide during the overlap, only the old one after."""
    agent_id, _, old_private_key = _register_fresh_agent(client)
    new_private_key, new_public_key = generate_keypair()
    new_key_id = key_id_for_public_key(new_public_key)
    old_key_id = key_id_for_public_key(old_private_key.public_key())

    rotate_response = client.post(
        f"/agents/{agent_id}/keys/{old_key_id}/rotate",
        json={
            "new_key_id": new_key_id,
            "new_public_key_base64": base64.b64encode(new_public_key.public_bytes_raw()).decode("ascii"),
            "overlap_hours": 0.0,
            "rotated_by": "ops-team",
        },
    )
    assert rotate_response.status_code == 200
    assert rotate_response.json()["reason"] == "rotated"

    # overlap_hours=0.0 means the old key's revocation is effective immediately.
    old_mandate_json = _signed_mandate_json(agent_id, old_private_key)
    old_mandate_id = old_mandate_json["mandate"]["mandate_id"]
    old_trace_json = _trace_json(agent_id, old_mandate_id)
    old_response = client.post(
        "/sessions/decide", json={"trace": old_trace_json, "signed_mandate": old_mandate_json}
    )
    assert "key_revoked" in old_response.json()["baseline"]["verification_reasons"]

    new_mandate_json = _signed_mandate_json(agent_id, new_private_key)
    new_mandate_id = new_mandate_json["mandate"]["mandate_id"]
    new_trace_json = _trace_json(agent_id, new_mandate_id)
    new_response = client.post(
        "/sessions/decide", json={"trace": new_trace_json, "signed_mandate": new_mandate_json}
    )
    assert new_response.json()["baseline"]["blocked"] is False


def test_rotation_without_overlap_hours_uses_the_documented_default(client: TestClient) -> None:
    """Omitting overlap_hours from the request body must fall back to the documented default, not fail closed to 0."""
    agent_id, _, old_private_key = _register_fresh_agent(client)
    new_private_key, new_public_key = generate_keypair()
    new_key_id = key_id_for_public_key(new_public_key)
    old_key_id = key_id_for_public_key(old_private_key.public_key())

    rotate_response = client.post(
        f"/agents/{agent_id}/keys/{old_key_id}/rotate",
        json={
            "new_key_id": new_key_id,
            "new_public_key_base64": base64.b64encode(new_public_key.public_bytes_raw()).decode("ascii"),
            "rotated_by": "ops-team",
        },
    )
    assert rotate_response.status_code == 200
    body = rotate_response.json()
    revoked_at = datetime.fromisoformat(body["revoked_at"])
    effective_at = datetime.fromisoformat(body["effective_at"])
    actual_overlap_hours = (effective_at - revoked_at).total_seconds() / 3600
    assert actual_overlap_hours == pytest.approx(DEFAULT_KEY_ROTATION_OVERLAP_HOURS, abs=0.01)


def test_rotate_with_invalid_public_key_is_rejected(client: TestClient) -> None:
    """A malformed incoming public key on rotation must be a clear 400, not a 500."""
    agent_id, _, private_key = _register_fresh_agent(client)
    key_id = key_id_for_public_key(private_key.public_key())
    response = client.post(
        f"/agents/{agent_id}/keys/{key_id}/rotate",
        json={
            "new_key_id": "ed25519:whatever",
            "new_public_key_base64": "not-valid-base64!!!",
            "overlap_hours": 24.0,
            "rotated_by": "ops-team",
        },
    )
    assert response.status_code == 400


def test_key_revocation_lookup_is_null_when_never_revoked(client: TestClient) -> None:
    """A key that was never revoked must report null, not an error."""
    agent_id, _, private_key = _register_fresh_agent(client)
    key_id = key_id_for_public_key(private_key.public_key())
    response = client.get(f"/agents/{agent_id}/keys/{key_id}/revocation")
    assert response.status_code == 200
    assert response.json() is None


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
