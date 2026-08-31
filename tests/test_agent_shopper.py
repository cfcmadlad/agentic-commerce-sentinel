"""Tests for `agent.shopper`'s tool-calling loop mechanics.

Uses a small, fixed, in-file fake `ToolCallingClient` (never a real network
call) to drive the loop deterministically, matching the convention
`tests/test_narrate.py`'s own `_FakeClient` already established for
`GroqNarrationClient`. `checkout` calls within these scripted plans still
go through the real `agent.tools.checkout` -> real `service.main.decide`,
against a module-scoped, once-fitted `AppState`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest

from agent.catalog import CATALOG
from agent.llm_client import AssistantTurn, ToolCall, ToolDefinition
from agent.shopper import MAX_TOOL_ITERATIONS, run_shopper_session
from agent.tools import STANDARD_EVENT_GAPS, ShopperToolContext
from mandate.schema import Mandate, MandateScope
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate
from service.state import AppState, build_app_state

ANCHOR = datetime(2026, 5, 2, 9, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def state(tmp_path_factory: pytest.TempPathFactory) -> AppState:
    """A real, fully fitted `AppState`, built once for this module's tests."""
    tmp_dir = tmp_path_factory.mktemp("agent-shopper-state")
    return build_app_state(audit_log_path=tmp_dir / "audit.jsonl", escalation_log_path=tmp_dir / "escalations.jsonl")


@pytest.fixture
def ctx(state: AppState) -> ShopperToolContext:
    """A fresh, valid, registered mandate context for one test."""
    seed_bytes = hashlib.sha256(b"test-agent-shopper").digest()
    private_key, public_key = keypair_from_seed_bytes(seed_bytes)
    agent_id = "shopper-agent-test-shopper"
    key_id = key_id_for_public_key(public_key)
    state.registry.register(agent_id, key_id, public_key)
    mandate_id = uuid5(NAMESPACE_URL, "test-agent-shopper:mandate")
    mandate = Mandate(
        mandate_id=mandate_id,
        agent_id=agent_id,
        user_id="user-shopper-test",
        issued_at=ANCHOR - timedelta(hours=2),
        expires_at=ANCHOR + timedelta(hours=7),
        nonce=uuid5(NAMESPACE_URL, "test-agent-shopper:nonce").hex,
        scope=MandateScope(
            max_amount=Decimal("5000"),
            currency="INR",
            allowed_merchant_categories=frozenset({"electronics"}),
            allowed_item_categories=frozenset({"gadgets"}),
            valid_from=ANCHOR - timedelta(hours=2),
            valid_until=ANCHOR + timedelta(hours=6),
            max_transaction_count=10,
        ),
        signer_key_id=key_id,
    )
    signed = sign_mandate(mandate, private_key)
    catalog = tuple(item for item in CATALOG if item.item_id in {"earbuds-wireless-01", "laptop-pro-01"})
    return ShopperToolContext(
        agent_id=agent_id,
        user_id="user-shopper-test",
        signed_mandate=signed,
        app_state=state,
        session_started_at=ANCHOR,
        event_gaps=STANDARD_EVENT_GAPS,
        include_browse=True,
        catalog=catalog,
    )


class _ScriptedClient:
    """A fixed, deterministic tool-call sequence, then a final content turn."""

    def __init__(self, plan: list[tuple[str, dict[str, Any]]], final_text: str = "done") -> None:
        self._plan = list(plan)
        self._final_text = final_text
        self._counter = 0

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        if not self._plan:
            return AssistantTurn(content=self._final_text, tool_calls=())
        name, arguments = self._plan.pop(0)
        self._counter += 1
        return AssistantTurn(
            content=None, tool_calls=(ToolCall(call_id=f"call-{self._counter}", name=name, arguments=arguments),)
        )


class _AlwaysToolCallingClient:
    """Never produces a final answer -- used to exercise the iteration cap."""

    def __init__(self) -> None:
        self._counter = 0

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        self._counter += 1
        call = ToolCall(call_id=f"call-{self._counter}", name="search_catalog", arguments={"query": "earbuds"})
        return AssistantTurn(content=None, tool_calls=(call,))


def test_run_shopper_session_terminates_on_final_answer(ctx: ShopperToolContext) -> None:
    """A content-only first turn ends the loop immediately with no tool calls made."""
    client = _ScriptedClient(plan=[], final_text="Nothing to do.")
    transcript = run_shopper_session(ctx, client, "hello")
    assert transcript.final_text == "Nothing to do."
    assert transcript.invocations == []
    assert transcript.hit_iteration_cap is False


def test_run_shopper_session_dispatches_real_tools_in_order(ctx: ShopperToolContext) -> None:
    """search_catalog, propose_purchase, and checkout are dispatched to the real functions, in order."""
    plan: list[tuple[str, dict[str, Any]]] = [
        ("search_catalog", {"query": "earbuds"}),
        ("propose_purchase", {"item_id": "earbuds-wireless-01", "quantity": 1}),
        ("checkout", {"item_id": "earbuds-wireless-01", "quantity": 1}),
    ]
    client = _ScriptedClient(plan=plan, final_text="Purchased.")
    transcript = run_shopper_session(ctx, client, "buy earbuds")

    assert [inv.name for inv in transcript.invocations] == ["search_catalog", "propose_purchase", "checkout"]
    assert all(not inv.is_error for inv in transcript.invocations)
    assert len(transcript.verdicts) == 1
    assert transcript.verdicts[0].blocked is False  # real decide() verdict: in-scope purchase, allowed
    assert transcript.final_text == "Purchased."


def test_run_shopper_session_reports_unknown_tool_as_error_and_continues(ctx: ShopperToolContext) -> None:
    """A hallucinated tool name is reported as a tool error, not a crash -- the loop continues."""
    plan = [("delete_everything", {}), ("search_catalog", {"query": "earbuds"})]
    client = _ScriptedClient(plan=plan, final_text="Recovered.")
    transcript = run_shopper_session(ctx, client, "do something")

    assert transcript.invocations[0].name == "delete_everything"
    assert transcript.invocations[0].is_error is True
    assert transcript.invocations[1].name == "search_catalog"
    assert transcript.invocations[1].is_error is False
    assert transcript.final_text == "Recovered."


def test_run_shopper_session_reports_malformed_arguments_as_error(ctx: ShopperToolContext) -> None:
    """An unknown item ID from propose_purchase is reported as a tool error, never a silent pass."""
    plan = [("propose_purchase", {"item_id": "does-not-exist", "quantity": 1})]
    client = _ScriptedClient(plan=plan, final_text="Gave up.")
    transcript = run_shopper_session(ctx, client, "buy something fake")

    assert transcript.invocations[0].is_error is True
    assert "unknown catalog item" in str(transcript.invocations[0].result)
    assert transcript.verdicts == []  # checkout was never reached


def test_run_shopper_session_hits_iteration_cap(ctx: ShopperToolContext) -> None:
    """A client that never produces a final answer stops at MAX_TOOL_ITERATIONS, not indefinitely."""
    client = _AlwaysToolCallingClient()
    transcript = run_shopper_session(ctx, client, "loop forever")
    assert transcript.hit_iteration_cap is True
    assert transcript.final_text is None
    assert len(transcript.invocations) == MAX_TOOL_ITERATIONS
