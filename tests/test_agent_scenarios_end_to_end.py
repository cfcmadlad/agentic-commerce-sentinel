"""End-to-end tests: all four required demo outcomes (project brief Section 4.4), against the real pipeline.

Every scenario here runs through `agent.shopper.run_shopper_session` with a
small, fixed, scripted tool-call client (never a real network call, for
CI determinism -- see the project brief's own Section 4.5 requirement) but
every `checkout` call still reaches the real `service.main.decide` and the
real Layer 2.5 containment check. Nothing about the resulting verdicts is
mocked or asserted-then-forced; these tests would fail if the real pipeline
stopped producing the outcome each scenario is built to demonstrate.

A real-Groq-gated end-to-end test (skipped unless `GROQ_API_KEY` is set)
covers the one thing the scripted client cannot: that a genuine live model
call drives the same real tools to the same real verdict.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from agent.llm_client import AssistantTurn, GroqToolCallingClient, ToolCall, ToolDefinition
from agent.scenarios import ShopperScenario, build_scenarios
from agent.shopper import ShopperTranscript, run_shopper_session
from agent.tools import SentinelVerdict
from service.state import DEFAULT_AUDIT_LOG_PATH, DEFAULT_ESCALATION_LOG_PATH, AppState, build_app_state


def _snapshot(path: Path) -> tuple[bool, int, float] | None:
    """Captures a file's existence/size/mtime, or None if it does not exist.

    Args:
        path: The path to snapshot.

    Returns:
        `(exists, size, mtime)`, or None if `path` does not exist.
    """
    if not path.exists():
        return None
    stat = path.stat()
    return True, stat.st_size, stat.st_mtime


# Captured at module import time -- before any fixture in this module runs
# a single scenario -- so the isolation regression test below can prove
# "this run did not touch the default paths" without assuming they start
# out empty or absent (a real local machine can have a legitimate,
# gitignored, pre-existing service_audit.jsonl from an earlier manual
# `uvicorn service.main:app` run).
_DEFAULT_AUDIT_LOG_SNAPSHOT_BEFORE = _snapshot(DEFAULT_AUDIT_LOG_PATH)
_DEFAULT_ESCALATION_LOG_SNAPSHOT_BEFORE = _snapshot(DEFAULT_ESCALATION_LOG_PATH)

_FAKE_PLANS: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "allowed": [
        ("search_catalog", {"query": "earbuds"}),
        ("propose_purchase", {"item_id": "earbuds-wireless-01", "quantity": 1}),
        ("checkout", {"item_id": "earbuds-wireless-01", "quantity": 1}),
    ],
    "blocked_scope_violation": [
        ("search_catalog", {"query": "laptop"}),
        ("propose_purchase", {"item_id": "laptop-pro-01", "quantity": 1}),
        ("checkout", {"item_id": "laptop-pro-01", "quantity": 1}),
    ],
    "escalated_behavioral_anomaly": [
        ("propose_purchase", {"item_id": "sneakers-running-01", "quantity": 1}),
        ("checkout", {"item_id": "sneakers-running-01", "quantity": 1}),
    ],
    "headline_budget_escalation": [
        ("search_catalog", {"query": "rice"}),
        ("propose_purchase", {"item_id": "rice-sack-5kg-01", "quantity": 1}),
        ("checkout", {"item_id": "rice-sack-5kg-01", "quantity": 1}),
    ],
}


class _ScriptedClient:
    """A fixed, deterministic tool-call sequence -- see `agent.shopper`'s test module for the same pattern."""

    def __init__(self, plan: list[tuple[str, dict[str, Any]]]) -> None:
        self._plan = list(plan)
        self._counter = 0

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        if not self._plan:
            return AssistantTurn(content="Attempt complete.", tool_calls=())
        name, arguments = self._plan.pop(0)
        self._counter += 1
        return AssistantTurn(
            content=None, tool_calls=(ToolCall(call_id=f"call-{self._counter}", name=name, arguments=arguments),)
        )


@pytest.fixture(scope="module")
def demo_state_and_paths(tmp_path_factory: pytest.TempPathFactory) -> tuple[AppState, Path, Path]:
    """The demo-run-isolated `AppState` all four scenarios share, plus its own log paths."""
    tmp_dir = tmp_path_factory.mktemp("agent-scenarios-state")
    audit_path = tmp_dir / "audit.jsonl"
    escalation_path = tmp_dir / "escalations.jsonl"
    state = build_app_state(audit_log_path=audit_path, escalation_log_path=escalation_path)
    return state, audit_path, escalation_path


@pytest.fixture(scope="module")
def scenarios(demo_state_and_paths: tuple[AppState, Path, Path]) -> tuple[ShopperScenario, ...]:
    """All four fixed scenarios, built once against the shared demo state."""
    state, _, _ = demo_state_and_paths
    return build_scenarios(state)


@pytest.fixture(scope="module")
def verdicts_by_key(scenarios: tuple[ShopperScenario, ...]) -> dict[str, SentinelVerdict]:
    """Runs every scenario's scripted plan and returns its resulting real checkout verdict."""
    results: dict[str, SentinelVerdict] = {}
    for scenario in scenarios:
        client = _ScriptedClient(_FAKE_PLANS[scenario.key])
        transcript: ShopperTranscript = run_shopper_session(
            scenario.context, client, scenario.user_prompt, system_prompt_addition=scenario.system_prompt_addition
        )
        assert len(transcript.verdicts) == 1, f"scenario {scenario.key!r}: expected exactly one checkout verdict"
        results[scenario.key] = transcript.verdicts[0]
    return results


def test_all_four_scenarios_are_present(scenarios: tuple[ShopperScenario, ...]) -> None:
    """The four required demo outcomes (project brief Section 4.4) all exist, in order."""
    assert [s.key for s in scenarios] == [
        "allowed",
        "blocked_scope_violation",
        "escalated_behavioral_anomaly",
        "headline_budget_escalation",
    ]


def test_outcome_1_allowed(verdicts_by_key: dict[str, SentinelVerdict]) -> None:
    """An in-scope purchase is really allowed."""
    verdict = verdicts_by_key["allowed"]
    assert verdict.blocked is False
    assert verdict.source == "allowed"


def test_outcome_2_blocked_deterministic(verdicts_by_key: dict[str, SentinelVerdict]) -> None:
    """An over-ceiling purchase is really blocked by the deterministic rules layer."""
    verdict = verdicts_by_key["blocked_scope_violation"]
    assert verdict.blocked is True
    assert verdict.source == "rules"


def test_outcome_3_escalated_via_real_behavioral_flag(verdicts_by_key: dict[str, SentinelVerdict]) -> None:
    """A scripted-fast pacing pattern is really flagged by Layer 3, opening a real escalation."""
    verdict = verdicts_by_key["escalated_behavioral_anomaly"]
    assert verdict.blocked is True
    assert verdict.source == "behavioral"
    assert verdict.behavioral_score is not None
    assert verdict.escalation_opened is True


def test_outcome_4_headline_containment_catch(verdicts_by_key: dict[str, SentinelVerdict]) -> None:
    """The budget-escalation delegation chain is allowed by decide() but caught by real Layer 2.5 containment.

    This is the exact disclosed gap `docs/adr/0003-held-out-class-evaluation.md`
    and `docs/adr/0004-delegation-chain-containment.md` already measured --
    demonstrated live here, not tuned or forced.
    """
    verdict = verdicts_by_key["headline_budget_escalation"]
    assert verdict.blocked is False  # Layers 1-3 allow it -- fits the child's own ceiling
    assert verdict.containment_in_bounds is False  # real Layer 2.5 catches it
    assert "scope_amount_exceeds_parent" in verdict.containment_reasons
    assert verdict.escalation_opened is True


def test_demo_run_never_touches_the_default_service_log_paths(
    demo_state_and_paths: tuple[AppState, Path, Path], verdicts_by_key: dict[str, SentinelVerdict]
) -> None:
    """Every scenario's side effects land only on this test's own isolated log paths.

    Regression guard against the exact failure mode the project has already
    hit once (see `agent/__init__.py`'s docstring and
    `run_delegation_demo_export.py`'s own module docstring): a stray run
    accumulating state in the shared default audit/escalation log files that
    a live service or another test run would also read.

    Compares the default paths' state (size/mtime) against the snapshot
    captured at module import time, rather than asserting they are empty or
    absent outright -- a real local development machine can legitimately
    already have a nonempty, gitignored `service_audit.jsonl` from an
    earlier manual `uvicorn service.main:app` run, and this test must not
    fail on that pre-existing, unrelated state. What it actually proves is
    that *this run* did not add to it.
    """
    _, audit_path, escalation_path = demo_state_and_paths
    assert audit_path.exists()  # this run's own isolated log did get written to
    assert escalation_path.exists()
    assert _snapshot(DEFAULT_AUDIT_LOG_PATH) == _DEFAULT_AUDIT_LOG_SNAPSHOT_BEFORE
    assert _snapshot(DEFAULT_ESCALATION_LOG_PATH) == _DEFAULT_ESCALATION_LOG_SNAPSHOT_BEFORE


@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="GROQ_API_KEY not set; skipping live Groq call")
def test_live_groq_shopper_session_produces_a_real_verdict() -> None:
    """End-to-end smoke test against the real Groq API and the real decision path, run only when a key is configured."""
    from groq import Groq

    tmp_dir = Path(tempfile.mkdtemp(prefix="agent-live-groq-"))
    tmp_state = build_app_state(
        audit_log_path=tmp_dir / "audit.jsonl", escalation_log_path=tmp_dir / "escalations.jsonl"
    )
    scenario_list = build_scenarios(tmp_state)
    allowed_scenario = next(s for s in scenario_list if s.key == "allowed")
    client = GroqToolCallingClient(client=Groq())
    transcript = run_shopper_session(
        allowed_scenario.context,
        client,
        allowed_scenario.user_prompt,
        system_prompt_addition=allowed_scenario.system_prompt_addition,
    )
    assert len(transcript.verdicts) >= 1
    assert transcript.verdicts[-1].blocked is False
