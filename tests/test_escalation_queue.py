"""Tests for `escalation.queue.EscalationQueue`: the full open/review/resolve workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from escalation.circuit_breaker import CircuitBreaker
from escalation.queue import (
    EscalationNotFoundError,
    EscalationQueue,
    HumanActionRequiredError,
    InvalidTransitionError,
)
from escalation.schema import EscalationStatus, ResolutionDecision

_T0 = datetime(2026, 8, 30, 0, 0, 0, tzinfo=UTC)


def _queue(tmp_path: Path, **breaker_kwargs: object) -> EscalationQueue:
    """Builds a fresh queue backed by a temp-file log.

    Args:
        tmp_path: The pytest temp directory fixture.
        **breaker_kwargs: Overrides for the circuit breaker.

    Returns:
        A fresh `EscalationQueue`.
    """
    breaker = CircuitBreaker(**breaker_kwargs) if breaker_kwargs else CircuitBreaker()  # type: ignore[arg-type]
    return EscalationQueue.from_path(tmp_path / "escalations.jsonl", breaker=breaker)


def test_open_escalation_creates_an_open_record(tmp_path: Path) -> None:
    """Opening an escalation must produce an OPEN record with the system as actor."""
    queue = _queue(tmp_path)
    session_id = uuid4()
    escalation = queue.open_escalation(session_id, "agent-1", "score 0.94 >= 0.0251", at=_T0)
    assert escalation.status is EscalationStatus.OPEN
    assert escalation.session_id == session_id
    assert escalation.agent_id == "agent-1"
    assert len(escalation.events) == 1
    assert escalation.events[0].actor == "system"


def test_review_then_resolve_moves_through_every_state(tmp_path: Path) -> None:
    """The full workflow must move OPEN -> REVIEWED -> RESOLVED, each attributed to a human."""
    queue = _queue(tmp_path)
    escalation = queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)

    reviewed = queue.review(escalation.escalation_id, actor="reviewer-1", note="looks suspicious", at=_T0)
    assert reviewed.status is EscalationStatus.REVIEWED
    assert reviewed.reviewed_by == "reviewer-1"

    resolved = queue.resolve(
        escalation.escalation_id,
        actor="reviewer-1",
        note="confirmed after checking merchant history",
        decision=ResolutionDecision.CONFIRMED_ATTACK,
        at=_T0 + timedelta(minutes=5),
    )
    assert resolved.status is EscalationStatus.RESOLVED
    assert resolved.resolution is ResolutionDecision.CONFIRMED_ATTACK
    assert resolved.resolved_by == "reviewer-1"


def test_resolve_without_review_is_rejected(tmp_path: Path) -> None:
    """Resolving straight from OPEN, skipping review, must not be allowed."""
    queue = _queue(tmp_path)
    escalation = queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    with pytest.raises(InvalidTransitionError):
        queue.resolve(
            escalation.escalation_id, actor="reviewer-1", note="", decision=ResolutionDecision.CLEARED, at=_T0
        )


def test_review_by_system_actor_is_rejected(tmp_path: Path) -> None:
    """A review claiming the system actor must be rejected -- this is the human-in-the-loop guarantee."""
    queue = _queue(tmp_path)
    escalation = queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    with pytest.raises(HumanActionRequiredError):
        queue.review(escalation.escalation_id, actor="system", note="", at=_T0)


def test_review_of_unknown_escalation_raises(tmp_path: Path) -> None:
    """Reviewing a nonexistent escalation ID must fail clearly, not silently no-op."""
    queue = _queue(tmp_path)
    with pytest.raises(EscalationNotFoundError):
        queue.review(uuid4(), actor="reviewer-1", note="", at=_T0)


def test_re_reviewing_an_already_reviewed_escalation_is_rejected(tmp_path: Path) -> None:
    """A second review of an already-reviewed escalation must be rejected, not silently accepted."""
    queue = _queue(tmp_path)
    escalation = queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    queue.review(escalation.escalation_id, actor="reviewer-1", note="first pass", at=_T0)
    with pytest.raises(InvalidTransitionError):
        queue.review(escalation.escalation_id, actor="reviewer-2", note="second pass", at=_T0)


def test_circuit_breaker_trips_after_enough_escalations_for_one_agent(tmp_path: Path) -> None:
    """Enough escalations for one agent within the window must auto-suspend it."""
    queue = _queue(tmp_path, threshold=2, window=timedelta(hours=24))
    queue.open_escalation(uuid4(), "agent-1", "first", at=_T0)
    assert not queue.is_agent_suspended("agent-1")

    queue.open_escalation(uuid4(), "agent-1", "second", at=_T0 + timedelta(hours=1))
    assert queue.is_agent_suspended("agent-1")


def test_suspension_from_one_agent_does_not_affect_another(tmp_path: Path) -> None:
    """Two escalations against different agents must not jointly trip either one's breaker."""
    queue = _queue(tmp_path, threshold=2, window=timedelta(hours=24))
    queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    queue.open_escalation(uuid4(), "agent-2", "reason", at=_T0)
    assert not queue.is_agent_suspended("agent-1")
    assert not queue.is_agent_suspended("agent-2")


def test_reset_circuit_breaker_requires_a_human_actor(tmp_path: Path) -> None:
    """A circuit-breaker reset claiming the system actor must be rejected."""
    queue = _queue(tmp_path, threshold=1, window=timedelta(hours=24))
    queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    assert queue.is_agent_suspended("agent-1")
    with pytest.raises(HumanActionRequiredError):
        queue.reset_circuit_breaker("agent-1", actor="system", note="", at=_T0)


def test_reset_circuit_breaker_lifts_suspension(tmp_path: Path) -> None:
    """An explicit human reset must lift a suspension."""
    queue = _queue(tmp_path, threshold=1, window=timedelta(hours=24))
    queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    assert queue.is_agent_suspended("agent-1")

    queue.reset_circuit_breaker("agent-1", actor="reviewer-1", note="false positive pattern, cleared", at=_T0)
    assert not queue.is_agent_suspended("agent-1")


def test_reset_of_a_not_suspended_agent_is_rejected(tmp_path: Path) -> None:
    """Resetting an agent that was never suspended must fail clearly, not silently no-op."""
    queue = _queue(tmp_path)
    with pytest.raises(InvalidTransitionError):
        queue.reset_circuit_breaker("agent-1", actor="reviewer-1", note="", at=_T0)


def test_list_all_filters_by_status_and_agent(tmp_path: Path) -> None:
    """list_all must filter by status and agent independently."""
    queue = _queue(tmp_path)
    open_one = queue.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    queue.open_escalation(uuid4(), "agent-2", "reason", at=_T0)
    queue.review(open_one.escalation_id, actor="reviewer-1", note="", at=_T0)

    assert len(queue.list_all(agent_id="agent-1")) == 1
    assert len(queue.list_all(status=EscalationStatus.OPEN)) == 1
    assert len(queue.list_all(status=EscalationStatus.REVIEWED)) == 1
    assert len(queue.list_all()) == 2


def test_replaying_from_an_existing_log_rebuilds_the_same_state(tmp_path: Path) -> None:
    """A fresh EscalationQueue built from a log with existing history must rebuild identical state."""
    path = tmp_path / "escalations.jsonl"
    first = EscalationQueue.from_path(path, breaker=CircuitBreaker(threshold=2, window=timedelta(hours=24)))
    escalation = first.open_escalation(uuid4(), "agent-1", "reason", at=_T0)
    first.review(escalation.escalation_id, actor="reviewer-1", note="", at=_T0)
    first.open_escalation(uuid4(), "agent-1", "second", at=_T0 + timedelta(hours=1))
    assert first.is_agent_suspended("agent-1")

    second = EscalationQueue.from_path(path, breaker=CircuitBreaker(threshold=2, window=timedelta(hours=24)))
    rebuilt = second.get(escalation.escalation_id)
    assert rebuilt is not None
    assert rebuilt.status is EscalationStatus.REVIEWED
    assert second.is_agent_suspended("agent-1")
