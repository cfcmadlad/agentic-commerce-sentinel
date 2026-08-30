"""Tests for `escalation.circuit_breaker.CircuitBreaker`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from escalation.circuit_breaker import CircuitBreaker

_T0 = datetime(2026, 8, 30, 0, 0, 0, tzinfo=UTC)


def test_agent_not_suspended_below_threshold() -> None:
    """Fewer escalations than the threshold must not trip suspension."""
    breaker = CircuitBreaker(threshold=3, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    assert not breaker.is_suspended("agent-1")


def test_agent_suspended_at_threshold_within_window() -> None:
    """Reaching the threshold within the window must trip suspension."""
    breaker = CircuitBreaker(threshold=3, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    tripped = breaker.record_escalation("agent-1", _T0 + timedelta(hours=2))
    assert tripped
    assert breaker.is_suspended("agent-1")


def test_escalations_outside_the_window_do_not_count() -> None:
    """Old escalations that have aged out of the window must not contribute to the count."""
    breaker = CircuitBreaker(threshold=3, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=25))  # first has aged out by now
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=26))
    assert not breaker.is_suspended("agent-1")


def test_suspension_is_sticky_even_after_the_triggering_window_passes() -> None:
    """Once tripped, suspension must not clear itself just because time moves on."""
    breaker = CircuitBreaker(threshold=2, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    assert breaker.is_suspended("agent-1")

    # A much later check -- no new escalations recorded, no window recomputation happens
    # on its own -- must still report suspended.
    assert breaker.is_suspended("agent-1")


def test_reset_clears_suspension() -> None:
    """An explicit reset is the only thing that lifts a suspension."""
    breaker = CircuitBreaker(threshold=2, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    assert breaker.is_suspended("agent-1")

    breaker.reset("agent-1")
    assert not breaker.is_suspended("agent-1")


def test_reset_clears_history_so_a_fresh_escalation_does_not_immediately_retrip() -> None:
    """After a reset, a single new escalation alone must not re-trip suspension."""
    breaker = CircuitBreaker(threshold=2, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    breaker.reset("agent-1")

    tripped = breaker.record_escalation("agent-1", _T0 + timedelta(hours=2))
    assert not tripped
    assert not breaker.is_suspended("agent-1")


def test_agents_are_tracked_independently() -> None:
    """One agent's escalations must never affect another agent's suspension state."""
    breaker = CircuitBreaker(threshold=2, window=timedelta(hours=24))
    breaker.record_escalation("agent-1", _T0)
    breaker.record_escalation("agent-1", _T0 + timedelta(hours=1))
    assert breaker.is_suspended("agent-1")
    assert not breaker.is_suspended("agent-2")
