"""Tests for `escalation.log`: hash-chained persistence of `EscalationEvent`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from escalation.log import EscalationLog, verify_chain
from escalation.schema import EscalationEvent, EscalationEventKind


def _event(**overrides: object) -> EscalationEvent:
    """Builds a minimally valid `EscalationEvent`, overridable per test.

    Args:
        **overrides: Field values to override.

    Returns:
        A valid event.
    """
    defaults: dict[str, object] = {
        "event_id": uuid4(),
        "escalation_id": uuid4(),
        "session_id": uuid4(),
        "agent_id": "agent-001",
        "kind": EscalationEventKind.OPENED,
        "actor": "system",
        "note": "behavioral score 0.94 >= threshold 0.0251",
        "created_at": datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return EscalationEvent(**defaults)  # type: ignore[arg-type]


def test_append_then_read_all_round_trips(tmp_path: Path) -> None:
    """A written event must read back with every field intact."""
    log = EscalationLog(tmp_path / "escalations.jsonl")
    event = _event()
    log.append(event)
    assert log.read_all() == (event,)


def test_circuit_breaker_event_round_trips_with_none_escalation_and_session(tmp_path: Path) -> None:
    """A circuit-breaker event's None escalation_id/session_id must round-trip as None, not a sentinel string."""
    log = EscalationLog(tmp_path / "escalations.jsonl")
    event = _event(
        escalation_id=None, session_id=None, kind=EscalationEventKind.CIRCUIT_BREAKER_SUSPENDED, note="3 within 24h"
    )
    log.append(event)
    read_back = log.read_all()[0]
    assert read_back.escalation_id is None
    assert read_back.session_id is None


def test_events_are_read_back_in_append_order(tmp_path: Path) -> None:
    """Multiple events must replay in the order they were appended."""
    log = EscalationLog(tmp_path / "escalations.jsonl")
    first = _event(event_id=uuid4())
    second = _event(event_id=uuid4(), kind=EscalationEventKind.REVIEWED, actor="reviewer-1")
    log.append(first)
    log.append(second)
    assert log.read_all() == (first, second)


def test_chain_verifies_intact_across_multiple_events(tmp_path: Path) -> None:
    """A log written normally, untouched afterward, must verify intact end to end."""
    log = EscalationLog(tmp_path / "escalations.jsonl")
    for _ in range(4):
        log.append(_event(event_id=uuid4()))
    result = verify_chain(log)
    assert result.intact
    assert result.total_records == 4


def test_exposes_no_mutation_or_deletion_method() -> None:
    """The public interface must stay append-only: no update, delete, or clear method."""
    public_methods = {name for name in dir(EscalationLog) if not name.startswith("_")}
    assert public_methods == {"path", "append", "read_entries", "read_all"}
