"""Tests for `common.schema`: session trace and label invariants."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from common.schema import (
    AttackClass,
    EventType,
    LabeledSession,
    SessionEvent,
    SessionTrace,
)
from tests.factories import REFERENCE_NOW


def _build_trace(**overrides: object) -> SessionTrace:
    defaults: dict[str, object] = {
        "session_id": uuid4(),
        "agent_id": "agent-grocery-bot-01",
        "user_id": "user-0001",
        "mandate_id": uuid4(),
        "merchant_id": "merchant-bigbasket",
        "merchant_category": "grocery",
        "item_category": "packaged_food",
        "amount": Decimal("450.00"),
        "currency": "INR",
        "events": [
            SessionEvent(event_type=EventType.INTENT_CAPTURED, timestamp=REFERENCE_NOW),
            SessionEvent(
                event_type=EventType.PAYMENT_RESULT,
                timestamp=REFERENCE_NOW + timedelta(minutes=2),
            ),
        ],
        "started_at": REFERENCE_NOW,
        "completed_at": REFERENCE_NOW + timedelta(minutes=2),
    }
    defaults.update(overrides)
    return SessionTrace(**defaults)  # type: ignore[arg-type]


def test_valid_trace_constructs() -> None:
    """A trace with the standard fixture shape should construct without error."""
    trace = _build_trace()
    assert trace.amount == Decimal("450.00")


def test_rejects_empty_events() -> None:
    """A session with no events is malformed input, not a zero-length legitimate case."""
    with pytest.raises(ValidationError, match="zero events"):
        _build_trace(events=[])


def test_rejects_completed_before_started() -> None:
    """completed_at before started_at must fail loudly."""
    with pytest.raises(ValidationError, match="precedes started_at"):
        _build_trace(
            started_at=REFERENCE_NOW,
            completed_at=REFERENCE_NOW - timedelta(minutes=1),
        )


def test_rejects_non_positive_amount() -> None:
    """A zero or negative amount session must be rejected."""
    with pytest.raises(ValidationError, match="must be positive"):
        _build_trace(amount=Decimal("0"))


def test_mandate_id_may_be_none() -> None:
    """A session with no mandate presented at all must still be constructible.

    This is itself a Layer 2 finding (no authorization presented), not a
    malformed trace.
    """
    trace = _build_trace(mandate_id=None)
    assert trace.mandate_id is None


class TestLabeledSession:
    """Ground-truth wrapper invariants."""

    def test_consistent_label_constructs(self) -> None:
        """is_attack matching attack_class should construct without error."""
        labeled = LabeledSession(
            trace=_build_trace(),
            attack_class=AttackClass.LEGITIMATE,
            is_attack=False,
            generator_seed=42,
            generator_params_digest="deadbeef",
        )
        assert not labeled.is_attack

    def test_rejects_inconsistent_is_attack_true(self) -> None:
        """is_attack=True with attack_class=LEGITIMATE must be rejected."""
        with pytest.raises(ValidationError, match="inconsistent"):
            LabeledSession(
                trace=_build_trace(),
                attack_class=AttackClass.LEGITIMATE,
                is_attack=True,
                generator_seed=42,
                generator_params_digest="deadbeef",
            )

    def test_rejects_inconsistent_is_attack_false(self) -> None:
        """is_attack=False with a non-legitimate attack_class must be rejected."""
        with pytest.raises(ValidationError, match="inconsistent"):
            LabeledSession(
                trace=_build_trace(),
                attack_class=AttackClass.SCOPE_VIOLATION,
                is_attack=False,
                generator_seed=42,
                generator_params_digest="deadbeef",
            )