"""Tests for `detect.baseline`: the stateful rules-only classifier."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from common.schema import EventType, SessionEvent, SessionTrace
from detect.baseline import RulesOnlyBaseline
from detect.resolution import InMemoryMandateResolver
from detect.scope import ScopeViolationReason
from mandate.schema import SignedMandate
from mandate.signing import generate_keypair, sign_mandate
from mandate.verification import AgentKeyRegistry, VerificationFailureReason
from tests.factories import REFERENCE_NOW, build_mandate, build_scope


def _registry_and_mandate(max_transaction_count: int = 3) -> tuple[AgentKeyRegistry, SignedMandate]:
    """Builds a registry with one registered agent and a mandate it signed.

    Args:
        max_transaction_count: Redemptions the mandate authorizes.

    Returns:
        The registry and the signed mandate.
    """
    private_key, public_key = generate_keypair()
    scope = build_scope(max_transaction_count=max_transaction_count)
    mandate = build_mandate(private_key, scope=scope)
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    return registry, signed


def _trace(signed: SignedMandate, started_at: object, **overrides: object) -> SessionTrace:
    """Builds an in-scope session presenting `signed` at a given time.

    Args:
        signed: The mandate presented.
        started_at: Session start time.
        **overrides: Field values to override.

    Returns:
        The session trace.
    """
    defaults: dict[str, object] = {
        "session_id": uuid4(),
        "agent_id": signed.mandate.agent_id,
        "user_id": signed.mandate.user_id,
        "mandate_id": signed.mandate.mandate_id,
        "merchant_id": "bigbasket",
        "merchant_category": "grocery",
        "item_category": "packaged_food",
        "amount": Decimal("450.00"),
        "currency": "INR",
        "events": [
            SessionEvent(event_type=EventType.INTENT_CAPTURED, timestamp=started_at),  # type: ignore[arg-type]
            SessionEvent(event_type=EventType.PAYMENT_RESULT, timestamp=started_at),  # type: ignore[arg-type]
        ],
        "started_at": started_at,
        "completed_at": started_at,
    }
    defaults.update(overrides)
    return SessionTrace(**defaults)  # type: ignore[arg-type]


def test_valid_in_scope_session_is_allowed() -> None:
    """A session passing both layers must not be blocked."""
    registry, signed = _registry_and_mandate()
    trace = _trace(signed, REFERENCE_NOW)
    baseline = RulesOnlyBaseline(registry, InMemoryMandateResolver({trace.session_id: signed}))
    decision = baseline.decide(trace)
    assert not decision.blocked
    assert decision.fired_rules == ()


def test_unresolvable_mandate_is_blocked() -> None:
    """A session whose mandate cannot be produced must be blocked, not skipped."""
    registry, signed = _registry_and_mandate()
    trace = _trace(signed, REFERENCE_NOW)
    baseline = RulesOnlyBaseline(registry, InMemoryMandateResolver({}))
    decision = baseline.decide(trace)
    assert decision.blocked
    assert decision.scope_reasons == (ScopeViolationReason.NO_MANDATE_PRESENTED,)


def test_budget_is_consumed_across_a_session_stream() -> None:
    """Replaying a mandate past its authorized count must be caught by the ledger."""
    registry, signed = _registry_and_mandate(max_transaction_count=2)
    traces = [_trace(signed, REFERENCE_NOW + timedelta(hours=i)) for i in range(3)]
    resolver = InMemoryMandateResolver({t.session_id: signed for t in traces})
    decisions = RulesOnlyBaseline(registry, resolver).decide_all(traces)
    assert [d.blocked for d in decisions] == [False, False, True]
    assert VerificationFailureReason.BUDGET_EXHAUSTED in decisions[2].verification_reasons


def test_blocked_sessions_do_not_consume_budget() -> None:
    """A blocked transaction never reaches authorization, so it must not spend the mandate.

    Otherwise an attacker could exhaust a legitimate user's budget purely by
    submitting sessions the detector rejects.
    """
    registry, signed = _registry_and_mandate(max_transaction_count=1)
    over_ceiling = _trace(signed, REFERENCE_NOW, amount=signed.mandate.scope.max_amount + Decimal("1"))
    legitimate = _trace(signed, REFERENCE_NOW + timedelta(hours=1))
    resolver = InMemoryMandateResolver({over_ceiling.session_id: signed, legitimate.session_id: signed})
    decisions = RulesOnlyBaseline(registry, resolver).decide_all([over_ceiling, legitimate])
    assert decisions[0].blocked
    assert not decisions[1].blocked


def test_both_layers_report_together() -> None:
    """A session failing both layers must name rules from both."""
    registry, signed = _registry_and_mandate()
    late = signed.mandate.scope.valid_until + timedelta(days=1)
    trace = _trace(signed, late, amount=Decimal("999999.00"))
    baseline = RulesOnlyBaseline(registry, InMemoryMandateResolver({trace.session_id: signed}))
    fired = baseline.decide(trace).fired_rules
    assert any(rule.startswith("layer1:") for rule in fired)
    assert any(rule.startswith("layer2:") for rule in fired)


def test_out_of_order_input_fails_loudly() -> None:
    """Unsorted input would evaluate the budget rule against a future ledger."""
    registry, signed = _registry_and_mandate()
    first = _trace(signed, REFERENCE_NOW)
    earlier = _trace(signed, REFERENCE_NOW - timedelta(hours=1))
    resolver = InMemoryMandateResolver({first.session_id: signed, earlier.session_id: signed})
    with pytest.raises(ValueError, match="chronologically ordered"):
        RulesOnlyBaseline(registry, resolver).decide_all([first, earlier])