"""Tests for `containment.gate.ContainmentGate`: statefulness across a session stream."""

from __future__ import annotations

from decimal import Decimal

from containment.gate import ContainmentGate
from containment.schema import ContainmentViolationReason
from containment.store import InMemoryMandateChainStore
from mandate.signing import generate_keypair
from tests.factories import build_mandate, build_scope


def test_root_mandate_passes_trivially_without_store_lookup() -> None:
    """A mandate with no parent has nothing to check, and needs no store entry."""
    private_key, _ = generate_keypair()
    root = build_mandate(private_key)
    gate = ContainmentGate(InMemoryMandateChainStore({}))
    result = gate.decide(root)
    assert result.in_bounds
    assert result.reasons == ()


def test_single_delegation_within_parent_scope_passes() -> None:
    """A well-formed one-level delegation must pass."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child = build_mandate(private_key, parent_mandate_id=parent.mandate_id, expires_at=parent.expires_at)
    store = InMemoryMandateChainStore({parent.mandate_id: parent})
    gate = ContainmentGate(store)
    result = gate.decide(child)
    assert result.in_bounds


def test_delegation_exceeding_parent_scope_is_blocked() -> None:
    """A child inflating its ceiling past its parent's must be blocked."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(max_amount=parent.scope.max_amount * 5)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    store = InMemoryMandateChainStore({parent.mandate_id: parent})
    gate = ContainmentGate(store)
    result = gate.decide(child)
    assert not result.in_bounds
    assert ContainmentViolationReason.SCOPE_AMOUNT_EXCEEDS_PARENT in result.reasons


def test_sibling_cap_first_child_allowed_second_blocked() -> None:
    """Fan-out structuring: the first sibling fits, later siblings exceed what remains.

    Mirrors the `fanout_structuring` held-out variant: several children each
    individually within their own declared ceiling, but whose combined
    ceilings exceed the parent's. The first sibling processed consumes the
    parent's remaining cap; the next one to arrive is measured against what
    is left, not against the parent's original cap again.
    """
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("1000.00")))
    store_index = {parent.mandate_id: parent}

    sibling_scope = build_scope(max_amount=Decimal("750.00"))
    sibling_one = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=sibling_scope,
        expires_at=parent.expires_at,
    )
    sibling_two = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=sibling_scope,
        expires_at=parent.expires_at,
    )
    store_index[sibling_one.mandate_id] = sibling_one
    store_index[sibling_two.mandate_id] = sibling_two

    gate = ContainmentGate(InMemoryMandateChainStore(store_index))

    first = gate.decide(sibling_one)
    second = gate.decide(sibling_two)

    assert first.in_bounds
    assert not second.in_bounds
    assert ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING in second.reasons


def test_rejected_sibling_does_not_consume_remaining_cap() -> None:
    """A blocked child must not count as committed against its parent's remaining cap."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("1000.00")))

    over_cap_scope = build_scope(max_amount=Decimal("2000.00"))
    rejected_sibling = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=over_cap_scope,
        expires_at=parent.expires_at,
    )
    fits_scope = build_scope(max_amount=Decimal("900.00"))
    fitting_sibling = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=fits_scope,
        expires_at=parent.expires_at,
    )
    store = InMemoryMandateChainStore({parent.mandate_id: parent})
    gate = ContainmentGate(store)

    rejected_result = gate.decide(rejected_sibling)
    fitting_result = gate.decide(fitting_sibling)

    assert not rejected_result.in_bounds
    assert fitting_result.in_bounds


def test_reusing_the_same_mandate_does_not_double_commit() -> None:
    """A mandate reused across two sessions must only commit its cap once."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("1000.00")))
    child_scope = build_scope(max_amount=Decimal("900.00"))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    store = InMemoryMandateChainStore({parent.mandate_id: parent})
    gate = ContainmentGate(store)

    first_use = gate.decide(child)
    second_use = gate.decide(child)

    assert first_use.in_bounds
    assert second_use.in_bounds
