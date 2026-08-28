"""Tests for `containment.engine.enforce_containment`, one rule at a time."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from containment.chain import AncestorChainResolution
from containment.engine import enforce_containment
from containment.schema import ContainmentViolationReason
from mandate.schema import Mandate
from mandate.signing import generate_keypair
from tests.factories import build_mandate, build_scope

_ZERO = Decimal("0")


def _resolved(parent: Mandate) -> AncestorChainResolution:
    """Wraps a resolved parent mandate as an intact (non-broken) chain resolution.

    Args:
        parent: The immediate parent mandate.

    Returns:
        A resolution bypassing `containment.chain.resolve_ancestor_chain`, so
        each engine rule can be tested in isolation from chain walking.
    """
    return AncestorChainResolution(
        immediate_parent=parent,
        ancestors=(parent,),
        cycle_detected=False,
        depth_exceeded=False,
        unresolvable=False,
    )


def _broken(
    *, cycle: bool = False, depth_exceeded: bool = False, unresolvable: bool = False
) -> AncestorChainResolution:
    """Builds a broken chain resolution with exactly one failure flag set.

    Args:
        cycle: Whether to mark the chain as cycle-broken.
        depth_exceeded: Whether to mark the chain as depth-broken.
        unresolvable: Whether to mark the chain as unresolvable.

    Returns:
        The resolution.
    """
    return AncestorChainResolution(
        immediate_parent=None,
        ancestors=(),
        cycle_detected=cycle,
        depth_exceeded=depth_exceeded,
        unresolvable=unresolvable,
    )


def _parent_and_child(**child_scope_overrides: object) -> tuple[Mandate, Mandate]:
    """Builds a parent mandate and a child chained from it with scope overrides.

    Args:
        **child_scope_overrides: Overrides applied to the child's own scope,
            on top of a scope otherwise identical to the parent's.

    Returns:
        A (parent, child) pair. The child's own expiry is held equal to the
        parent's, so only the overridden scope dimension differs.
    """
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(**child_scope_overrides)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    return parent, child


def test_child_identical_to_parent_passes() -> None:
    """A child whose scope exactly matches its parent's must pass every rule."""
    parent, child = _parent_and_child()
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert result.in_bounds
    assert result.reasons == ()


def test_child_amount_equal_to_parent_is_allowed() -> None:
    """The ceiling comparison is inclusive, matching Layer 2's own convention."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(max_amount=parent.scope.max_amount)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert result.in_bounds


def test_child_amount_exceeding_parent_is_blocked() -> None:
    """A child claiming more than its parent's own ceiling must be caught."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(max_amount=parent.scope.max_amount * 2)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_AMOUNT_EXCEEDS_PARENT in result.reasons


def test_child_currency_mismatch_is_blocked() -> None:
    """A parent's authority in one currency does not authorize another."""
    parent, child = _parent_and_child(currency="USD")
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_CURRENCY_MISMATCH in result.reasons


def test_child_merchant_category_beyond_parent_is_blocked() -> None:
    """A child reaching a merchant category its parent never covered must be caught."""
    parent, child = _parent_and_child(
        allowed_merchant_categories=frozenset({"grocery", "electronics"})
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_MERCHANT_CATEGORY_NOT_SUBSET in result.reasons


def test_child_item_category_beyond_parent_is_blocked() -> None:
    """A child reaching an item category its parent never covered must be caught."""
    parent, child = _parent_and_child(
        allowed_item_categories=frozenset({"packaged_food", "produce", "smartphone"})
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_ITEM_CATEGORY_NOT_SUBSET in result.reasons


def test_child_merchant_id_widened_when_parent_restricts_is_blocked() -> None:
    """A child dropping a merchant-ID pin its parent held must be caught."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=frozenset({"bigbasket"})))
    child_scope = build_scope(allowed_merchant_ids=None)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_MERCHANT_ID_NOT_SUBSET in result.reasons


def test_child_merchant_id_outside_parent_allowlist_is_blocked() -> None:
    """A child naming a merchant its parent's allowlist never included must be caught."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=frozenset({"bigbasket"})))
    child_scope = build_scope(allowed_merchant_ids=frozenset({"bigbasket", "zepto"}))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_MERCHANT_ID_NOT_SUBSET in result.reasons


def test_both_null_merchant_allowlists_are_fine() -> None:
    """Two unrestricted merchant sets are trivially a subset of each other."""
    parent, child = _parent_and_child(allowed_merchant_ids=None)
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_MERCHANT_ID_NOT_SUBSET not in result.reasons


def test_child_window_beyond_parent_is_blocked() -> None:
    """A child's authorized transaction window may not exceed its parent's."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(valid_until=parent.scope.valid_until + timedelta(days=1))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at + timedelta(days=1),
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_WINDOW_NOT_SUBSET in result.reasons


def test_child_transaction_count_exceeding_parent_is_blocked() -> None:
    """A child redeemable more times than its parent must be caught."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_transaction_count=1))
    child_scope = build_scope(max_transaction_count=5)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at,
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.SCOPE_TRANSACTION_COUNT_EXCEEDS_PARENT in result.reasons


def test_child_expiry_beyond_parent_is_blocked() -> None:
    """A delegated mandate outliving its own parent's outright expiry must be caught."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(),
        expires_at=parent.expires_at + timedelta(days=14),
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert ContainmentViolationReason.EXPIRY_EXCEEDS_PARENT in result.reasons


def test_sibling_cap_within_remaining_passes() -> None:
    """A child fitting inside its parent's still-available cap must pass."""
    parent, child = _parent_and_child(max_amount=Decimal("500.00"))
    committed = parent.scope.max_amount - Decimal("500.00")
    result = enforce_containment(child, _resolved(parent), committed)
    assert ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING not in result.reasons


def test_sibling_cap_exceeding_remaining_is_blocked() -> None:
    """A child whose own cap exceeds what siblings left remaining must be caught."""
    parent, child = _parent_and_child(max_amount=Decimal("500.00"))
    committed = parent.scope.max_amount - Decimal("499.00")
    result = enforce_containment(child, _resolved(parent), committed)
    assert ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING in result.reasons


def test_broken_chain_cycle_fails_closed() -> None:
    """A cycle-broken chain must block regardless of the mandate's own scope."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=build_mandate(private_key).mandate_id)
    result = enforce_containment(child, _broken(cycle=True), _ZERO)
    assert not result.in_bounds
    assert result.reasons == (ContainmentViolationReason.CYCLE_DETECTED,)


def test_broken_chain_depth_exceeded_fails_closed() -> None:
    """A depth-broken chain must block regardless of the mandate's own scope."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=build_mandate(private_key).mandate_id)
    result = enforce_containment(child, _broken(depth_exceeded=True), _ZERO)
    assert not result.in_bounds
    assert result.reasons == (ContainmentViolationReason.DEPTH_EXCEEDED,)


def test_broken_chain_unresolvable_fails_closed() -> None:
    """An unresolvable ancestor must block rather than being treated as no constraint."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=build_mandate(private_key).mandate_id)
    result = enforce_containment(child, _broken(unresolvable=True), _ZERO)
    assert not result.in_bounds
    assert result.reasons == (ContainmentViolationReason.UNRESOLVABLE_ANCESTOR,)


def test_all_violated_rules_are_reported_together() -> None:
    """Multiple broken rules must all be reported -- no short-circuiting."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child_scope = build_scope(
        max_amount=parent.scope.max_amount * 10,
        allowed_merchant_categories=frozenset({"grocery", "electronics"}),
        allowed_item_categories=frozenset({"packaged_food", "produce", "smartphone"}),
    )
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope,
        expires_at=parent.expires_at + timedelta(days=1),
    )
    result = enforce_containment(child, _resolved(parent), _ZERO)
    assert {
        ContainmentViolationReason.SCOPE_AMOUNT_EXCEEDS_PARENT,
        ContainmentViolationReason.SCOPE_MERCHANT_CATEGORY_NOT_SUBSET,
        ContainmentViolationReason.SCOPE_ITEM_CATEGORY_NOT_SUBSET,
        ContainmentViolationReason.EXPIRY_EXCEEDS_PARENT,
        ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING,
    } <= set(result.reasons)


def test_enforce_containment_is_pure() -> None:
    """Repeated calls with the same inputs must give the same answer."""
    parent, child = _parent_and_child(max_amount=Decimal("500.00"))
    resolution = _resolved(parent)
    assert enforce_containment(child, resolution, _ZERO) == enforce_containment(child, resolution, _ZERO)
