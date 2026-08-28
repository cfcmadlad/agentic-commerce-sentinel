"""Tests for `formal.model`: sanity-checks that each builder evaluates correctly.

These are ordinary concrete-value tests, not the exhaustive properties
themselves (those live in `tests/test_formal_verify.py`) -- they exist to
catch a mistake in the *encoding's plumbing* (a swapped comparison, a wrong
field) using cases whose expected answer is obvious by inspection, before
trusting the same builders inside an exhaustive proof.
"""

from __future__ import annotations

import z3  # type: ignore[import-untyped]

from formal.model import (
    ITEM_CATEGORIES,
    MERCHANT_CATEGORIES,
    MERCHANT_IDS,
    MerchantCategory,
    MerchantId,
    contained,
    final_blocked,
    flagged_for_hold,
    fresh_containment_vars,
    fresh_ensemble_vars,
    fresh_scope_vars,
    fresh_sibling_group_vars,
    fresh_verification_vars,
    in_scope,
    mandate_verified,
    sibling_group_accepted_and_committed,
)
from formal.properties import Property
from formal.verify import verify_property


def _is_true_for(formula: z3.BoolRef, assumptions: list[z3.BoolRef]) -> bool:
    """Checks whether a formula holds under a fixed set of concrete assumptions.

    Args:
        formula: The formula to check.
        assumptions: Concrete equalities/constraints pinning every relevant
            variable to a specific value.

    Returns:
        True iff `formula` is satisfiable under exactly these assumptions.
    """
    solver = z3.Solver()
    solver.add(*assumptions, formula)
    return bool(solver.check() == z3.sat)


def test_mandate_verified_true_for_a_fully_compliant_mandate() -> None:
    """A mandate satisfying every Layer 1 check must verify."""
    v = fresh_verification_vars("t1")
    assumptions = [
        v.has_registered_key, v.signature_valid,
        v.now == 100, v.valid_from == 50, v.valid_until == 200, v.expires_at == 200,
        v.usage_count == 0, v.max_transaction_count == 5,
    ]
    assert _is_true_for(mandate_verified(v), assumptions)


def test_mandate_verified_false_when_expired() -> None:
    """A mandate past its own expiry must not verify, all else compliant."""
    v = fresh_verification_vars("t2")
    assumptions = [
        v.has_registered_key, v.signature_valid,
        v.now == 201, v.valid_from == 50, v.valid_until == 500, v.expires_at == 200,
        v.usage_count == 0, v.max_transaction_count == 5,
    ]
    assert not _is_true_for(mandate_verified(v), assumptions)


def test_mandate_verified_false_when_key_unregistered() -> None:
    """A mandate with no registered key must not verify."""
    v = fresh_verification_vars("t3")
    assumptions = [
        z3.Not(v.has_registered_key), v.signature_valid,
        v.now == 100, v.valid_from == 50, v.valid_until == 200, v.expires_at == 200,
        v.usage_count == 0, v.max_transaction_count == 5,
    ]
    assert not _is_true_for(mandate_verified(v), assumptions)


def test_in_scope_true_for_a_fully_compliant_session() -> None:
    """A session satisfying every Layer 2 check must be in scope."""
    v = fresh_scope_vars("t4")
    category = MERCHANT_CATEGORIES[0]
    item = ITEM_CATEGORIES[0]
    assumptions = [
        v.mandate_id_match, v.agent_id_match, v.user_id_match,
        v.amount == 500, v.max_amount == 2000,
        v.currency_match,
        v.merchant_category == category,
        v.allowed_merchant_categories == z3.SetAdd(z3.EmptySet(MerchantCategory), category),
        v.item_category == item,
        v.allowed_item_categories == z3.SetAdd(z3.EmptySet(item.sort()), item),
        z3.Not(v.has_merchant_restriction),
        v.session_time == 100, v.valid_from == 0, v.valid_until == 200,
    ]
    assert _is_true_for(in_scope(v), assumptions)


def test_in_scope_false_when_amount_over_ceiling() -> None:
    """A session over the ceiling must not be in scope, all else compliant."""
    v = fresh_scope_vars("t5")
    category = MERCHANT_CATEGORIES[0]
    item = ITEM_CATEGORIES[0]
    assumptions = [
        v.mandate_id_match, v.agent_id_match, v.user_id_match,
        v.amount == 2001, v.max_amount == 2000,
        v.currency_match,
        v.merchant_category == category,
        v.allowed_merchant_categories == z3.SetAdd(z3.EmptySet(MerchantCategory), category),
        v.item_category == item,
        v.allowed_item_categories == z3.SetAdd(z3.EmptySet(item.sort()), item),
        z3.Not(v.has_merchant_restriction),
        v.session_time == 100, v.valid_from == 0, v.valid_until == 200,
    ]
    assert not _is_true_for(in_scope(v), assumptions)


def test_in_scope_false_when_merchant_restricted_and_not_listed() -> None:
    """A restricted merchant allowlist that excludes the transaction's merchant must deny."""
    v = fresh_scope_vars("t6")
    category = MERCHANT_CATEGORIES[0]
    item = ITEM_CATEGORIES[0]
    m0 = MERCHANT_IDS[0]
    m1 = MERCHANT_IDS[1]
    assumptions = [
        v.mandate_id_match, v.agent_id_match, v.user_id_match,
        v.amount == 500, v.max_amount == 2000,
        v.currency_match,
        v.merchant_category == category,
        v.allowed_merchant_categories == z3.SetAdd(z3.EmptySet(MerchantCategory), category),
        v.item_category == item,
        v.allowed_item_categories == z3.SetAdd(z3.EmptySet(item.sort()), item),
        v.has_merchant_restriction,
        v.merchant_id == m0,
        v.allowed_merchant_ids == z3.SetAdd(z3.EmptySet(MerchantId), m1),  # m0 not in {m1}
        v.session_time == 100, v.valid_from == 0, v.valid_until == 200,
    ]
    assert not _is_true_for(in_scope(v), assumptions)


def test_contained_true_for_an_identical_child() -> None:
    """A child whose fields exactly match its parent's must be contained."""
    v = fresh_containment_vars("t7")
    assumptions = [
        v.child_max_amount == 500, v.parent_max_amount == 500,
        v.currency_match,
        v.child_merchant_categories == v.parent_merchant_categories,
        v.child_item_categories == v.parent_item_categories,
        z3.Not(v.parent_has_merchant_restriction),
        v.child_valid_from == 100, v.parent_valid_from == 100,
        v.child_valid_until == 200, v.parent_valid_until == 200,
        v.child_max_transaction_count == 3, v.parent_max_transaction_count == 3,
        v.child_expires_at == 200, v.parent_expires_at == 200,
        v.committed_sibling_total == 0,
        v.depth == 1, z3.Not(v.cycle_detected), z3.Not(v.unresolvable),
    ]
    assert _is_true_for(contained(v), assumptions)


def test_contained_false_when_child_amount_exceeds_parent() -> None:
    """A child ceiling above its parent's must not be contained."""
    v = fresh_containment_vars("t8")
    assumptions = [
        v.child_max_amount == 5000, v.parent_max_amount == 500,
        v.currency_match,
        v.child_merchant_categories == v.parent_merchant_categories,
        v.child_item_categories == v.parent_item_categories,
        z3.Not(v.parent_has_merchant_restriction),
        v.child_valid_from == 100, v.parent_valid_from == 100,
        v.child_valid_until == 200, v.parent_valid_until == 200,
        v.child_max_transaction_count == 3, v.parent_max_transaction_count == 3,
        v.child_expires_at == 200, v.parent_expires_at == 200,
        v.committed_sibling_total == 0,
        v.depth == 1, z3.Not(v.cycle_detected), z3.Not(v.unresolvable),
    ]
    assert not _is_true_for(contained(v), assumptions)


def test_contained_false_on_cycle() -> None:
    """A cycle-broken chain must not be contained, regardless of scope compliance."""
    v = fresh_containment_vars("t9")
    assumptions = [
        v.child_max_amount == 500, v.parent_max_amount == 500,
        v.currency_match,
        v.child_merchant_categories == v.parent_merchant_categories,
        v.child_item_categories == v.parent_item_categories,
        z3.Not(v.parent_has_merchant_restriction),
        v.child_valid_from == 100, v.parent_valid_from == 100,
        v.child_valid_until == 200, v.parent_valid_until == 200,
        v.child_max_transaction_count == 3, v.parent_max_transaction_count == 3,
        v.child_expires_at == 200, v.parent_expires_at == 200,
        v.committed_sibling_total == 0,
        v.depth == 1, v.cycle_detected, z3.Not(v.unresolvable),
    ]
    assert not _is_true_for(contained(v), assumptions)


def test_sibling_group_recurrence_matches_a_hand_computed_fanout_example() -> None:
    """Replays the fanout_structuring shape by hand: first sibling fits, the rest don't.

    Mirrors `docs/adr/0004`'s own measured result for this exact pattern:
    parent cap 1000, four siblings each claiming 750 -- only the first is
    accepted.
    """
    v = fresh_sibling_group_vars("t10", 4)
    accepted, total = sibling_group_accepted_and_committed(v)

    solver = z3.Solver()
    solver.add(v.parent_max_amount == 1000)
    for amount in v.sibling_amounts:
        solver.add(amount == 750)
    assert solver.check() == z3.sat
    model = solver.model()

    expected = [True, False, False, False]
    for flag, expected_value in zip(accepted, expected, strict=True):
        assert bool(model.eval(flag, model_completion=True)) == expected_value
    assert model.eval(total, model_completion=True).as_long() == 750


def test_ensemble_flagged_for_hold_requires_escalation_alone() -> None:
    """A session both rules-blocked and escalated is not 'flagged for hold' -- it's just blocked."""
    v = fresh_ensemble_vars("t11")
    assumptions = [v.rules_blocked, v.escalated, z3.Not(v.containment_blocked)]
    assert _is_true_for(final_blocked(v), assumptions)
    assert not _is_true_for(flagged_for_hold(v), assumptions)


def test_verify_property_extracts_a_real_counterexample_for_a_false_claim() -> None:
    """Sanity-checks the harness itself: a false property must come back unproved with a witness."""
    v = fresh_verification_vars("t12")
    false_property = Property(
        name="test_false_claim",
        layer="test",
        description="deliberately false, for harness sanity-checking only",
        formula=z3.Implies(v.now >= 0, mandate_verified(v)),
    )
    result = verify_property(false_property)
    assert not result.proved
    assert result.counterexample is not None
    assert len(result.counterexample) > 0
