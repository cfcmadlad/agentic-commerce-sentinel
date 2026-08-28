"""The eight safety properties this milestone proves, each a named function.

Every property is stated as an implication -- a premise about the encoded
inputs, and a conclusion that must hold whenever the premise does, for every
value of every other variable in the encoding's bounded space.
`formal/verify.py` proves each one by asserting its *negation* and checking
that no satisfying assignment exists (`unsat`): if there were one, it would
be a concrete counterexample to the property, and Z3 would report it.

Properties are grouped by which layer's logic they concern. P1-P2 are Layer
2 (scope enforcement); P3-P4 are Layer 1 (mandate verification); P5-P7 are
Layer 2.5 (containment); P8 concerns the combination logic across every
deterministic layer plus Layer 3's (entirely abstracted, unconstrained)
contribution.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3  # type: ignore[import-untyped]

from containment.schema import MAX_DELEGATION_DEPTH
from formal.model import (
    FANOUT_SIBLING_COUNT,
    EnsembleVars,
    ScopeVars,
    VerificationVars,
    contained,
    containment_bounds,
    final_blocked,
    flagged_for_hold,
    fresh_containment_vars,
    fresh_ensemble_vars,
    fresh_scope_vars,
    fresh_sibling_group_vars,
    fresh_verification_vars,
    in_scope,
    mandate_verified,
    scope_bounds,
    sibling_group_accepted_and_committed,
    sibling_group_bounds,
    verification_bounds,
)


@dataclass(frozen=True)
class Property:
    """One safety property, ready to be checked.

    Attributes:
        name: A short, stable identifier (e.g. `"amount_ceiling_no_tolerance"`).
        layer: Which layer's logic the property concerns.
        description: A one-sentence, human-readable statement of the property.
        formula: The property itself -- an implication that must be a
            tautology over the bounded encoded space. `formal/verify.py`
            asserts `z3.Not(formula)` and checks for `unsat`.
    """

    name: str
    layer: str
    description: str
    formula: z3.BoolRef


def _p1_amount_ceiling_no_tolerance() -> Property:
    """Builds P1: an over-ceiling amount always denies scope, regardless of every other field."""
    v: ScopeVars = fresh_scope_vars("p1")
    premise = z3.And(scope_bounds(v), v.amount > v.max_amount)
    formula = z3.Implies(premise, z3.Not(in_scope(v)))
    return Property(
        name="amount_ceiling_no_tolerance",
        layer="Layer 2 (scope enforcement)",
        description=(
            "An amount strictly over the mandate's ceiling always denies scope, no matter what "
            "every other field is set to -- there is no combination of matching currency, category, "
            "merchant, or timing that lets an over-ceiling transaction through."
        ),
        formula=formula,
    )


def _p2_merchant_allowlist_cannot_be_bypassed() -> Property:
    """Builds P2: a restricted merchant allowlist always denies an unlisted merchant."""
    v: ScopeVars = fresh_scope_vars("p2")
    premise = z3.And(
        scope_bounds(v),
        v.has_merchant_restriction,
        z3.Not(z3.IsMember(v.merchant_id, v.allowed_merchant_ids)),
    )
    formula = z3.Implies(premise, z3.Not(in_scope(v)))
    return Property(
        name="merchant_allowlist_cannot_be_bypassed",
        layer="Layer 2 (scope enforcement)",
        description=(
            "When a mandate restricts to specific merchants, a transaction with an unlisted "
            "merchant always denies scope, regardless of every other field being otherwise fully "
            "compliant."
        ),
        formula=formula,
    )


def _p3_expired_mandate_never_verifies() -> Property:
    """Builds P3: a mandate past its own expiry never verifies."""
    v: VerificationVars = fresh_verification_vars("p3")
    premise = z3.And(verification_bounds(v), v.now > v.expires_at)
    formula = z3.Implies(premise, z3.Not(mandate_verified(v)))
    return Property(
        name="expired_mandate_never_verifies",
        layer="Layer 1 (mandate verification)",
        description=(
            "A mandate presented after its own expires_at never verifies, regardless of signature "
            "validity, key registration, or remaining budget."
        ),
        formula=formula,
    )


def _p4_budget_exhausted_mandate_never_verifies() -> Property:
    """Builds P4: a mandate at or past its usage budget never verifies."""
    v: VerificationVars = fresh_verification_vars("p4")
    premise = z3.And(verification_bounds(v), v.usage_count >= v.max_transaction_count)
    formula = z3.Implies(premise, z3.Not(mandate_verified(v)))
    return Property(
        name="budget_exhausted_mandate_never_verifies",
        layer="Layer 1 (mandate verification)",
        description=(
            "A mandate whose usage_count has reached its max_transaction_count never verifies, "
            "regardless of signature validity, key registration, or the time window."
        ),
        formula=formula,
    )


def _p5_delegated_scope_only_attenuates() -> Property:
    """Builds P5: containment's acceptance implies every scope dimension attenuated."""
    v = fresh_containment_vars("p5")
    premise = z3.And(containment_bounds(v), contained(v))
    merchant_id_subset_ok = z3.Or(
        z3.Not(v.parent_has_merchant_restriction),
        z3.And(v.child_has_merchant_restriction, z3.IsSubset(v.child_merchant_ids, v.parent_merchant_ids)),
    )
    conclusion = z3.And(
        v.child_max_amount <= v.parent_max_amount,
        z3.IsSubset(v.child_merchant_categories, v.parent_merchant_categories),
        z3.IsSubset(v.child_item_categories, v.parent_item_categories),
        merchant_id_subset_ok,
        v.parent_valid_from <= v.child_valid_from,
        v.child_valid_until <= v.parent_valid_until,
        v.child_max_transaction_count <= v.parent_max_transaction_count,
    )
    formula = z3.Implies(premise, conclusion)
    return Property(
        name="delegated_scope_only_attenuates",
        layer="Layer 2.5 (delegation-chain containment)",
        description=(
            "Whenever containment accepts a delegated mandate, that mandate's ceiling, category "
            "reach, merchant allowlist, transaction window, and transaction count are each no "
            "broader than its parent's -- authority can only narrow across an accepted delegation, "
            "never widen."
        ),
        formula=formula,
    )


def _p6_no_accepted_chain_exceeds_depth_bound() -> Property:
    """Builds P6: containment's acceptance implies the resolved depth is within bound."""
    v = fresh_containment_vars("p6")
    premise = z3.And(containment_bounds(v), contained(v))
    formula = z3.Implies(premise, v.depth <= MAX_DELEGATION_DEPTH)
    return Property(
        name="no_accepted_chain_exceeds_depth_bound",
        layer="Layer 2.5 (delegation-chain containment)",
        description=(
            f"Whenever containment accepts a delegated mandate, its resolved ancestor chain is no "
            f"more than {MAX_DELEGATION_DEPTH} hops deep -- an accepted chain never exceeds the "
            f"configured depth bound."
        ),
        formula=formula,
    )


def _p7_sibling_committed_total_never_exceeds_parent_cap() -> Property:
    """Builds P7: the sequential sibling-cap ledger never over-commits a parent's cap."""
    v = fresh_sibling_group_vars("p7", FANOUT_SIBLING_COUNT)
    _, final_committed_total = sibling_group_accepted_and_committed(v)
    premise = sibling_group_bounds(v)
    formula = z3.Implies(premise, final_committed_total <= v.parent_max_amount)
    return Property(
        name="sibling_committed_total_never_exceeds_parent_cap",
        layer="Layer 2.5 (delegation-chain containment)",
        description=(
            f"For any group of up to {FANOUT_SIBLING_COUNT} sibling mandates chained from one "
            f"parent and decided in sequence by the real running-ledger algorithm, the sum of every "
            f"accepted sibling's own ceiling never exceeds the parent's cap -- for every possible "
            f"combination of sibling amounts in the bounded space, not just the ones any generated "
            f"corpus happened to produce."
        ),
        formula=formula,
    )


def _p8_no_session_both_allowed_and_flagged_for_hold() -> Property:
    """Builds P8: the combined verdict never marks a session both allowed and held."""
    v: EnsembleVars = fresh_ensemble_vars("p8")
    is_allowed = z3.Not(final_blocked(v))
    is_flagged_for_hold = flagged_for_hold(v)
    formula = z3.Not(z3.And(is_allowed, is_flagged_for_hold))
    return Property(
        name="no_session_both_allowed_and_flagged_for_hold",
        layer="Combination logic (Layers 1, 2, 2.5, and Layer 3's abstracted contribution)",
        description=(
            "No session can be simultaneously auto-approved and flagged for escalation to human "
            "review, for any combination of the deterministic layers' verdicts and any value "
            "Layer 3's own score might take."
        ),
        formula=formula,
    )


def all_properties() -> tuple[Property, ...]:
    """Builds every safety property this milestone proves.

    Returns:
        All eight properties, in the fixed order they are reported.
    """
    return (
        _p1_amount_ceiling_no_tolerance(),
        _p2_merchant_allowlist_cannot_be_bypassed(),
        _p3_expired_mandate_never_verifies(),
        _p4_budget_exhausted_mandate_never_verifies(),
        _p5_delegated_scope_only_attenuates(),
        _p6_no_accepted_chain_exceeds_depth_bound(),
        _p7_sibling_committed_total_never_exceeds_parent_cap(),
        _p8_no_session_both_allowed_and_flagged_for_hold(),
    )
