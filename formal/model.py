"""Z3 symbolic encoding of Layers 1, 2, and 2.5's deterministic decision logic.

Every builder function here is a direct, line-for-line transcription of the
real Python decision logic it names in its docstring -- `mandate.verification
.verify_mandate`, `detect.scope.enforce_scope`, `containment.engine.enforce_
containment`, `containment.gate.ContainmentGate`'s sequential sibling
algorithm, and `detect.ensemble.ensemble_decide`'s combination rule. Nothing
here is a new or independent policy; it is the existing policy, restated in a
form Z3 can reason about exhaustively.

Two kinds of abstraction are used, both stated explicitly per field:

- **Free boolean inputs** for facts this encoding does not reason about
  further (a signature's cryptographic validity, whether a key is
  registered, whether Layer 3 flagged a session). A property that holds for
  every possible value of a free input holds regardless of what the real,
  un-encoded check would ever decide.
- **Bounded numeric/finite-set domains** for every comparison this project's
  real logic actually performs (amounts, timestamps, category membership,
  transaction counts, delegation depth). Bounded rather than left as Z3's
  default unbounded integer sort, per this milestone's own scope constraint
  -- see the module-level constants below for the exact bounds and why each
  was chosen.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3  # type: ignore[import-untyped]

from containment.schema import MAX_DELEGATION_DEPTH

# --- Bounds -------------------------------------------------------------
# Every domain below is bounded to a value comfortably beyond anything the
# real system would ever see, so every property is checked exhaustively
# within a space large enough to be meaningful, without inviting the
# unbounded-integer performance cliff the brief for this milestone warns
# against.
AMOUNT_LOWER_BOUND = 1
AMOUNT_UPPER_BOUND = 100_000_000_00  # paise; matches this project's own paisa-quantized amounts
TIME_LOWER_BOUND = 0
TIME_UPPER_BOUND = 10_000_000  # abstract ticks -- only relative order is ever compared, see module docstring
TRANSACTION_COUNT_LOWER_BOUND = 0
TRANSACTION_COUNT_UPPER_BOUND = 1_000
DELEGATION_DEPTH_LOWER_BOUND = 0
DELEGATION_DEPTH_UPPER_BOUND = 10
# Matches generator/attacks/chaining.py::FANOUT_GROUP_SIZE, so the sibling-cap
# property below is checked over a group the same size the real generator
# actually produces, not an arbitrary one.
FANOUT_SIBLING_COUNT = 4

# --- Abstract finite domains ----------------------------------------------
# Merchant/item/merchant-ID membership in the real system is generic
# set-membership logic over whatever catalog generator/config.py defines --
# detect/scope.py and containment/engine.py never special-case a specific
# category name. An abstract finite domain sized to the real catalog is
# therefore a faithful representation, not an approximation: a property
# proved for every subset of an N-element abstract domain holds for every
# subset of any real domain of size N or smaller, because the decision logic
# being verified never inspects which element it received -- only set
# membership and subset relationships.
_MERCHANT_CATEGORY_DOMAIN_SIZE = 5  # matches generator/config.py's five merchant categories
_ITEM_CATEGORY_DOMAIN_SIZE = 6
_MERCHANT_ID_DOMAIN_SIZE = 6

MerchantCategory, MERCHANT_CATEGORIES = z3.EnumSort(
    "MerchantCategory", [f"category_{i}" for i in range(_MERCHANT_CATEGORY_DOMAIN_SIZE)]
)
ItemCategory, ITEM_CATEGORIES = z3.EnumSort(
    "ItemCategory", [f"item_{i}" for i in range(_ITEM_CATEGORY_DOMAIN_SIZE)]
)
MerchantId, MERCHANT_IDS = z3.EnumSort(
    "MerchantId", [f"merchant_{i}" for i in range(_MERCHANT_ID_DOMAIN_SIZE)]
)

MerchantCategorySet = z3.SetSort(MerchantCategory)
ItemCategorySet = z3.SetSort(ItemCategory)
MerchantIdSet = z3.SetSort(MerchantId)


# ==========================================================================
# Layer 1 -- mandate verification (mandate/verification.py::verify_mandate)
# ==========================================================================


@dataclass(frozen=True)
class VerificationVars:
    """Symbolic inputs to Layer 1's decision.

    Attributes:
        has_registered_key: Abstracts "a public key is registered for this
            (agent_id, key_id) pair" -- Layer 1's UNKNOWN_SIGNER check. Free:
            key registration is not a bounded numeric/finite-set fact this
            encoding reasons about further.
        signature_valid: Abstracts "the Ed25519 signature verifies" -- Layer
            1's INVALID_SIGNATURE check. Free for the same reason: Ed25519
            math is not expressible as, nor faithfully approximable by, a
            bounded SMT domain.
        now: The verification instant.
        valid_from: The mandate scope's authorized window start.
        valid_until: The mandate scope's authorized window end.
        expires_at: The mandate's own outright expiry, independent of scope.
        usage_count: Times this mandate has already been redeemed.
        max_transaction_count: The mandate's redemption budget.
    """

    has_registered_key: z3.BoolRef
    signature_valid: z3.BoolRef
    now: z3.ArithRef
    valid_from: z3.ArithRef
    valid_until: z3.ArithRef
    expires_at: z3.ArithRef
    usage_count: z3.ArithRef
    max_transaction_count: z3.ArithRef


def fresh_verification_vars(prefix: str) -> VerificationVars:
    """Creates a fresh, uniquely named set of Layer 1 symbolic inputs.

    Args:
        prefix: Prepended to every variable name, so two properties built in
            the same process never share a Z3 symbol.

    Returns:
        The fresh variable bundle.
    """
    return VerificationVars(
        has_registered_key=z3.Bool(f"{prefix}_has_registered_key"),
        signature_valid=z3.Bool(f"{prefix}_signature_valid"),
        now=z3.Int(f"{prefix}_now"),
        valid_from=z3.Int(f"{prefix}_valid_from"),
        valid_until=z3.Int(f"{prefix}_valid_until"),
        expires_at=z3.Int(f"{prefix}_expires_at"),
        usage_count=z3.Int(f"{prefix}_usage_count"),
        max_transaction_count=z3.Int(f"{prefix}_max_transaction_count"),
    )


def verification_bounds(v: VerificationVars) -> z3.BoolRef:
    """Builds the bounding constraints every Layer 1 property must assume.

    Args:
        v: The variable bundle to bound.

    Returns:
        A conjunction restricting every numeric field to its declared range.
    """
    return z3.And(
        TIME_LOWER_BOUND <= v.now, v.now <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.valid_from, v.valid_from <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.valid_until, v.valid_until <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.expires_at, v.expires_at <= TIME_UPPER_BOUND,
        TRANSACTION_COUNT_LOWER_BOUND <= v.usage_count, v.usage_count <= TRANSACTION_COUNT_UPPER_BOUND,
        TRANSACTION_COUNT_LOWER_BOUND <= v.max_transaction_count,
        v.max_transaction_count <= TRANSACTION_COUNT_UPPER_BOUND,
    )


def mandate_verified(v: VerificationVars) -> z3.BoolRef:
    """Encodes `mandate.verification.verify_mandate`'s pass/fail decision.

    A direct transcription of the real function's four checks, combined with
    AND exactly as `VerificationResult.valid = not reasons` combines them --
    every check must pass; any single failure denies.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff the mandate verifies under every one of Layer 1's checks.
    """
    return z3.And(
        v.has_registered_key,
        v.signature_valid,
        v.now >= v.valid_from,
        v.now <= v.expires_at,
        v.now <= v.valid_until,
        v.usage_count < v.max_transaction_count,
    )


# ==========================================================================
# Layer 2 -- scope enforcement (detect/scope.py::enforce_scope)
# ==========================================================================


@dataclass(frozen=True)
class ScopeVars:
    """Symbolic inputs to Layer 2's decision.

    Attributes:
        mandate_id_match: Abstracts the binding check `trace.mandate_id ==
            mandate.mandate_id` -- a string/UUID equality, faithfully a Bool
            since only `==`/`!=` is ever evaluated on it.
        agent_id_match: Abstracts the agent-binding equality check.
        user_id_match: Abstracts the user-binding equality check.
        amount: The transaction amount.
        max_amount: The mandate scope's ceiling.
        currency_match: Abstracts the currency-code equality check.
        merchant_category: The transaction's merchant category.
        allowed_merchant_categories: The scope's allowed category set.
        item_category: The transaction's item category.
        allowed_item_categories: The scope's allowed item-category set.
        has_merchant_restriction: Whether the scope's `allowed_merchant_ids`
            is set at all (`None` in the real schema means "any merchant
            within the allowed categories", not "unrestricted").
        merchant_id: The transaction's specific merchant.
        allowed_merchant_ids: The scope's merchant allowlist, meaningful
            only when `has_merchant_restriction` is true.
        session_time: The transaction's timestamp.
        valid_from: The scope's authorized window start.
        valid_until: The scope's authorized window end.
    """

    mandate_id_match: z3.BoolRef
    agent_id_match: z3.BoolRef
    user_id_match: z3.BoolRef
    amount: z3.ArithRef
    max_amount: z3.ArithRef
    currency_match: z3.BoolRef
    merchant_category: z3.ExprRef
    allowed_merchant_categories: z3.ExprRef
    item_category: z3.ExprRef
    allowed_item_categories: z3.ExprRef
    has_merchant_restriction: z3.BoolRef
    merchant_id: z3.ExprRef
    allowed_merchant_ids: z3.ExprRef
    session_time: z3.ArithRef
    valid_from: z3.ArithRef
    valid_until: z3.ArithRef


def fresh_scope_vars(prefix: str) -> ScopeVars:
    """Creates a fresh, uniquely named set of Layer 2 symbolic inputs.

    Args:
        prefix: Prepended to every variable name.

    Returns:
        The fresh variable bundle.
    """
    return ScopeVars(
        mandate_id_match=z3.Bool(f"{prefix}_mandate_id_match"),
        agent_id_match=z3.Bool(f"{prefix}_agent_id_match"),
        user_id_match=z3.Bool(f"{prefix}_user_id_match"),
        amount=z3.Int(f"{prefix}_amount"),
        max_amount=z3.Int(f"{prefix}_max_amount"),
        currency_match=z3.Bool(f"{prefix}_currency_match"),
        merchant_category=z3.Const(f"{prefix}_merchant_category", MerchantCategory),
        allowed_merchant_categories=z3.Const(f"{prefix}_allowed_merchant_categories", MerchantCategorySet),
        item_category=z3.Const(f"{prefix}_item_category", ItemCategory),
        allowed_item_categories=z3.Const(f"{prefix}_allowed_item_categories", ItemCategorySet),
        has_merchant_restriction=z3.Bool(f"{prefix}_has_merchant_restriction"),
        merchant_id=z3.Const(f"{prefix}_merchant_id", MerchantId),
        allowed_merchant_ids=z3.Const(f"{prefix}_allowed_merchant_ids", MerchantIdSet),
        session_time=z3.Int(f"{prefix}_session_time"),
        valid_from=z3.Int(f"{prefix}_valid_from"),
        valid_until=z3.Int(f"{prefix}_valid_until"),
    )


def scope_bounds(v: ScopeVars) -> z3.BoolRef:
    """Builds the bounding constraints every Layer 2 property must assume.

    Args:
        v: The variable bundle to bound.

    Returns:
        A conjunction restricting every numeric field to its declared range.
    """
    return z3.And(
        AMOUNT_LOWER_BOUND <= v.amount, v.amount <= AMOUNT_UPPER_BOUND,
        AMOUNT_LOWER_BOUND <= v.max_amount, v.max_amount <= AMOUNT_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.session_time, v.session_time <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.valid_from, v.valid_from <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.valid_until, v.valid_until <= TIME_UPPER_BOUND,
    )


def in_scope(v: ScopeVars) -> z3.BoolRef:
    """Encodes `detect.scope.enforce_scope`'s pass/fail decision.

    A direct transcription of the real function's binding and transaction-
    scope checks, combined with AND exactly as `ScopeResult.in_scope = not
    reasons` combines them.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff the session is in scope under every one of Layer 2's checks.
    """
    merchant_ok = z3.Or(
        z3.Not(v.has_merchant_restriction),
        z3.IsMember(v.merchant_id, v.allowed_merchant_ids),
    )
    return z3.And(
        v.mandate_id_match,
        v.agent_id_match,
        v.user_id_match,
        v.amount <= v.max_amount,
        v.currency_match,
        z3.IsMember(v.merchant_category, v.allowed_merchant_categories),
        z3.IsMember(v.item_category, v.allowed_item_categories),
        merchant_ok,
        v.valid_from <= v.session_time,
        v.session_time <= v.valid_until,
    )


# ==========================================================================
# Layer 2.5 -- delegation-chain containment (containment/engine.py)
# ==========================================================================


@dataclass(frozen=True)
class ContainmentVars:
    """Symbolic inputs to Layer 2.5's decision on one delegated mandate.

    Field names mirror `mandate.schema.MandateScope` and `Mandate`, prefixed
    `child_`/`parent_` for the mandate under evaluation and its immediate
    parent, matching `containment.engine.enforce_containment`'s own
    signature: one mandate checked against one resolved parent.

    Attributes:
        committed_sibling_total: The running total already committed by
            other children of the same parent, exactly as
            `containment.gate.ContainmentGate` tracks it.
        depth, cycle_detected, unresolvable: Abstract the outcome of
            `containment.chain.resolve_ancestor_chain` -- how many ancestor
            hops were walked, and whether that walk hit a cycle or an
            unresolvable link. Free/abstracted rather than modeling the walk
            itself: the walk is graph traversal, not a policy decision; the
            *bound* checked against its result is the policy this milestone
            verifies. See `docs/adr/0005` for this scope boundary stated in
            full.
    """

    child_max_amount: z3.ArithRef
    parent_max_amount: z3.ArithRef
    currency_match: z3.BoolRef
    child_merchant_categories: z3.ExprRef
    parent_merchant_categories: z3.ExprRef
    child_item_categories: z3.ExprRef
    parent_item_categories: z3.ExprRef
    parent_has_merchant_restriction: z3.BoolRef
    child_has_merchant_restriction: z3.BoolRef
    child_merchant_ids: z3.ExprRef
    parent_merchant_ids: z3.ExprRef
    child_valid_from: z3.ArithRef
    child_valid_until: z3.ArithRef
    parent_valid_from: z3.ArithRef
    parent_valid_until: z3.ArithRef
    child_max_transaction_count: z3.ArithRef
    parent_max_transaction_count: z3.ArithRef
    child_expires_at: z3.ArithRef
    parent_expires_at: z3.ArithRef
    committed_sibling_total: z3.ArithRef
    depth: z3.ArithRef
    cycle_detected: z3.BoolRef
    unresolvable: z3.BoolRef


def fresh_containment_vars(prefix: str) -> ContainmentVars:
    """Creates a fresh, uniquely named set of Layer 2.5 symbolic inputs.

    Args:
        prefix: Prepended to every variable name.

    Returns:
        The fresh variable bundle.
    """
    return ContainmentVars(
        child_max_amount=z3.Int(f"{prefix}_child_max_amount"),
        parent_max_amount=z3.Int(f"{prefix}_parent_max_amount"),
        currency_match=z3.Bool(f"{prefix}_currency_match"),
        child_merchant_categories=z3.Const(f"{prefix}_child_merchant_categories", MerchantCategorySet),
        parent_merchant_categories=z3.Const(f"{prefix}_parent_merchant_categories", MerchantCategorySet),
        child_item_categories=z3.Const(f"{prefix}_child_item_categories", ItemCategorySet),
        parent_item_categories=z3.Const(f"{prefix}_parent_item_categories", ItemCategorySet),
        parent_has_merchant_restriction=z3.Bool(f"{prefix}_parent_has_merchant_restriction"),
        child_has_merchant_restriction=z3.Bool(f"{prefix}_child_has_merchant_restriction"),
        child_merchant_ids=z3.Const(f"{prefix}_child_merchant_ids", MerchantIdSet),
        parent_merchant_ids=z3.Const(f"{prefix}_parent_merchant_ids", MerchantIdSet),
        child_valid_from=z3.Int(f"{prefix}_child_valid_from"),
        child_valid_until=z3.Int(f"{prefix}_child_valid_until"),
        parent_valid_from=z3.Int(f"{prefix}_parent_valid_from"),
        parent_valid_until=z3.Int(f"{prefix}_parent_valid_until"),
        child_max_transaction_count=z3.Int(f"{prefix}_child_max_transaction_count"),
        parent_max_transaction_count=z3.Int(f"{prefix}_parent_max_transaction_count"),
        child_expires_at=z3.Int(f"{prefix}_child_expires_at"),
        parent_expires_at=z3.Int(f"{prefix}_parent_expires_at"),
        committed_sibling_total=z3.Int(f"{prefix}_committed_sibling_total"),
        depth=z3.Int(f"{prefix}_depth"),
        cycle_detected=z3.Bool(f"{prefix}_cycle_detected"),
        unresolvable=z3.Bool(f"{prefix}_unresolvable"),
    )


def containment_bounds(v: ContainmentVars) -> z3.BoolRef:
    """Builds the bounding constraints every Layer 2.5 property must assume.

    Args:
        v: The variable bundle to bound.

    Returns:
        A conjunction restricting every numeric field to its declared range.
    """
    return z3.And(
        AMOUNT_LOWER_BOUND <= v.child_max_amount, v.child_max_amount <= AMOUNT_UPPER_BOUND,
        AMOUNT_LOWER_BOUND <= v.parent_max_amount, v.parent_max_amount <= AMOUNT_UPPER_BOUND,
        0 <= v.committed_sibling_total, v.committed_sibling_total <= AMOUNT_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.child_valid_from, v.child_valid_from <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.child_valid_until, v.child_valid_until <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.parent_valid_from, v.parent_valid_from <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.parent_valid_until, v.parent_valid_until <= TIME_UPPER_BOUND,
        TRANSACTION_COUNT_LOWER_BOUND <= v.child_max_transaction_count,
        v.child_max_transaction_count <= TRANSACTION_COUNT_UPPER_BOUND,
        TRANSACTION_COUNT_LOWER_BOUND <= v.parent_max_transaction_count,
        v.parent_max_transaction_count <= TRANSACTION_COUNT_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.child_expires_at, v.child_expires_at <= TIME_UPPER_BOUND,
        TIME_LOWER_BOUND <= v.parent_expires_at, v.parent_expires_at <= TIME_UPPER_BOUND,
        DELEGATION_DEPTH_LOWER_BOUND <= v.depth, v.depth <= DELEGATION_DEPTH_UPPER_BOUND,
    )


def scope_is_subset(v: ContainmentVars) -> z3.BoolRef:
    """Encodes `containment.engine._check_scope_subset`'s eight-field check.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff the child's scope fits inside the parent's on every
        dimension `containment.engine._check_scope_subset` checks.
    """
    merchant_id_subset_ok = z3.Or(
        z3.Not(v.parent_has_merchant_restriction),
        z3.And(
            v.child_has_merchant_restriction,
            z3.IsSubset(v.child_merchant_ids, v.parent_merchant_ids),
        ),
    )
    return z3.And(
        v.child_max_amount <= v.parent_max_amount,
        v.currency_match,
        z3.IsSubset(v.child_merchant_categories, v.parent_merchant_categories),
        z3.IsSubset(v.child_item_categories, v.parent_item_categories),
        merchant_id_subset_ok,
        v.parent_valid_from <= v.child_valid_from,
        v.child_valid_until <= v.parent_valid_until,
        v.child_max_transaction_count <= v.parent_max_transaction_count,
    )


def chain_intact(v: ContainmentVars) -> z3.BoolRef:
    """Encodes the negation of `containment.chain.AncestorChainResolution.broken`.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff the resolved chain is within the depth bound, and neither a
        cycle nor an unresolvable ancestor was encountered.
    """
    return z3.And(
        v.depth <= MAX_DELEGATION_DEPTH,
        z3.Not(v.cycle_detected),
        z3.Not(v.unresolvable),
    )


def contained(v: ContainmentVars) -> z3.BoolRef:
    """Encodes `containment.engine.enforce_containment`'s full pass/fail decision.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff the delegated mandate is accepted by every one of Layer
        2.5's checks: an intact chain, a subset scope, a bounded expiry, and
        a sibling cap that is not exceeded.
    """
    remaining = v.parent_max_amount - v.committed_sibling_total
    sibling_cap_ok = v.child_max_amount <= remaining
    expiry_ok = v.child_expires_at <= v.parent_expires_at
    return z3.And(chain_intact(v), scope_is_subset(v), expiry_ok, sibling_cap_ok)


@dataclass(frozen=True)
class SiblingGroupVars:
    """Symbolic inputs for a fixed-size group of siblings chained from one parent.

    Attributes:
        parent_max_amount: The shared parent's ceiling.
        sibling_amounts: Each sibling's own declared ceiling, in the same
            chronological order `containment.gate.ContainmentGate` would
            decide them in.
    """

    parent_max_amount: z3.ArithRef
    sibling_amounts: tuple[z3.ArithRef, ...]


def fresh_sibling_group_vars(prefix: str, count: int) -> SiblingGroupVars:
    """Creates a fresh, uniquely named sibling-group variable bundle.

    Args:
        prefix: Prepended to every variable name.
        count: Number of siblings in the group. Must be positive.

    Returns:
        The fresh variable bundle.

    Raises:
        ValueError: If `count` is not positive.
    """
    if count <= 0:
        raise ValueError(f"count must be positive, got {count}")
    return SiblingGroupVars(
        parent_max_amount=z3.Int(f"{prefix}_parent_max_amount"),
        sibling_amounts=tuple(z3.Int(f"{prefix}_sibling_{i}_amount") for i in range(count)),
    )


def sibling_group_bounds(v: SiblingGroupVars) -> z3.BoolRef:
    """Builds the bounding constraints the sibling-cap property must assume.

    Args:
        v: The variable bundle to bound.

    Returns:
        A conjunction restricting every amount to its declared range.
    """
    bounds = [AMOUNT_LOWER_BOUND <= v.parent_max_amount, v.parent_max_amount <= AMOUNT_UPPER_BOUND]
    for amount in v.sibling_amounts:
        bounds.extend([AMOUNT_LOWER_BOUND <= amount, amount <= AMOUNT_UPPER_BOUND])
    return z3.And(*bounds)


def sibling_group_accepted_and_committed(
    v: SiblingGroupVars,
) -> tuple[tuple[z3.BoolRef, ...], z3.ArithRef]:
    """Replays `ContainmentGate`'s sequential accept/commit recurrence symbolically.

    Each sibling is measured against the parent's cap minus whatever the
    group's prior siblings already committed -- exactly
    `containment.gate.ContainmentGate.decide`'s own running-ledger logic,
    unrolled for a fixed-size group instead of an open-ended session stream.

    Args:
        v: The symbolic inputs.

    Returns:
        A tuple of (per-sibling acceptance flags, the group's final
        committed total), in the same order as `v.sibling_amounts`.
    """
    accepted: list[z3.BoolRef] = []
    running_total: z3.ArithRef = z3.IntVal(0)
    for amount in v.sibling_amounts:
        remaining = v.parent_max_amount - running_total
        this_accepted = amount <= remaining
        accepted.append(this_accepted)
        running_total = running_total + z3.If(this_accepted, amount, z3.IntVal(0))
    return tuple(accepted), running_total


# ==========================================================================
# Combination logic (detect/ensemble.py::ensemble_decide, extended with
# containment per eval/containment_evaluation.py's composition)
# ==========================================================================


@dataclass(frozen=True)
class EnsembleVars:
    """Symbolic inputs to the combined verdict across all layers.

    Attributes:
        rules_blocked: Abstracts the combined Layer 1 + Layer 2 verdict.
        containment_blocked: Abstracts the Layer 2.5 verdict.
        escalated: Abstracts "Layer 3's score reached the calibrated
            threshold" -- free and entirely unconstrained, since Layer 3's
            decision boundary is a learned model, out of scope for this
            package by design (see the package docstring). A property that
            holds for every value of this variable holds regardless of what
            the real model would ever output.
    """

    rules_blocked: z3.BoolRef
    containment_blocked: z3.BoolRef
    escalated: z3.BoolRef


def fresh_ensemble_vars(prefix: str) -> EnsembleVars:
    """Creates a fresh, uniquely named set of combination-logic inputs.

    Args:
        prefix: Prepended to every variable name.

    Returns:
        The fresh variable bundle.
    """
    return EnsembleVars(
        rules_blocked=z3.Bool(f"{prefix}_rules_blocked"),
        containment_blocked=z3.Bool(f"{prefix}_containment_blocked"),
        escalated=z3.Bool(f"{prefix}_escalated"),
    )


def final_blocked(v: EnsembleVars) -> z3.BoolRef:
    """Encodes the combined block verdict across every deterministic layer plus Layer 3.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff any layer blocked -- the "add, never override" rule
        `detect/ensemble.py` and `eval/containment_evaluation.py` both
        implement.
    """
    return z3.Or(v.rules_blocked, v.containment_blocked, v.escalated)


def flagged_for_hold(v: EnsembleVars) -> z3.BoolRef:
    """Encodes "Layer 3 alone raised a flag" -- `SOURCE_BEHAVIORAL` in `detect/ensemble.py`.

    Args:
        v: The symbolic inputs.

    Returns:
        True iff Layer 3 escalated a session neither deterministic layer
        already blocked.
    """
    return z3.And(v.escalated, z3.Not(v.rules_blocked), z3.Not(v.containment_blocked))
