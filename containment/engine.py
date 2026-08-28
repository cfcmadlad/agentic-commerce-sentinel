"""Layer 2.5's rule set: checks a delegated mandate against its resolved parent.

Design constraints, matching Layer 2's own (`detect/scope.py`):

- Every rule is a pure function of (mandate, chain, committed sibling total).
  No I/O, no clock, no global state.
- Every firing rule is collected, not short-circuited on the first. An audit
  record showing "amount exceeds parent AND sibling cap exceeded" is worth
  more than one naming whichever check happened to run first.
- Comparisons are exact -- Decimal amounts and category sets compared
  directly, no tolerance.

This module implements a fixed rule brief -- scope subset, remaining sibling
cap, bounded expiry, bounded delegation depth, no cycles, fail-closed on
schema drift -- decided before this package was ever run against the frozen
held-out corpus. It is not a patch tuned to catch any specific chaining
variant; see `docs/adr/0004-delegation-chain-containment.md` for which
variants it does and does not catch, and why.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from containment.chain import AncestorChainResolution
from containment.schema import ContainmentResult, ContainmentViolationReason, assert_known_scope_fields
from mandate.schema import Mandate, MandateScope

logger = logging.getLogger(__name__)


def _merchant_ids_subset(child: frozenset[str] | None, parent: frozenset[str] | None) -> bool:
    """Checks whether a child's merchant-ID restriction fits inside its parent's.

    Args:
        child: The child mandate's `allowed_merchant_ids`.
        parent: The parent mandate's `allowed_merchant_ids`.

    Returns:
        True if the child cannot reach any merchant the parent didn't already
        allow. `None` means "any merchant within the allowed categories" --
        broader than any explicit set -- so a child of `None` under a parent
        that does restrict merchant IDs is a widening, not a subset, even
        though both are technically "unset or a set."
    """
    if parent is None:
        return True
    if child is None:
        return False
    return child <= parent


def _check_scope_subset(
    child_scope: MandateScope, parent_scope: MandateScope
) -> list[ContainmentViolationReason]:
    """Checks every `MandateScope` field for the parent authorizing the child.

    Args:
        child_scope: The delegated mandate's own scope.
        parent_scope: Its immediate parent's scope.

    Returns:
        Every scope-subset rule that fired. Covers all eight `MandateScope`
        fields explicitly; the caller's `assert_known_scope_fields` call
        guarantees this list cannot silently fall out of sync with the
        schema without failing loudly first.
    """
    reasons: list[ContainmentViolationReason] = []
    if child_scope.max_amount > parent_scope.max_amount:
        reasons.append(ContainmentViolationReason.SCOPE_AMOUNT_EXCEEDS_PARENT)
    if child_scope.currency != parent_scope.currency:
        reasons.append(ContainmentViolationReason.SCOPE_CURRENCY_MISMATCH)
    if not child_scope.allowed_merchant_categories <= parent_scope.allowed_merchant_categories:
        reasons.append(ContainmentViolationReason.SCOPE_MERCHANT_CATEGORY_NOT_SUBSET)
    if not child_scope.allowed_item_categories <= parent_scope.allowed_item_categories:
        reasons.append(ContainmentViolationReason.SCOPE_ITEM_CATEGORY_NOT_SUBSET)
    if not _merchant_ids_subset(child_scope.allowed_merchant_ids, parent_scope.allowed_merchant_ids):
        reasons.append(ContainmentViolationReason.SCOPE_MERCHANT_ID_NOT_SUBSET)
    if not (
        parent_scope.valid_from <= child_scope.valid_from
        and child_scope.valid_until <= parent_scope.valid_until
    ):
        reasons.append(ContainmentViolationReason.SCOPE_WINDOW_NOT_SUBSET)
    if child_scope.max_transaction_count > parent_scope.max_transaction_count:
        reasons.append(ContainmentViolationReason.SCOPE_TRANSACTION_COUNT_EXCEEDS_PARENT)
    return reasons


def enforce_containment(
    mandate: Mandate,
    chain: AncestorChainResolution,
    committed_sibling_total: Decimal,
) -> ContainmentResult:
    """Checks a delegated mandate against its resolved ancestor chain.

    Args:
        mandate: The mandate under evaluation. Must declare a
            `parent_mandate_id` -- a root mandate never reaches this
            function; see `containment.gate.ContainmentGate.decide`.
        chain: The mandate's resolved ancestor chain, from
            `containment.chain.resolve_ancestor_chain`.
        committed_sibling_total: Sum of `max_amount` already committed by
            other children chained from the same immediate parent, from
            `containment.gate.ContainmentGate`'s running ledger. Excludes
            this mandate itself.

    Returns:
        The containment verdict, with every rule that fired.

    Raises:
        ContainmentSchemaDriftError: If `MandateScope` has gained or lost a
            field this engine has no explicit rule for -- fails closed
            rather than silently passing an unchecked authority dimension.
    """
    assert_known_scope_fields()

    if chain.broken:
        reasons: list[ContainmentViolationReason] = []
        if chain.cycle_detected:
            reasons.append(ContainmentViolationReason.CYCLE_DETECTED)
        if chain.depth_exceeded:
            reasons.append(ContainmentViolationReason.DEPTH_EXCEEDED)
        if chain.unresolvable:
            reasons.append(ContainmentViolationReason.UNRESOLVABLE_ANCESTOR)
        logger.info(
            "mandate %s: containment fails closed on a broken chain: %s", mandate.mandate_id, reasons
        )
        return ContainmentResult(mandate_id=mandate.mandate_id, in_bounds=False, reasons=tuple(reasons))

    parent = chain.immediate_parent
    if parent is None:
        # Unreachable: chain.broken is False here, and resolve_ancestor_chain
        # requires mandate.parent_mandate_id to be set, so a non-broken
        # resolution for a mandate that declares a parent always resolves at
        # least one ancestor.
        raise AssertionError(f"mandate {mandate.mandate_id}: resolved chain has no immediate parent")

    reasons = _check_scope_subset(mandate.scope, parent.scope)
    if mandate.expires_at > parent.expires_at:
        reasons.append(ContainmentViolationReason.EXPIRY_EXCEEDS_PARENT)

    remaining = parent.scope.max_amount - committed_sibling_total
    if mandate.scope.max_amount > remaining:
        reasons.append(ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING)

    if reasons:
        logger.info("mandate %s: containment violated: %s", mandate.mandate_id, reasons)
    return ContainmentResult(mandate_id=mandate.mandate_id, in_bounds=not reasons, reasons=tuple(reasons))
