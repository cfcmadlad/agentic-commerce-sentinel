"""Shared types and constants for Layer 2.5 (delegation-chain containment).

Kept as a pure data-definition module, matching the split already used by
`mandate/schema.py` and `detect/scope.py`: no rule logic lives here, only the
vocabulary the chain resolver (`containment/chain.py`) and rule engine
(`containment/engine.py`) share.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from mandate.schema import MandateScope

# How many delegation hops (mandate -> parent -> grandparent -> ...) a chain
# may have before containment rejects it outright, independent of anything
# else about the chain. A named constant, not a magic number, per this
# project's standing style rule.
MAX_DELEGATION_DEPTH = 3

# The complete set of MandateScope fields this engine has an explicit
# subset/comparison rule for (see `containment/engine.py::_check_scope_subset`).
# Compared against `MandateScope.model_fields` at evaluation time so that a
# future scope field added without a matching containment rule fails loudly
# instead of silently passing as an unchecked authority-widening channel.
_KNOWN_SCOPE_FIELDS: frozenset[str] = frozenset(
    {
        "max_amount",
        "currency",
        "allowed_merchant_ids",
        "allowed_merchant_categories",
        "allowed_item_categories",
        "valid_from",
        "valid_until",
        "max_transaction_count",
    }
)


class ContainmentSchemaDriftError(RuntimeError):
    """Raised when MandateScope has gained or lost a field containment doesn't check.

    This is the literal implementation of "any constraint field the engine
    does not recognise fails closed rather than passing": rather than a
    generic field-by-field walk that silently ignores anything unfamiliar,
    `assert_known_scope_fields` compares the schema's actual field set
    against the fixed set this engine was built to check, and raises the
    moment they diverge.
    """


def assert_known_scope_fields() -> None:
    """Fails loudly if `MandateScope`'s fields have drifted from this engine's known set.

    Raises:
        ContainmentSchemaDriftError: If `MandateScope.model_fields` is not
            exactly `_KNOWN_SCOPE_FIELDS` -- either a new field appeared with
            no containment rule for it, or a checked field was removed.
    """
    actual = frozenset(MandateScope.model_fields)
    if actual != _KNOWN_SCOPE_FIELDS:
        unrecognized = sorted(actual - _KNOWN_SCOPE_FIELDS)
        missing = sorted(_KNOWN_SCOPE_FIELDS - actual)
        raise ContainmentSchemaDriftError(
            f"MandateScope fields have drifted from containment's known set: "
            f"unrecognized={unrecognized} missing={missing}; a scope field cannot "
            f"be trusted to have a containment rule until this engine is updated "
            f"and this check is updated to match"
        )


class ContainmentViolationReason(str, Enum):
    """Named containment rules, one per way a delegated mandate can exceed its parent."""

    SCOPE_AMOUNT_EXCEEDS_PARENT = "scope_amount_exceeds_parent"
    SCOPE_CURRENCY_MISMATCH = "scope_currency_mismatch"
    SCOPE_MERCHANT_CATEGORY_NOT_SUBSET = "scope_merchant_category_not_subset"
    SCOPE_ITEM_CATEGORY_NOT_SUBSET = "scope_item_category_not_subset"
    SCOPE_MERCHANT_ID_NOT_SUBSET = "scope_merchant_id_not_subset"
    SCOPE_WINDOW_NOT_SUBSET = "scope_window_not_subset"
    SCOPE_TRANSACTION_COUNT_EXCEEDS_PARENT = "scope_transaction_count_exceeds_parent"
    EXPIRY_EXCEEDS_PARENT = "expiry_exceeds_parent"
    SIBLING_CAP_EXCEEDS_PARENT_REMAINING = "sibling_cap_exceeds_parent_remaining"
    DEPTH_EXCEEDED = "depth_exceeded"
    CYCLE_DETECTED = "cycle_detected"
    UNRESOLVABLE_ANCESTOR = "unresolvable_ancestor"


@dataclass(frozen=True)
class ContainmentResult:
    """Outcome of enforcing containment on one delegated mandate.

    Attributes:
        mandate_id: The mandate evaluated.
        in_bounds: True only if `reasons` is empty.
        reasons: Every containment rule that fired, in declaration order.
            Deliberately not fail-fast on the first violation, matching
            Layer 2's own `ScopeResult` convention: an audit record showing
            every reason a delegation was rejected is more useful than only
            the first one found.
    """

    mandate_id: UUID
    in_bounds: bool
    reasons: tuple[ContainmentViolationReason, ...]
