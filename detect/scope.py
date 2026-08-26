"""Layer 2: deterministic scope enforcement.

Layer 1 answers "is this authorization genuine and still alive". This module
answers the real question: does what the agent is doing fit inside what the
human authorized. A valid, unexpired mandate for two thousand rupees of
groceries does not authorize eight thousand rupees of electronics, and no
signature check will ever say otherwise.

Design constraints, kept for the sake of being auditable and correct:

- Every rule is a pure function of (trace, mandate). No I/O, no clock, no
  global state.
- Every firing rule is collected, not short-circuited on the first. An audit
  record showing "amount over ceiling AND merchant not allowed" is worth
  more than one naming whichever check happened to run first.
- Comparisons are exact — Decimal amounts compared with `>`, no tolerance.
  A tolerance here would be a vulnerability: a band just past the
  authorized limit where spending is silently permitted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from common.schema import SessionTrace
from mandate.schema import SignedMandate

logger = logging.getLogger(__name__)


class ScopeViolationReason(str, Enum):
    """Named scope rules, one per way a session can exceed its authorization."""

    NO_MANDATE_PRESENTED = "no_mandate_presented"
    MANDATE_ID_MISMATCH = "mandate_id_mismatch"
    AGENT_BINDING_MISMATCH = "agent_binding_mismatch"
    USER_BINDING_MISMATCH = "user_binding_mismatch"
    AMOUNT_OVER_CEILING = "amount_over_ceiling"
    CURRENCY_MISMATCH = "currency_mismatch"
    MERCHANT_CATEGORY_NOT_ALLOWED = "merchant_category_not_allowed"
    ITEM_CATEGORY_NOT_ALLOWED = "item_category_not_allowed"
    MERCHANT_NOT_ALLOWED = "merchant_not_allowed"
    OUTSIDE_TIME_WINDOW = "outside_time_window"


@dataclass(frozen=True)
class ScopeResult:
    """Outcome of enforcing a mandate's scope against one session.

    Attributes:
        in_scope: True only if `reasons` is empty.
        reasons: Every scope rule that fired, in declaration order.
    """

    in_scope: bool
    reasons: tuple[ScopeViolationReason, ...]


def _check_binding(trace: SessionTrace, signed: SignedMandate) -> list[ScopeViolationReason]:
    """Checks the presented mandate actually belongs to this session.

    A mandate that is cryptographically perfect but issued to a different
    agent or human is not this session's authorization, and Layer 1 has no
    reason to object to it.

    Args:
        trace: The session under evaluation.
        signed: The mandate presented in that session.

    Returns:
        Any binding rules that fired.
    """
    mandate = signed.mandate
    reasons: list[ScopeViolationReason] = []
    if trace.mandate_id != mandate.mandate_id:
        reasons.append(ScopeViolationReason.MANDATE_ID_MISMATCH)
    if trace.agent_id != mandate.agent_id:
        reasons.append(ScopeViolationReason.AGENT_BINDING_MISMATCH)
    if trace.user_id != mandate.user_id:
        reasons.append(ScopeViolationReason.USER_BINDING_MISMATCH)
    return reasons


def _check_transaction_scope(
    trace: SessionTrace, signed: SignedMandate
) -> list[ScopeViolationReason]:
    """Checks the transaction against the authorized bounds.

    Args:
        trace: The session under evaluation.
        signed: The mandate presented in that session.

    Returns:
        Any transaction-scope rules that fired.
    """
    scope = signed.mandate.scope
    reasons: list[ScopeViolationReason] = []

    if trace.amount > scope.max_amount:
        reasons.append(ScopeViolationReason.AMOUNT_OVER_CEILING)
    if trace.currency != scope.currency:
        reasons.append(ScopeViolationReason.CURRENCY_MISMATCH)
    if trace.merchant_category not in scope.allowed_merchant_categories:
        reasons.append(ScopeViolationReason.MERCHANT_CATEGORY_NOT_ALLOWED)
    if trace.item_category not in scope.allowed_item_categories:
        reasons.append(ScopeViolationReason.ITEM_CATEGORY_NOT_ALLOWED)
    if scope.allowed_merchant_ids is not None and trace.merchant_id not in scope.allowed_merchant_ids:
        # None means "any merchant inside the allowed categories", not
        # unrestricted — the category rule above already constrains it.
        reasons.append(ScopeViolationReason.MERCHANT_NOT_ALLOWED)
    if not scope.valid_from <= trace.started_at <= scope.valid_until:
        reasons.append(ScopeViolationReason.OUTSIDE_TIME_WINDOW)
    return reasons


def enforce_scope(trace: SessionTrace, signed: SignedMandate | None) -> ScopeResult:
    """Enforces a presented mandate's scope against a session.

    Args:
        trace: The session under evaluation.
        signed: The mandate presented in that session, or None if the
            session presented no resolvable mandate.

    Returns:
        A `ScopeResult` listing every rule that fired. A session presenting
        no mandate is a scope failure, not an error: an agent-initiated
        payment with no authorization attached is exactly what this layer
        exists to stop.
    """
    if signed is None:
        logger.info("session %s presented no mandate", trace.session_id)
        return ScopeResult(in_scope=False, reasons=(ScopeViolationReason.NO_MANDATE_PRESENTED,))

    reasons = _check_binding(trace, signed) + _check_transaction_scope(trace, signed)
    if reasons:
        logger.info("session %s out of scope: %s", trace.session_id, reasons)
    return ScopeResult(in_scope=not reasons, reasons=tuple(reasons))