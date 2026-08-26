"""Tests for `detect.scope`: the scope-enforcement rules, one at a time."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from common.schema import EventType, SessionEvent, SessionTrace
from detect.scope import ScopeViolationReason, enforce_scope
from mandate.schema import SignedMandate
from mandate.signing import generate_keypair, sign_mandate
from tests.factories import REFERENCE_NOW, build_mandate, build_scope


@pytest.fixture
def signed_mandate() -> SignedMandate:
    """Builds a grocery-scoped mandate pinned to one merchant.

    Returns:
        The signed mandate every test in this module works against.
    """
    private_key, _ = generate_keypair()
    scope = build_scope(
        max_amount=Decimal("2000.00"),
        allowed_merchant_ids=frozenset({"bigbasket"}),
        allowed_merchant_categories=frozenset({"grocery"}),
        allowed_item_categories=frozenset({"packaged_food", "produce"}),
    )
    return sign_mandate(build_mandate(private_key, scope=scope), private_key)


def _trace(signed: SignedMandate, **overrides: object) -> SessionTrace:
    """Builds a session that is fully in scope for `signed`, before overrides.

    Args:
        signed: The mandate the session presents.
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
            SessionEvent(event_type=EventType.INTENT_CAPTURED, timestamp=REFERENCE_NOW),
            SessionEvent(
                event_type=EventType.PAYMENT_RESULT,
                timestamp=REFERENCE_NOW + timedelta(minutes=1),
            ),
        ],
        "started_at": REFERENCE_NOW,
        "completed_at": REFERENCE_NOW + timedelta(minutes=1),
    }
    defaults.update(overrides)
    return SessionTrace(**defaults)  # type: ignore[arg-type]


def test_in_scope_session_passes(signed_mandate: SignedMandate) -> None:
    """A session inside every scope dimension must produce no reasons."""
    result = enforce_scope(_trace(signed_mandate), signed_mandate)
    assert result.in_scope
    assert result.reasons == ()


def test_missing_mandate_is_a_scope_failure(signed_mandate: SignedMandate) -> None:
    """A session with no resolvable mandate must be reported, not raise."""
    result = enforce_scope(_trace(signed_mandate), None)
    assert result.reasons == (ScopeViolationReason.NO_MANDATE_PRESENTED,)


def test_amount_exactly_at_ceiling_is_allowed(signed_mandate: SignedMandate) -> None:
    """The ceiling is inclusive: spending exactly the authorized limit is authorized."""
    trace = _trace(signed_mandate, amount=signed_mandate.mandate.scope.max_amount)
    assert enforce_scope(trace, signed_mandate).in_scope


def test_amount_one_paisa_over_ceiling_is_blocked(signed_mandate: SignedMandate) -> None:
    """The smallest representable overshoot must fire the amount rule.

    A tolerance here would define a band just past the limit where spending
    is silently permitted, which is a vulnerability, not a convenience.
    """
    over = signed_mandate.mandate.scope.max_amount + Decimal("0.01")
    result = enforce_scope(_trace(signed_mandate, amount=over), signed_mandate)
    assert result.reasons == (ScopeViolationReason.AMOUNT_OVER_CEILING,)


def test_merchant_outside_allowlist_is_blocked(signed_mandate: SignedMandate) -> None:
    """A merchant not on an explicit allowlist must fire the merchant rule."""
    result = enforce_scope(_trace(signed_mandate, merchant_id="blinkit"), signed_mandate)
    assert result.reasons == (ScopeViolationReason.MERCHANT_NOT_ALLOWED,)


def test_null_merchant_allowlist_permits_any_in_category_merchant() -> None:
    """A None allowlist means any merchant inside the allowed categories."""
    private_key, _ = generate_keypair()
    scope = build_scope(allowed_merchant_ids=None)
    signed = sign_mandate(build_mandate(private_key, scope=scope), private_key)
    assert enforce_scope(_trace(signed, merchant_id="zepto"), signed).in_scope


def test_wrong_merchant_category_is_blocked(signed_mandate: SignedMandate) -> None:
    """A grocery mandate does not authorize electronics."""
    result = enforce_scope(_trace(signed_mandate, merchant_category="electronics"), signed_mandate)
    assert ScopeViolationReason.MERCHANT_CATEGORY_NOT_ALLOWED in result.reasons


def test_wrong_item_category_is_blocked(signed_mandate: SignedMandate) -> None:
    """An item outside the authorized item set must fire the item rule."""
    result = enforce_scope(_trace(signed_mandate, item_category="smartphone"), signed_mandate)
    assert result.reasons == (ScopeViolationReason.ITEM_CATEGORY_NOT_ALLOWED,)


def test_currency_mismatch_is_blocked(signed_mandate: SignedMandate) -> None:
    """A ceiling in one currency authorizes nothing in another."""
    result = enforce_scope(_trace(signed_mandate, currency="USD"), signed_mandate)
    assert ScopeViolationReason.CURRENCY_MISMATCH in result.reasons


def test_agent_binding_mismatch_is_blocked(signed_mandate: SignedMandate) -> None:
    """A mandate issued to another agent is not this session's authorization."""
    result = enforce_scope(_trace(signed_mandate, agent_id="agent-999"), signed_mandate)
    assert result.reasons == (ScopeViolationReason.AGENT_BINDING_MISMATCH,)


def test_user_binding_mismatch_is_blocked(signed_mandate: SignedMandate) -> None:
    """A mandate granted by another human is not this session's authorization."""
    result = enforce_scope(_trace(signed_mandate, user_id="user-9999"), signed_mandate)
    assert result.reasons == (ScopeViolationReason.USER_BINDING_MISMATCH,)


def test_mandate_id_mismatch_is_blocked(signed_mandate: SignedMandate) -> None:
    """A session claiming one mandate ID while presenting another must be caught."""
    result = enforce_scope(_trace(signed_mandate, mandate_id=uuid4()), signed_mandate)
    assert result.reasons == (ScopeViolationReason.MANDATE_ID_MISMATCH,)


def test_session_before_window_opens_is_blocked(signed_mandate: SignedMandate) -> None:
    """A session before valid_from is outside the authorized window."""
    early = signed_mandate.mandate.scope.valid_from - timedelta(minutes=1)
    trace = _trace(signed_mandate, started_at=early, completed_at=early)
    assert ScopeViolationReason.OUTSIDE_TIME_WINDOW in enforce_scope(trace, signed_mandate).reasons


def test_session_after_window_closes_is_blocked(signed_mandate: SignedMandate) -> None:
    """A session after valid_until is outside the authorized window."""
    late = signed_mandate.mandate.scope.valid_until + timedelta(minutes=1)
    trace = _trace(signed_mandate, started_at=late, completed_at=late)
    assert ScopeViolationReason.OUTSIDE_TIME_WINDOW in enforce_scope(trace, signed_mandate).reasons


def test_all_violated_rules_are_reported_together(signed_mandate: SignedMandate) -> None:
    """Multiple broken rules must all be reported — no short-circuiting."""
    trace = _trace(
        signed_mandate,
        amount=Decimal("99999.00"),
        merchant_id="croma",
        merchant_category="electronics",
        item_category="laptop",
    )
    reasons = set(enforce_scope(trace, signed_mandate).reasons)
    assert {
        ScopeViolationReason.AMOUNT_OVER_CEILING,
        ScopeViolationReason.MERCHANT_NOT_ALLOWED,
        ScopeViolationReason.MERCHANT_CATEGORY_NOT_ALLOWED,
        ScopeViolationReason.ITEM_CATEGORY_NOT_ALLOWED,
    } <= reasons


def test_enforce_scope_is_pure(signed_mandate: SignedMandate) -> None:
    """Repeated calls with the same inputs must give the same answer."""
    trace = _trace(signed_mandate, amount=Decimal("99999.00"))
    assert enforce_scope(trace, signed_mandate) == enforce_scope(trace, signed_mandate)