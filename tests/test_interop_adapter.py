"""Tests for `interop.adapter`: translating between AP2 and this project's mandate schema."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from interop.adapter import DEFAULT_MAX_TRANSACTION_COUNT, ap2_to_mandate, mandate_to_ap2
from interop.ap2_types import (
    CartContents,
    CartMandate,
    IntentMandate,
    PaymentCurrencyAmount,
    PaymentDetailsInit,
    PaymentItem,
    PaymentRequest,
)
from tests.factories import build_mandate, build_scope

_VALID_FROM = datetime(2026, 8, 30, 0, 0, 0, tzinfo=UTC)


def _real_ap2_intent(**overrides: object) -> IntentMandate:
    """Builds a real, valid `IntentMandate`, overridable per test.

    Args:
        **overrides: Field values to override the defaults with.

    Returns:
        A valid `IntentMandate`.
    """
    defaults: dict[str, object] = {
        "user_cart_confirmation_required": True,
        "natural_language_description": "a pair of running shoes, size 10, under 15000 INR",
        "merchants": ("amazon_in", "flipkart"),
        "skus": None,
        "requires_refundability": None,
        "intent_expiry": "2026-09-30T00:00:00+00:00",
    }
    defaults.update(overrides)
    return IntentMandate(**defaults)  # type: ignore[arg-type]


def _real_ap2_cart(**overrides: object) -> CartMandate:
    """Builds a real, valid `CartMandate`, overridable per test.

    Args:
        **overrides: Field values to override `CartContents` with.

    Returns:
        A valid `CartMandate`.
    """
    defaults: dict[str, object] = {
        "id": "cart-001",
        "payment_request": PaymentRequest(
            details=PaymentDetailsInit(
                id="details-001",
                total=PaymentItem(label="running shoes", amount=PaymentCurrencyAmount(currency="INR", value=2999.0)),
            )
        ),
        "cart_expiry": "2026-09-15T00:00:00+00:00",
        "merchant_name": "amazon_in",
    }
    defaults.update(overrides)
    return CartMandate(contents=CartContents(**defaults), merchant_authorization="fake-vc-signature")  # type: ignore[arg-type]


def test_amount_and_currency_come_from_the_cart_not_the_intent() -> None:
    """The translated ceiling must come from the cart's real total, AP2's only source for one."""
    mandate = ap2_to_mandate(
        _real_ap2_intent(),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert mandate.scope.max_amount == Decimal("2999.0")
    assert mandate.scope.currency == "INR"


def test_expiry_is_the_earlier_of_intent_and_cart_expiry() -> None:
    """valid_until must be the tighter of AP2's two independent expiries."""
    mandate = ap2_to_mandate(
        _real_ap2_intent(intent_expiry="2026-12-01T00:00:00+00:00"),
        _real_ap2_cart(cart_expiry="2026-09-15T00:00:00+00:00"),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert mandate.scope.valid_until == datetime(2026, 9, 15, tzinfo=UTC)
    assert mandate.expires_at == datetime(2026, 9, 15, tzinfo=UTC)


def test_merchant_ids_come_from_intent_merchants() -> None:
    """AP2's merchants list, not a category, becomes the allowlist."""
    mandate = ap2_to_mandate(
        _real_ap2_intent(merchants=("amazon_in",)),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert mandate.scope.allowed_merchant_ids == frozenset({"amazon_in"})


def test_no_merchant_restriction_when_intent_has_none() -> None:
    """AP2's None merchants list must translate to no restriction, not an empty (invalid) set."""
    mandate = ap2_to_mandate(
        _real_ap2_intent(merchants=None),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert mandate.scope.allowed_merchant_ids is None


def test_max_transaction_count_defaults_to_one() -> None:
    """AP2 is single-transaction by construction; the default must reflect exactly that."""
    mandate = ap2_to_mandate(
        _real_ap2_intent(),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert mandate.scope.max_transaction_count == DEFAULT_MAX_TRANSACTION_COUNT == 1


def test_same_cart_translates_to_the_same_mandate_id() -> None:
    """Deterministic mandate_id derivation: the same AP2 cart must always map to the same ID."""
    first = ap2_to_mandate(
        _real_ap2_intent(),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    second = ap2_to_mandate(
        _real_ap2_intent(),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id="ed25519:test",
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    assert first.mandate_id == second.mandate_id


def test_translated_mandate_can_be_signed_and_verified_with_this_projects_own_scheme() -> None:
    """The adapter's output must be a real, valid, signable `Mandate` -- not merely structurally similar."""
    from mandate.signing import generate_keypair, key_id_for_public_key, sign_mandate, signature_is_valid

    private_key, public_key = generate_keypair()
    mandate = ap2_to_mandate(
        _real_ap2_intent(),
        _real_ap2_cart(),
        agent_id="agent-1",
        user_id="user-1",
        signer_key_id=key_id_for_public_key(public_key),
        merchant_category="fashion_apparel",
        item_category="footwear",
        valid_from=_VALID_FROM,
    )
    signed = sign_mandate(mandate, private_key)
    assert signature_is_valid(signed, public_key)


def test_mandate_to_ap2_round_trips_the_amount_and_currency() -> None:
    """The genuinely-mappable fields must survive an internal -> AP2 -> internal round trip."""
    private_key = Ed25519PrivateKey.generate()
    original = build_mandate(
        private_key, scope=build_scope(max_amount=Decimal("1500.00"), currency="INR", allowed_merchant_ids=None)
    )

    intent, cart = mandate_to_ap2(original)
    recovered = ap2_to_mandate(
        intent,
        cart,
        agent_id=original.agent_id,
        user_id=original.user_id,
        signer_key_id=original.signer_key_id,
        merchant_category=next(iter(original.scope.allowed_merchant_categories)),
        item_category=next(iter(original.scope.allowed_item_categories)),
        valid_from=original.issued_at,
    )

    assert recovered.scope.max_amount == original.scope.max_amount
    assert recovered.scope.currency == original.scope.currency
    assert recovered.scope.valid_until == original.scope.valid_until


def test_mandate_to_ap2_round_trips_a_single_merchant_restriction() -> None:
    """A single-merchant allowlist must survive the round trip; AP2 has no category to lose here."""
    private_key = Ed25519PrivateKey.generate()
    original = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=frozenset({"bigbasket"})))

    intent, cart = mandate_to_ap2(original)
    assert intent.merchants == ("bigbasket",)

    recovered = ap2_to_mandate(
        intent,
        cart,
        agent_id=original.agent_id,
        user_id=original.user_id,
        signer_key_id=original.signer_key_id,
        merchant_category=next(iter(original.scope.allowed_merchant_categories)),
        item_category=next(iter(original.scope.allowed_item_categories)),
        valid_from=original.issued_at,
    )
    assert recovered.scope.allowed_merchant_ids == original.scope.allowed_merchant_ids


def test_mandate_to_ap2_never_fabricates_a_merchant_authorization() -> None:
    """This project's own signature is never smuggled in as a fake AP2 VC signature."""
    private_key = Ed25519PrivateKey.generate()
    original = build_mandate(private_key)
    _, cart = mandate_to_ap2(original)
    assert cart.merchant_authorization is None
