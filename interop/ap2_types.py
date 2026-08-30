"""Minimal, faithful mirrors of AP2's real Pydantic models.

Every class and field name here matches
`google-agentic-commerce/AP2`'s `code/sdk/python/ap2/models/mandate.py` and
`payment_request.py` exactly, verified directly against the live
repository rather than assumed -- this is a subset of AP2's real surface
(only the fields `interop/adapter.py` actually reads or writes), never a
reinterpretation of it. Fields this adapter has no use for are omitted
outright rather than included and ignored, so nothing here silently claims
to round-trip AP2 content it does not touch: shipping options, the contact
picker, payment-method-specific `data` payloads, and refund/pending flags
are all real AP2 fields not reproduced here.

AP2 mandates are transported as signed Verifiable Credentials in the real
protocol; `merchant_authorization`/`user_authorization` below are the
opaque signature strings that scheme produces. This module models AP2's
*content* shape only -- it does not implement VC signing or verification,
and nothing in `interop/adapter.py` treats these strings as anything but
opaque text to carry through unexamined. See that module's own docstring
for why this project's Ed25519 signing scheme cannot verify them, and does
not try to.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class PaymentCurrencyAmount(BaseModel):
    """A monetary amount. Mirrors AP2's `PaymentCurrencyAmount` exactly.

    Attributes:
        currency: ISO 4217 currency code.
        value: The amount, as AP2 declares it -- a float, not a Decimal
            (see `interop/adapter.py` for how this project's Decimal
            amounts are converted at the boundary).
    """

    model_config = ConfigDict(frozen=True)

    currency: str
    value: float


class PaymentItem(BaseModel):
    """An item for purchase and the value asked for it. Mirrors AP2's `PaymentItem`.

    Attributes:
        label: Human-readable description of the item.
        amount: The item's price.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    amount: PaymentCurrencyAmount


class PaymentDetailsInit(BaseModel):
    """The details of the payment being requested. A subset of AP2's `PaymentDetailsInit`.

    Attributes:
        id: Identifier for this payment details object.
        total: The total amount due -- this is where AP2 actually carries
            an amount ceiling, not on `IntentMandate` (see the module and
            ADR for why).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    total: PaymentItem


class PaymentRequest(BaseModel):
    """A request for payment. A subset of AP2's `PaymentRequest`.

    Attributes:
        details: The payment details, including the total.
    """

    model_config = ConfigDict(frozen=True)

    details: PaymentDetailsInit


class IntentMandate(BaseModel):
    """The user's purchase intent. Mirrors AP2's real `IntentMandate` exactly.

    Attributes:
        user_cart_confirmation_required: Whether the user must confirm the
            assembled cart before payment.
        natural_language_description: Free-text description of the
            intended purchase (e.g. "a pair of running shoes, size 10,
            under $150"). AP2 has no structured category field anywhere on
            this type; this is the closest AP2 equivalent, and it is
            unstructured text, not a category this project's Layer 2 could
            enforce against directly.
        merchants: Specific merchant identifiers this intent authorizes, or
            None for no merchant restriction. Note: a specific merchant
            list, not a merchant *category* -- AP2 has no category concept.
        skus: Specific SKUs this intent authorizes, or None for no SKU
            restriction. Same caveat as `merchants`: specific items, not
            an item category.
        requires_refundability: Whether the purchased item(s) must be
            refundable.
        intent_expiry: ISO 8601 timestamp after which this intent is void.
    """

    model_config = ConfigDict(frozen=True)

    user_cart_confirmation_required: bool
    natural_language_description: str
    merchants: tuple[str, ...] | None = None
    skus: tuple[str, ...] | None = None
    requires_refundability: bool | None = None
    intent_expiry: str


class CartContents(BaseModel):
    """The detailed contents of a cart. Mirrors AP2's real `CartContents` exactly.

    Attributes:
        id: Identifier for this cart.
        payment_request: The payment request, including the total amount
            -- this is where an AP2-derived mandate's actual ceiling comes
            from, not from the `IntentMandate` above it.
        cart_expiry: ISO 8601 timestamp after which this cart is void.
        merchant_name: The merchant's display name.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    payment_request: PaymentRequest
    cart_expiry: str
    merchant_name: str


class CartMandate(BaseModel):
    """A cart whose contents have been signed by the merchant. Mirrors AP2's real `CartMandate`.

    Attributes:
        contents: The signed cart contents.
        merchant_authorization: The merchant's opaque VC signature over
            `contents`, or None. Carried through unexamined -- see the
            module docstring.
    """

    model_config = ConfigDict(frozen=True)

    contents: CartContents
    merchant_authorization: str | None = None
