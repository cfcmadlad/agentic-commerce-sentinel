"""Translates between AP2's Intent/Cart mandates and this project's `Mandate`/`MandateScope`.

Field-by-field mapping, stated once here and restated as a table in
`docs/adr/0010-ap2-interop-adapter.md`:

| This project's field            | AP2 source                                              |
|----------------------------------|----------------------------------------------------------|
| `scope.max_amount`/`currency`     | `cart.contents.payment_request.details.total.amount`     |
| `scope.allowed_merchant_ids`      | `intent.merchants` (a specific list, not a category)      |
| `scope.valid_until`/`expires_at`  | `min(intent.intent_expiry, cart.contents.cart_expiry)`    |
| `scope.allowed_merchant_categories` | **no AP2 source** -- caller-supplied                    |
| `scope.allowed_item_categories`   | **no AP2 source** -- caller-supplied                     |
| `scope.valid_from`/`issued_at`    | **no AP2 source** -- caller-supplied                     |
| `scope.max_transaction_count`     | **no AP2 source** -- defaults to 1, see below             |
| `agent_id`, `user_id`             | **no AP2 source** -- caller-supplied, see below           |
| `signer_key_id`                   | **no AP2 source** -- caller-supplied, see below            |
| `parent_mandate_id`               | **no AP2 concept at all** -- no delegation chain in AP2   |

`max_transaction_count` defaults to 1 because AP2 is single-transaction by
construction; a caller raising it is deliberately granting standing
authority AP2 itself never granted. `agent_id`/`user_id` have no AP2
source because AP2's real files carry no such identifier -- that binding
lives in the surrounding VC envelope, which `interop/ap2_types.py` does
not model. `signer_key_id` has no AP2 source because AP2 signs via an
external VC scheme this project's Ed25519 verification cannot check --
see below.

**This adapter translates declared content, not cryptographic trust.**
`ap2_to_mandate` returns an *unsigned* `Mandate` -- AP2's
`merchant_authorization`/`user_authorization` are opaque Verifiable
Credential signatures this project's `mandate.signing.signature_is_valid`
cannot check (a different signature scheme entirely, not merely a
different key format), and this module makes no attempt to bridge that
trust boundary. A caller wanting the translated mandate to actually flow
through this project's Layers 1/2 must sign it with this project's own
Ed25519 scheme (`mandate.signing.sign_mandate`) using a key it separately
registers -- the same as any other mandate this project issues. Treat a
translated mandate as informational sync (what did the AP2 side declare)
until that re-signing step happens, never as already-authenticated.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from interop.ap2_types import (
    CartContents,
    CartMandate,
    IntentMandate,
    PaymentCurrencyAmount,
    PaymentDetailsInit,
    PaymentItem,
    PaymentRequest,
)
from mandate.schema import Mandate, MandateScope

# AP2 is single-transaction by construction: one Intent authorizes one Cart
# authorizes one Payment. Translating into this project's reusable-budget
# model defaults to the most literal reading of that -- one authorized use
# -- rather than inventing a multi-use grant AP2 never made.
DEFAULT_MAX_TRANSACTION_COUNT = 1

_AP2_MANDATE_ID_NAMESPACE = uuid5(NAMESPACE_URL, "sentinel.interop.ap2")


def _mandate_id_for_cart(cart_id: str) -> UUID:
    """Derives a stable mandate ID from an AP2 cart ID.

    Deterministic so translating the same AP2 cart twice yields the same
    internal `mandate_id`, matching this project's general preference for
    reproducible derivations over random ones wherever a stable identity
    already exists to derive from.

    Args:
        cart_id: `CartContents.id`.

    Returns:
        A UUID5 derived from the cart ID.
    """
    return uuid5(_AP2_MANDATE_ID_NAMESPACE, cart_id)


def ap2_to_mandate(
    intent: IntentMandate,
    cart: CartMandate,
    *,
    agent_id: str,
    user_id: str,
    signer_key_id: str,
    merchant_category: str,
    item_category: str,
    valid_from: datetime,
    max_transaction_count: int = DEFAULT_MAX_TRANSACTION_COUNT,
    parent_mandate_id: UUID | None = None,
) -> Mandate:
    """Translates an AP2 Intent/Cart pair into an unsigned internal `Mandate`.

    Args:
        intent: The user's AP2 purchase intent.
        cart: The merchant-signed AP2 cart naming the actual total.
        agent_id: The agent this mandate authorizes -- AP2's own files
            carry no such field, see the module docstring.
        user_id: The human principal granting authority -- same caveat.
        signer_key_id: The key ID that will eventually sign the returned
            `Mandate` with this project's own Ed25519 scheme. AP2's own
            signature is not carried into the result at all (see the
            module docstring on why); the returned `Mandate` is unsigned.
        merchant_category: AP2 has no category concept (`intent.merchants`
            is a specific ID list, not a category) -- this project's
            `MandateScope` requires a non-empty category set, so the
            caller must supply what category this transaction should be
            classified under for Layer 2 enforcement.
        item_category: Same caveat as `merchant_category`, for items
            (AP2's closest field, `intent.skus`, is a specific ID list).
        valid_from: Start of the authorized window. AP2 has no equivalent
            field on either `IntentMandate` or `CartContents` -- both only
            state an expiry, never a start.
        max_transaction_count: See `DEFAULT_MAX_TRANSACTION_COUNT`.
        parent_mandate_id: If this translated mandate should itself be a
            delegated child of an existing internal mandate. AP2 has no
            delegation-chain concept to derive this from; it is never
            implied by `intent`/`cart`.

    Returns:
        The translated, unsigned `Mandate`.
    """
    total = cart.contents.payment_request.details.total
    expires_at = min(
        datetime.fromisoformat(intent.intent_expiry), datetime.fromisoformat(cart.contents.cart_expiry)
    )
    scope = MandateScope(
        max_amount=Decimal(str(total.amount.value)),
        currency=total.amount.currency,
        allowed_merchant_ids=frozenset(intent.merchants) if intent.merchants else None,
        allowed_merchant_categories=frozenset({merchant_category}),
        allowed_item_categories=frozenset({item_category}),
        valid_from=valid_from,
        valid_until=expires_at,
        max_transaction_count=max_transaction_count,
    )
    return Mandate(
        mandate_id=_mandate_id_for_cart(cart.contents.id),
        agent_id=agent_id,
        user_id=user_id,
        parent_mandate_id=parent_mandate_id,
        issued_at=valid_from,
        expires_at=expires_at,
        nonce=uuid4().hex,
        scope=scope,
        signer_key_id=signer_key_id,
    )


def mandate_to_ap2(mandate: Mandate) -> tuple[IntentMandate, CartMandate]:
    """Translates an internal `Mandate` into an AP2 Intent/Cart pair.

    Lossy by the same field boundary `ap2_to_mandate` documents, in
    reverse: `agent_id`, `user_id`, `parent_mandate_id`, the item/merchant
    *category* distinction (only the merchant ID list survives), and
    `max_transaction_count` beyond "at least one use was authorized" have
    no AP2 field to land in and are dropped, not approximated.

    Args:
        mandate: The mandate to translate.

    Returns:
        (intent, cart) -- `cart.merchant_authorization` is always None;
        this project's own Ed25519 signature is not a valid AP2 VC
        signature and no attempt is made to fabricate one.
    """
    scope = mandate.scope
    merchants = tuple(sorted(scope.allowed_merchant_ids)) if scope.allowed_merchant_ids else None
    category = next(iter(scope.allowed_merchant_categories))
    item = next(iter(scope.allowed_item_categories))
    description = (
        f"Authorized to spend up to {scope.max_amount} {scope.currency} in the {category!r} category "
        f"(items: {item!r})"
        + (f", restricted to merchants {merchants}" if merchants else ", no merchant restriction")
        + "."
    )
    intent = IntentMandate(
        user_cart_confirmation_required=True,
        natural_language_description=description,
        merchants=merchants,
        skus=None,
        requires_refundability=None,
        intent_expiry=mandate.expires_at.isoformat(),
    )
    merchant_name = merchants[0] if merchants and len(merchants) == 1 else "(any allowed merchant)"
    cart = CartMandate(
        contents=CartContents(
            id=str(mandate.mandate_id),
            payment_request=PaymentRequest(
                details=PaymentDetailsInit(
                    id=str(mandate.mandate_id),
                    total=PaymentItem(
                        label=f"{category} purchase",
                        amount=PaymentCurrencyAmount(currency=scope.currency, value=float(scope.max_amount)),
                    ),
                )
            ),
            cart_expiry=scope.valid_until.isoformat(),
            merchant_name=merchant_name,
        ),
        merchant_authorization=None,
    )
    return intent, cart
