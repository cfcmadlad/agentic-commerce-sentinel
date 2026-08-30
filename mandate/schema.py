"""Mandate schema: the signed authorization an agent presents before payment.

Takes AP2 (google-agentic-commerce/AP2), a public, citable specification,
as its reference point rather than NPCI's Unified Agent Protocol, which as
of this writing has no published technical schema and is still pending RBI
approval. Not a direct implementation of AP2's own `IntentMandate`, though
-- `interop/adapter.py`'s field-by-field mapping (see `docs/adr/
0010-ap2-interop-adapter.md`) found that AP2's real Intent Mandate carries
no spending-limit or category field at all (the price commitment lives in
a separate, merchant-signed Cart Mandate), targets specific merchant/item
IDs rather than categories, is single-transaction by construction, and has
no delegation-chain concept -- none of which this project's own scope
model needs to match, since it was designed independently for a reusable,
category-scoped, multi-agent-delegation authorization AP2 does not
represent. Where UAP's reported design is known -- per-merchant spending
limits, consent-based delegation built on UPI Circle -- this schema
follows that direction anyway. See README §8 and the interop ADR for the
full sourcing; this is a defensible design point, not a claim of
conformance to either spec.

A `Mandate` is the unsigned content. A `SignedMandate` wraps it with the
Ed25519 signature and the key identifier that produced it. Verification
(signature check, expiry, budget) lives in `mandate/verification.py`, kept
separate from this module so the schema stays a pure data definition.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Named constants instead of magic numbers scattered through validators.
MIN_MANDATE_AMOUNT = Decimal("0.01")
CURRENCY_CODE_LENGTH = 3
MIN_TRANSACTION_COUNT = 1


class MandateScope(BaseModel):
    """The bounded authority a mandate grants, enforced by Layer 2.

    Attributes:
        max_amount: Ceiling on the transaction amount this mandate may
            authorize, per use.
        currency: ISO 4217 currency code (e.g. "INR").
        allowed_merchant_ids: Explicit merchant allowlist. None means "any
            merchant within `allowed_merchant_categories`" rather than
            "any merchant whatsoever" — category is always required.
        allowed_merchant_categories: Merchant category codes this mandate
            authorizes spending within. Must be non-empty: a mandate with no
            category restriction is not a scoped mandate.
        allowed_item_categories: Item categories this mandate authorizes.
        valid_from: Start of the authorized transaction time window.
        valid_until: End of the authorized transaction time window. Must not
            exceed the mandate's own `expires_at` (checked at the `Mandate`
            level, since that field lives one level up).
        max_transaction_count: Maximum number of times this mandate may be
            redeemed over its lifetime.
    """

    model_config = ConfigDict(frozen=True)

    max_amount: Decimal = Field(ge=MIN_MANDATE_AMOUNT)
    currency: str = Field(min_length=CURRENCY_CODE_LENGTH, max_length=CURRENCY_CODE_LENGTH)
    allowed_merchant_ids: frozenset[str] | None = None
    allowed_merchant_categories: frozenset[str]
    allowed_item_categories: frozenset[str]
    valid_from: datetime
    valid_until: datetime
    max_transaction_count: int = Field(ge=MIN_TRANSACTION_COUNT)

    @model_validator(mode="after")
    def _check_scope_invariants(self) -> MandateScope:
        """Validates internal consistency of the scope.

        Returns:
            The validated instance, unchanged.

        Raises:
            ValueError: If the time window is inverted or a required
                category set is empty.
        """
        if self.valid_until < self.valid_from:
            raise ValueError("valid_until precedes valid_from")
        if not self.allowed_merchant_categories:
            raise ValueError(
                "allowed_merchant_categories must be non-empty; "
                "an unrestricted mandate is not a scoped mandate"
            )
        if not self.allowed_item_categories:
            raise ValueError("allowed_item_categories must be non-empty")
        return self


class Mandate(BaseModel):
    """The unsigned content of an agent authorization.

    Attributes:
        mandate_id: Globally unique identifier for this mandate.
        schema_version: Schema version string, for forward compatibility as
            the format evolves alongside AP2/UAP.
        agent_id: Identity of the agent this mandate authorizes to act.
        user_id: Identity of the human principal granting authority.
        parent_mandate_id: If this mandate was derived from a broader
            mandate (delegation / chaining), the parent's ID. None for a
            root mandate signed directly by the user. Present from the
            first schema version, even though the chaining detector
            (Section 3, held-out class) isn't built yet, because
            retrofitting this field later would touch every downstream
            consumer of `Mandate`.
        issued_at: UTC time the mandate was signed.
        expires_at: UTC time after which the mandate is void outright,
            independent of `scope.valid_until`.
        nonce: Unique-per-mandate random value, included in the signed
            payload so that two mandates with otherwise identical content
            (same agent, amount, category, timestamps) still produce
            distinct signatures.
        scope: The bounded authority granted, see `MandateScope`.
        signer_key_id: Identifier of the public key expected to have
            produced the signature. Verification looks this up in an
            `AgentKeyRegistry` rather than trusting a key embedded in the
            mandate itself.

    Raises:
        ValueError: If `expires_at` does not strictly follow `issued_at`, or
            if `scope.valid_until` exceeds `expires_at`.
    """

    model_config = ConfigDict(frozen=True)

    mandate_id: UUID
    schema_version: str = "1.0"
    agent_id: str
    user_id: str
    parent_mandate_id: UUID | None = None
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=16)
    scope: MandateScope
    signer_key_id: str

    @model_validator(mode="after")
    def _check_mandate_invariants(self) -> Mandate:
        """Validates cross-field consistency between the mandate and its scope.

        Returns:
            The validated instance, unchanged.

        Raises:
            ValueError: If timestamps are inconsistent.
        """
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly after issued_at")
        if self.scope.valid_until > self.expires_at:
            raise ValueError(
                "scope.valid_until cannot exceed the mandate's own expires_at"
            )
        return self


class SignedMandate(BaseModel):
    """A mandate plus the Ed25519 signature over its canonical encoding.

    Attributes:
        mandate: The signed content.
        signature: Base64-encoded Ed25519 signature (produced by
            `mandate.signing.sign_mandate`, verified by
            `mandate.verification.verify_mandate`). Stored as base64 text
            rather than raw bytes so `SignedMandate` round-trips cleanly
            through JSON without a custom encoder.
    """

    model_config = ConfigDict(frozen=True)

    mandate: Mandate
    signature: str