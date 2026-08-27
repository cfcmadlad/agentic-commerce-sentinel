"""Factory helpers for constructing valid test fixtures.

Not a test module itself (no `test_` prefix) so pytest does not collect it.
Centralizing "what does a minimally valid Mandate look like" here means a
schema change only requires updating one place, not every test that builds
a Mandate inline.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.schema import EventType, SessionEvent, SessionTrace
from mandate.schema import Mandate, MandateScope
from mandate.signing import key_id_for_public_key

REFERENCE_NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)


def build_scope(**overrides: object) -> MandateScope:
    """Builds a valid `MandateScope` with sensible defaults, overridable per test.

    Args:
        **overrides: Field values to override the defaults with.

    Returns:
        A valid `MandateScope`.
    """
    defaults: dict[str, object] = {
        "max_amount": Decimal("2000.00"),
        "currency": "INR",
        "allowed_merchant_ids": None,
        "allowed_merchant_categories": frozenset({"grocery"}),
        "allowed_item_categories": frozenset({"packaged_food", "produce"}),
        "valid_from": REFERENCE_NOW - timedelta(days=1),
        "valid_until": REFERENCE_NOW + timedelta(days=6),
        "max_transaction_count": 5,
    }
    defaults.update(overrides)
    return MandateScope(**defaults)  # type: ignore[arg-type]


def build_mandate(
    signer_private_key: Ed25519PrivateKey,
    *,
    scope: MandateScope | None = None,
    **overrides: object,
) -> Mandate:
    """Builds a valid `Mandate` bound to the given signing key.

    Args:
        signer_private_key: The private key whose public fingerprint becomes
            `signer_key_id`. Callers hold the matching private key so the
            returned mandate can immediately be passed to `sign_mandate`.
        scope: The scope to attach. Defaults to `build_scope()`.
        **overrides: Field values to override the defaults with.

    Returns:
        A valid, unsigned `Mandate`.
    """
    key_id = key_id_for_public_key(signer_private_key.public_key())
    defaults: dict[str, object] = {
        "mandate_id": uuid4(),
        "agent_id": "agent-grocery-bot-01",
        "user_id": "user-0001",
        "parent_mandate_id": None,
        "issued_at": REFERENCE_NOW - timedelta(days=1),
        "expires_at": REFERENCE_NOW + timedelta(days=7),
        "nonce": uuid4().hex,
        "scope": scope if scope is not None else build_scope(),
        "signer_key_id": key_id,
    }
    defaults.update(overrides)
    return Mandate(**defaults)  # type: ignore[arg-type]


def build_session_trace(**overrides: object) -> SessionTrace:
    """Builds a minimally valid `SessionTrace` with sensible defaults.

    Args:
        **overrides: Field values to override the defaults with. Passing
            `events` replaces the default single-event lifecycle entirely.

    Returns:
        A valid `SessionTrace`.
    """
    default_event = SessionEvent(event_type=EventType.PAYMENT_RESULT, timestamp=REFERENCE_NOW)
    defaults: dict[str, object] = {
        "session_id": uuid4(),
        "agent_id": "agent-grocery-bot-01",
        "user_id": "user-0001",
        "mandate_id": uuid4(),
        "merchant_id": "bigbasket",
        "merchant_category": "grocery",
        "item_category": "packaged_food",
        "amount": Decimal("450.00"),
        "currency": "INR",
        "events": [default_event],
        "started_at": REFERENCE_NOW,
        "completed_at": REFERENCE_NOW,
    }
    defaults.update(overrides)
    return SessionTrace(**defaults)  # type: ignore[arg-type]


def random_uuid() -> UUID:
    """Returns a fresh random UUID, for tests that just need a placeholder ID.

    Returns:
        A random UUID4.
    """
    return uuid4()