"""Tests for `mandate.signing`: canonicalization, signing, and signature checks."""

from __future__ import annotations

import base64
import json
from decimal import Decimal

import pytest

from mandate.signing import (
    canonical_bytes,
    generate_keypair,
    key_id_for_public_key,
    sign_mandate,
    signature_is_valid,
)
from tests.factories import build_mandate, build_scope


def test_canonical_bytes_is_deterministic() -> None:
    """Encoding the same mandate twice must yield byte-identical output."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    assert canonical_bytes(mandate) == canonical_bytes(mandate)


def test_canonical_bytes_differs_on_content_change() -> None:
    """Two mandates differing only in amount must canonicalize differently."""
    private_key, _ = generate_keypair()
    mandate_a = build_mandate(private_key, scope=build_scope(max_amount=Decimal("100.00")))
    mandate_b = build_mandate(private_key, scope=build_scope(max_amount=Decimal("999.00")))
    assert canonical_bytes(mandate_a) != canonical_bytes(mandate_b)


def test_canonical_bytes_orders_category_sets_independently_of_hash_seed() -> None:
    """Category-set fields must canonicalize in sorted order, not set-iteration order.

    `frozenset` iteration order depends on Python's per-process hash
    randomization (`PYTHONHASHSEED`), not on the set's contents. A mandate
    signed in one process and verified in a different one -- the ordinary
    case, since a client signs and a separate server verifies -- would
    otherwise canonicalize to different bytes for the exact same logical
    content purely because the two processes drew different hash seeds,
    causing a perfectly legitimate signature to fail verification for a
    reason that has nothing to do with the mandate's actual content.
    Sorting removes the dependency on iteration order entirely; asserting
    the exact sorted order (rather than just equality across two calls in
    this same process, which `test_canonical_bytes_is_deterministic`
    already covers and which a hash-seed bug would not fail either) is
    what actually pins the fix down.
    """
    private_key, _ = generate_keypair()
    mandate = build_mandate(
        private_key,
        scope=build_scope(
            allowed_merchant_ids=frozenset({"merchant-c", "merchant-a", "merchant-b"}),
            allowed_merchant_categories=frozenset({"fashion", "electronics", "grocery"}),
            allowed_item_categories=frozenset({"phones", "apparel", "produce", "packaged_food"}),
        ),
    )
    payload = json.loads(canonical_bytes(mandate))
    scope = payload["scope"]
    assert scope["allowed_merchant_ids"] == ["merchant-a", "merchant-b", "merchant-c"]
    assert scope["allowed_merchant_categories"] == ["electronics", "fashion", "grocery"]
    assert scope["allowed_item_categories"] == ["apparel", "packaged_food", "phones", "produce"]


def test_sign_then_verify_round_trips() -> None:
    """A mandate signed with a key must verify against that key's public half."""
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)
    assert signature_is_valid(signed, public_key)


def test_verify_fails_against_wrong_public_key() -> None:
    """A signature must not verify against an unrelated key."""
    private_key, _ = generate_keypair()
    _, other_public_key = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)
    assert not signature_is_valid(signed, other_public_key)


def test_verify_fails_if_signed_bytes_tampered() -> None:
    """Flipping a byte in the signature must be detected, not silently accepted."""
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)

    raw = bytearray(base64.b64decode(signed.signature))
    raw[0] ^= 0xFF
    tampered = signed.model_copy(update={"signature": base64.b64encode(bytes(raw)).decode()})

    assert not signature_is_valid(tampered, public_key)


def test_verify_fails_if_mandate_content_tampered_after_signing() -> None:
    """Changing mandate content after signing must invalidate the signature.

    This is the core property scope-violation attacks would need to defeat:
    an agent cannot take a legitimately signed mandate and alter its amount
    or category without the signature failing.
    """
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)

    inflated_scope = mandate.scope.model_copy(
        update={"max_amount": mandate.scope.max_amount * 100}
    )
    tampered_mandate = mandate.model_copy(update={"scope": inflated_scope})
    tampered_signed = signed.model_copy(update={"mandate": tampered_mandate})

    assert not signature_is_valid(tampered_signed, public_key)


def test_sign_mandate_rejects_key_mismatch() -> None:
    """Signing with a key whose fingerprint does not match signer_key_id must fail loudly."""
    private_key, _ = generate_keypair()
    other_private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)  # signer_key_id bound to `private_key`

    with pytest.raises(ValueError, match="does not match"):
        sign_mandate(mandate, other_private_key)


def test_key_id_is_deterministic_and_key_specific() -> None:
    """The same public key must always fingerprint the same, and differ across keys."""
    private_key, public_key = generate_keypair()
    _, other_public_key = generate_keypair()
    assert key_id_for_public_key(public_key) == key_id_for_public_key(public_key)
    assert key_id_for_public_key(public_key) != key_id_for_public_key(other_public_key)