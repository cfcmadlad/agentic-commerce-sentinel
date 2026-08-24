"""Ed25519 signing over a deterministic canonical encoding of a Mandate.

Signature correctness depends entirely on both sides (signer and verifier)
computing byte-for-byte identical input. Pydantic's default JSON export is
not safe for this: field order, float/Decimal handling, and datetime
formatting are not contractually stable across versions. `canonical_bytes`
below is the single source of truth for what gets signed, deliberately
independent of any model's default serialization.
"""

from __future__ import annotations

import base64
import hashlib
import json
from decimal import Decimal
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mandate.schema import Mandate, SignedMandate

# Fingerprint prefix length balances collision resistance against audit-log
# readability. 16 hex chars = 64 bits, ample for a synthetic eval's key
# population; production would use the full 256-bit digest.
KEY_ID_FINGERPRINT_LENGTH = 16


def _json_default(value: Any) -> str:  # noqa: ANN401
    """Serializes types `json.dumps` does not natively support.

    Args:
        value: The value being serialized. Typed `Any` because this
            function is invoked as `json.dumps`'s `default` callback, whose
            signature is fixed by the standard library and cannot be
            narrowed without breaking that contract.

    Returns:
        A canonical string representation.

    Raises:
        TypeError: If `value` is of a type this function does not handle,
            re-raised implicitly by `json.dumps` calling this as a fallback.
    """
    if isinstance(value, Decimal):
        # Fixed string form, never float: float would silently perturb the
        # signed bytes on round-trip through some other language's JSON
        # parser and break cross-implementation signature verification.
        return format(value, "f")
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"no canonical encoding for type {type(value)!r}")


def canonical_bytes(mandate: Mandate) -> bytes:
    """Produces the exact byte sequence that gets signed for a mandate.

    Args:
        mandate: The mandate content to encode.

    Returns:
        UTF-8 encoded, sorted-key, separator-compact JSON bytes. Datetimes
        are serialized via `mandate.model_dump(mode="json")`, which Pydantic
        guarantees renders as RFC 3339 with an explicit offset, so they are
        left to that path rather than handled in `_json_default`.
    """
    payload = mandate.model_dump(mode="json")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=_json_default
    )
    return canonical.encode("utf-8")


def key_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    """Derives a stable, deterministic identifier for a public key.

    Args:
        public_key: The Ed25519 public key to fingerprint.

    Returns:
        A `"ed25519:"`-prefixed hex fingerprint, suitable for use as
        `Mandate.signer_key_id` and for audit-log display.
    """
    raw = public_key.public_bytes_raw()
    digest = hashlib.sha256(raw).hexdigest()[:KEY_ID_FINGERPRINT_LENGTH]
    return f"ed25519:{digest}"


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generates a fresh Ed25519 keypair using OS entropy.

    Returns:
        A `(private_key, public_key)` pair. Callers are responsible for
        persisting the private key securely; this module never writes key
        material to disk. Not reproducible across calls by design — for
        deterministic key derivation (synthetic data generation, tests
        needing a fixed keypair), use `keypair_from_seed_bytes` instead.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def keypair_from_seed_bytes(seed_bytes: bytes) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Deterministically derives an Ed25519 keypair from 32 bytes of seed material.

    Args:
        seed_bytes: Exactly 32 bytes.

    Returns:
        The derived `(private_key, public_key)` pair. The same input always
        produces the same output, unlike `generate_keypair`. Intended for
        reproducible synthetic data generation (see
        `generator/legitimate.py`), where every random draw must trace back
        to a single seed. Do not use this for real signing keys: seed bytes
        for that purpose must come from a CSPRNG, not a seeded PRNG whose
        seed is checked into a public repo.

    Raises:
        ValueError: If `seed_bytes` is not exactly 32 bytes.
    """
    if len(seed_bytes) != 32:
        raise ValueError(f"seed_bytes must be exactly 32 bytes, got {len(seed_bytes)}")
    private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    return private_key, private_key.public_key()


def sign_mandate(mandate: Mandate, private_key: Ed25519PrivateKey) -> SignedMandate:
    """Signs a mandate's canonical encoding with the given private key.

    Args:
        mandate: The mandate to sign.
        private_key: The Ed25519 private key to sign with. Its public key's
            fingerprint must match `mandate.signer_key_id`.

    Returns:
        The mandate wrapped with a base64-encoded signature.

    Raises:
        ValueError: If `mandate.signer_key_id` does not match the
            fingerprint of `private_key`'s public key. Signing with a key
            that does not match the mandate's declared signer would produce
            a mandate that fails verification for every legitimate
            verifier, so this is caught at sign time rather than left to be
            discovered downstream.
    """
    actual_key_id = key_id_for_public_key(private_key.public_key())
    if actual_key_id != mandate.signer_key_id:
        raise ValueError(
            f"private key fingerprint {actual_key_id!r} does not match "
            f"mandate.signer_key_id {mandate.signer_key_id!r}"
        )
    signature_bytes = private_key.sign(canonical_bytes(mandate))
    return SignedMandate(
        mandate=mandate,
        signature=base64.b64encode(signature_bytes).decode("ascii"),
    )


def signature_is_valid(signed: SignedMandate, public_key: Ed25519PublicKey) -> bool:
    """Checks a mandate's signature against a candidate public key.

    Args:
        signed: The mandate and its claimed signature.
        public_key: The public key to verify against. Callers obtain this
            from an `AgentKeyRegistry` keyed by `signed.mandate.signer_key_id`
            rather than trusting any key carried inside the payload itself.

    Returns:
        True if the signature is valid over the mandate's canonical
        encoding, False otherwise. Never raises for a bad signature; a
        malformed or forged signature is an expected input this function
        must classify, not an exceptional condition.
    """
    try:
        public_key.verify(
            base64.b64decode(signed.signature), canonical_bytes(signed.mandate)
        )
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        # Malformed base64 or wrong-length signature bytes: still just an
        # invalid signature from the caller's point of view.
        return False
    return True


__all__ = [
    "canonical_bytes",
    "generate_keypair",
    "key_id_for_public_key",
    "keypair_from_seed_bytes",
    "sign_mandate",
    "signature_is_valid",
]