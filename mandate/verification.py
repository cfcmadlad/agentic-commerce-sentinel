"""Layer 1: cryptographic and lifecycle verification of a presented mandate.

Deliberately narrow in scope. This module answers exactly four questions:
is the signature valid, is the mandate within its time window, is it bound
to a registered key for the claiming agent, and has its transaction budget
been exhausted. It does not decide whether a transaction amount, merchant,
or category is in-scope — that is Layer 2 (`/detect`), built on Day 3, and
it consumes a passing `VerificationResult` from this module as a
precondition rather than duplicating these checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mandate.schema import SignedMandate
from mandate.signing import signature_is_valid

logger = logging.getLogger(__name__)


class VerificationFailureReason(str, Enum):
    """Why a mandate failed verification, for audit logging and eval breakdowns."""

    UNKNOWN_SIGNER = "unknown_signer"
    INVALID_SIGNATURE = "invalid_signature"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying one presented mandate.

    Attributes:
        valid: True only if `reasons` is empty.
        reasons: All failure reasons detected. Empty when `valid` is True.
            Deliberately not fail-fast on non-signature checks: an audit
            record showing "expired AND budget exhausted" is more useful to
            the reasoning layer (Section 2) than only the first reason
            found, and to a panel question about why a given attack was
            caught.
        mandate_id: The mandate's ID, if the mandate could be identified at
            all. None only in the pathological case of a signature check
            that could not even resolve a signer.
    """

    valid: bool
    reasons: tuple[VerificationFailureReason, ...]
    mandate_id: UUID | None


class AgentKeyRegistry:
    """Maps (agent_id, key_id) to the public key expected to sign for them.

    An in-memory registry is sufficient for the synthetic eval harness this
    project builds. A production deployment would back this with the
    result of NPCI/UAP agent registration (or, absent that, AP2's
    Credential Provider role) rather than a local dict; the interface here
    is written narrow enough that swapping the backing store later does not
    require changing any caller.
    """

    def __init__(self) -> None:
        """Initializes an empty registry."""
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}

    def register(self, agent_id: str, key_id: str, public_key: Ed25519PublicKey) -> None:
        """Registers a public key as valid for a given agent and key ID.

        Args:
            agent_id: The agent identity this key is bound to.
            key_id: The key fingerprint (see
                `mandate.signing.key_id_for_public_key`).
            public_key: The public key itself.
        """
        self._keys[(agent_id, key_id)] = public_key

    def get(self, agent_id: str, key_id: str) -> Ed25519PublicKey | None:
        """Looks up a registered public key.

        Args:
            agent_id: The agent identity claimed on the mandate.
            key_id: The key ID claimed on the mandate.

        Returns:
            The registered public key, or None if no such (agent_id, key_id)
            pair was registered. Returning None rather than raising: an
            unregistered signer is an expected, common verification
            failure (attack class 3, agent impersonation), not a bug.
        """
        return self._keys.get((agent_id, key_id))


@dataclass
class MandateLedger:
    """Tracks per-mandate usage so a spent budget cannot be re-verified as fresh.

    In-memory only. A production ledger backing real money movement would
    need atomic, durable increments to close the race-condition window
    between check and use; that hardening is out of scope for an offline
    eval harness scoring synthetic sessions one at a time, and is called out
    explicitly here rather than silently assumed away.

    Attributes:
        _usage_counts: Number of times each mandate_id has been recorded as
            used.
    """

    _usage_counts: dict[UUID, int] = field(default_factory=dict)

    def usage_count(self, mandate_id: UUID) -> int:
        """Returns how many times a mandate has been recorded as used.

        Args:
            mandate_id: The mandate to look up.

        Returns:
            The usage count, 0 if never used.
        """
        return self._usage_counts.get(mandate_id, 0)

    def record_usage(self, mandate_id: UUID) -> None:
        """Records one redemption of a mandate.

        Args:
            mandate_id: The mandate being redeemed.

        Note:
            Verification (`verify_mandate`) is intentionally read-only and
            does not call this. A caller that only wants to display or audit
            a mandate's status must not silently consume its budget; only a
            caller that is actually acting on the transaction should record
            usage, and it must do so explicitly.
        """
        self._usage_counts[mandate_id] = self.usage_count(mandate_id) + 1


def verify_mandate(
    signed: SignedMandate,
    registry: AgentKeyRegistry,
    ledger: MandateLedger,
    now: datetime,
) -> VerificationResult:
    """Verifies a presented mandate's signature, time window, and budget.

    Args:
        signed: The mandate and its claimed signature.
        registry: Registry of public keys trusted to sign for each agent.
        ledger: Usage ledger to check remaining transaction budget against.
        now: The current time, injected rather than read from the system
            clock so verification is deterministic and testable.

    Returns:
        A `VerificationResult`. See `VerificationFailureReason` for the set
        of reasons a mandate can fail.
    """
    mandate = signed.mandate
    public_key = registry.get(mandate.agent_id, mandate.signer_key_id)
    if public_key is None:
        logger.warning(
            "mandate %s: no registered key for agent=%s key_id=%s",
            mandate.mandate_id,
            mandate.agent_id,
            mandate.signer_key_id,
        )
        return VerificationResult(
            valid=False,
            reasons=(VerificationFailureReason.UNKNOWN_SIGNER,),
            mandate_id=mandate.mandate_id,
        )

    if not signature_is_valid(signed, public_key):
        logger.warning("mandate %s: invalid signature", mandate.mandate_id)
        # Short-circuit: once the signature fails, the mandate's content is
        # untrusted, so reporting time-window or budget detail about a
        # potentially forged payload adds noise, not signal.
        return VerificationResult(
            valid=False,
            reasons=(VerificationFailureReason.INVALID_SIGNATURE,),
            mandate_id=mandate.mandate_id,
        )

    reasons: list[VerificationFailureReason] = []
    if now < mandate.scope.valid_from:
        reasons.append(VerificationFailureReason.NOT_YET_VALID)
    if now > mandate.expires_at or now > mandate.scope.valid_until:
        reasons.append(VerificationFailureReason.EXPIRED)
    if ledger.usage_count(mandate.mandate_id) >= mandate.scope.max_transaction_count:
        reasons.append(VerificationFailureReason.BUDGET_EXHAUSTED)

    if reasons:
        logger.info(
            "mandate %s failed verification: %s", mandate.mandate_id, reasons
        )
    return VerificationResult(
        valid=not reasons, reasons=tuple(reasons), mandate_id=mandate.mandate_id
    )