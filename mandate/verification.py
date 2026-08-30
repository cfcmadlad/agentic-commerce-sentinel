"""Layer 1: cryptographic and lifecycle verification of a presented mandate.

Deliberately narrow in scope. This module answers exactly four questions:
is the signature valid, is the mandate within its time window, is it bound
to a registered key for the claiming agent, and has its transaction budget
been exhausted. It does not decide whether a transaction amount, merchant,
or category is in-scope — that is Layer 2 (`/detect`), and
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
    KEY_REVOKED = "key_revoked"
    INVALID_SIGNATURE = "invalid_signature"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    BUDGET_EXHAUSTED = "budget_exhausted"


class KeyRevocationReason(str, Enum):
    """Structured reason a key was revoked, for audit logging and eval breakdowns."""

    COMPROMISED = "compromised"
    ROTATED = "rotated"
    AGENT_OFFBOARDED = "agent_offboarded"
    OTHER = "other"


@dataclass(frozen=True)
class KeyRevocation:
    """One recorded revocation of a registered key.

    Attributes:
        agent_id: The agent whose key was revoked.
        key_id: The key fingerprint revoked.
        reason: The structured reason.
        revoked_by: Identifier of the human who revoked it -- revocation is
            always a human action (see `AgentKeyRegistry.revoke`'s own
            docstring), never something this project's own code calls
            automatically.
        revoked_at: When the revocation was recorded.
        effective_at: When the revocation actually starts blocking
            verification -- equal to `revoked_at` for an immediate
            revocation, or a future time for a rotation's overlap window
            (see `AgentKeyRegistry.rotate`). `now < effective_at` means the
            key still verifies; `now >= effective_at` means it does not.
    """

    agent_id: str
    key_id: str
    reason: KeyRevocationReason
    revoked_by: str
    revoked_at: datetime
    effective_at: datetime


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

    Revocation and rotation (`revoke`/`rotate`) are never called by
    anything in this codebase automatically -- the only callers anywhere
    are `service/main.py`'s two dedicated endpoints
    (`POST /agents/{id}/keys/{key_id}/revoke`, `POST /agents/{id}/keys
    /rotate`), each requiring an explicit HTTP request and an `actor`
    identifying who made it. That is the literal meaning of "revocation is
    a human action ... never automatic": there is no scheduled job, no
    automatic-suspicion trigger, and no code path from `verify_mandate`
    (or anything it calls) back into either method.
    """

    def __init__(self) -> None:
        """Initializes an empty registry."""
        self._keys: dict[tuple[str, str], Ed25519PublicKey] = {}
        self._revocations: dict[tuple[str, str], KeyRevocation] = {}

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

    def revoke(
        self,
        agent_id: str,
        key_id: str,
        reason: KeyRevocationReason,
        revoked_by: str,
        at: datetime,
        effective_at: datetime | None = None,
    ) -> KeyRevocation:
        """Records a revocation for one (agent_id, key_id) pair.

        Overwrites any prior revocation for the same pair -- a key can only
        be in one revoked state at a time, and re-revoking (e.g. to correct
        a mistaken `effective_at`) replaces it rather than stacking.

        Args:
            agent_id: The agent whose key is being revoked.
            key_id: The key fingerprint being revoked.
            reason: The structured reason.
            revoked_by: Identifier of the human revoking it.
            at: When this revocation was recorded.
            effective_at: When the revocation starts blocking verification.
                Defaults to `at` (immediate). A future time models a
                rotation's overlap window -- see `rotate`.

        Returns:
            The recorded revocation.
        """
        revocation = KeyRevocation(
            agent_id=agent_id,
            key_id=key_id,
            reason=reason,
            revoked_by=revoked_by,
            revoked_at=at,
            effective_at=effective_at if effective_at is not None else at,
        )
        self._revocations[(agent_id, key_id)] = revocation
        logger.info(
            "agent %s key %s revoked by %s (%s), effective %s",
            agent_id,
            key_id,
            revoked_by,
            reason,
            revocation.effective_at,
        )
        return revocation

    def is_revoked(self, agent_id: str, key_id: str, at: datetime) -> bool:
        """Checks whether a key is revoked as of a given instant.

        Args:
            agent_id: The agent identity claimed on the mandate.
            key_id: The key ID claimed on the mandate.
            at: The instant to check against -- the same `now` a caller
                passes to `verify_mandate`, so this stays exactly as
                reproducible as the rest of Layer 1.

        Returns:
            True if a revocation exists for this pair and `at` is at or
            after its `effective_at`. A key with a revocation scheduled
            for a future time (a rotation's overlap window) is not yet
            revoked before that time.
        """
        revocation = self._revocations.get((agent_id, key_id))
        return revocation is not None and at >= revocation.effective_at

    def revocation_for(self, agent_id: str, key_id: str) -> KeyRevocation | None:
        """Looks up the recorded revocation for one (agent_id, key_id) pair, if any.

        Args:
            agent_id: The agent identity to look up.
            key_id: The key ID to look up.

        Returns:
            The revocation, regardless of whether its `effective_at` has
            passed yet, or None if this pair was never revoked.
        """
        return self._revocations.get((agent_id, key_id))

    def rotate(
        self,
        agent_id: str,
        old_key_id: str,
        new_key_id: str,
        new_public_key: Ed25519PublicKey,
        overlap_until: datetime,
        rotated_by: str,
        at: datetime,
    ) -> KeyRevocation:
        """Registers a new key and schedules the old one's revocation at the end of an overlap window.

        The overlap window's own length is a caller decision, not a
        constant this method imposes -- an agent's real operational needs
        (how long its in-flight mandates can take to be re-signed with the
        new key) vary too much for one hard-coded default to fit every
        case. The service endpoint (`POST /agents/{id}/keys/{old_key_id}
        /rotate`) exposes it as `overlap_hours`, defaulting to
        `service.schemas.DEFAULT_KEY_ROTATION_OVERLAP_HOURS` when a caller
        doesn't have a more specific value in mind -- see `docs/adr/
        0014-agent-key-lifecycle.md` for that default's rationale.

        Args:
            agent_id: The agent whose key is being rotated.
            old_key_id: The key fingerprint being rotated out.
            new_key_id: The key fingerprint being rotated in.
            new_public_key: The new key's public key.
            overlap_until: When the old key stops verifying. Both old and
                new keys verify for any `now` before this instant.
            rotated_by: Identifier of the human performing the rotation.
            at: When this rotation was recorded.

        Returns:
            The old key's scheduled revocation.
        """
        self.register(agent_id, new_key_id, new_public_key)
        return self.revoke(
            agent_id,
            old_key_id,
            reason=KeyRevocationReason.ROTATED,
            revoked_by=rotated_by,
            at=at,
            effective_at=overlap_until,
        )


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
    *,
    revocation_checked_at: datetime | None = None,
) -> VerificationResult:
    """Verifies a presented mandate's signature, time window, and budget.

    Args:
        signed: The mandate and its claimed signature.
        registry: Registry of public keys trusted to sign for each agent.
        ledger: Usage ledger to check remaining transaction budget against.
        now: The current time, injected rather than read from the system
            clock so verification is deterministic and testable. Used for
            the mandate's own time-window checks (`valid_from`,
            `expires_at`, `valid_until`), which are properties of the
            mandate and legitimately evaluated as of whatever instant a
            caller means by "now" for that mandate.
        revocation_checked_at: The instant to check key revocation against.
            Defaults to `now` if omitted. Deliberately separate from `now`:
            revocation is a security kill-switch keyed to real decision
            time, not to a value a caller (or an untrusted request field
            such as a session's self-reported start time) could supply to
            evade it by claiming an instant before the key was revoked.

    Returns:
        A `VerificationResult`. See `VerificationFailureReason` for the set
        of reasons a mandate can fail.
    """
    if revocation_checked_at is None:
        revocation_checked_at = now
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

    if registry.is_revoked(mandate.agent_id, mandate.signer_key_id, revocation_checked_at):
        # The kill switch: checked before the signature itself, so a
        # revoked key hard-fails regardless of whether the signature it
        # produced is otherwise perfectly genuine -- revocation means "do
        # not trust anything signed with this key from this instant on,"
        # not "this specific signature looks wrong."
        logger.warning(
            "mandate %s: key revoked for agent=%s key_id=%s",
            mandate.mandate_id,
            mandate.agent_id,
            mandate.signer_key_id,
        )
        return VerificationResult(
            valid=False,
            reasons=(VerificationFailureReason.KEY_REVOKED,),
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