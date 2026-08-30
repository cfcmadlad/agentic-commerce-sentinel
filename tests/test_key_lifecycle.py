"""Tests for `mandate.verification`'s key revocation and rotation."""

from __future__ import annotations

from datetime import timedelta

from mandate.signing import generate_keypair, key_id_for_public_key, sign_mandate
from mandate.verification import (
    AgentKeyRegistry,
    KeyRevocationReason,
    MandateLedger,
    VerificationFailureReason,
    verify_mandate,
)
from tests.factories import REFERENCE_NOW, build_mandate


def test_valid_pre_revocation_mandate_is_rejected_after_revocation() -> None:
    """A mandate that verified fine before revocation must fail afterward, at the same instant a request arrives."""
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key, agent_id="agent-01")
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    ledger = MandateLedger()

    before = verify_mandate(signed, registry, ledger, now=REFERENCE_NOW)
    assert before.valid

    registry.revoke(
        mandate.agent_id, mandate.signer_key_id, reason=KeyRevocationReason.COMPROMISED, revoked_by="security-team",
        at=REFERENCE_NOW + timedelta(minutes=1),
    )

    after = verify_mandate(signed, registry, ledger, now=REFERENCE_NOW + timedelta(minutes=2))
    assert not after.valid
    assert after.reasons == (VerificationFailureReason.KEY_REVOKED,)


def test_revocation_is_a_kill_switch_regardless_of_other_signals() -> None:
    """A revoked key must hard-fail even when nothing else about the mandate is wrong."""
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key, agent_id="agent-01")
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    registry.revoke(
        mandate.agent_id, mandate.signer_key_id, reason=KeyRevocationReason.COMPROMISED, revoked_by="security-team",
        at=REFERENCE_NOW,
    )

    result = verify_mandate(signed, registry, MandateLedger(), now=REFERENCE_NOW)
    assert not result.valid
    assert result.reasons == (VerificationFailureReason.KEY_REVOKED,)


def test_mandate_signed_during_the_rotation_overlap_window_is_accepted() -> None:
    """Both the old and new keys must verify while a rotation's overlap window is still open."""
    old_key, old_public = generate_keypair()
    new_key, new_public = generate_keypair()
    old_key_id = key_id_for_public_key(old_public)
    new_key_id = key_id_for_public_key(new_public)
    registry = AgentKeyRegistry()
    registry.register("agent-01", old_key_id, old_public)

    overlap_until = REFERENCE_NOW + timedelta(hours=24)
    registry.rotate(
        "agent-01", old_key_id, new_key_id, new_public, overlap_until=overlap_until, rotated_by="ops-team",
        at=REFERENCE_NOW,
    )

    old_mandate = build_mandate(old_key, agent_id="agent-01", signer_key_id=old_key_id)
    old_signed = sign_mandate(old_mandate, old_key)
    new_mandate = build_mandate(new_key, agent_id="agent-01", signer_key_id=new_key_id)
    new_signed = sign_mandate(new_mandate, new_key)

    during_window = REFERENCE_NOW + timedelta(hours=1)
    assert verify_mandate(old_signed, registry, MandateLedger(), now=during_window).valid
    assert verify_mandate(new_signed, registry, MandateLedger(), now=during_window).valid


def test_mandate_signed_by_a_rotated_out_key_after_the_window_closes_is_rejected() -> None:
    """The old key must stop verifying once the overlap window has closed, the new key must keep working."""
    old_key, old_public = generate_keypair()
    new_key, new_public = generate_keypair()
    old_key_id = key_id_for_public_key(old_public)
    new_key_id = key_id_for_public_key(new_public)
    registry = AgentKeyRegistry()
    registry.register("agent-01", old_key_id, old_public)

    overlap_until = REFERENCE_NOW + timedelta(hours=24)
    registry.rotate(
        "agent-01", old_key_id, new_key_id, new_public, overlap_until=overlap_until, rotated_by="ops-team",
        at=REFERENCE_NOW,
    )

    old_mandate = build_mandate(old_key, agent_id="agent-01", signer_key_id=old_key_id)
    old_signed = sign_mandate(old_mandate, old_key)
    new_mandate = build_mandate(new_key, agent_id="agent-01", signer_key_id=new_key_id)
    new_signed = sign_mandate(new_mandate, new_key)

    after_window = overlap_until + timedelta(minutes=1)
    old_result = verify_mandate(old_signed, registry, MandateLedger(), now=after_window)
    assert not old_result.valid
    assert old_result.reasons == (VerificationFailureReason.KEY_REVOKED,)
    assert verify_mandate(new_signed, registry, MandateLedger(), now=after_window).valid


def test_revocation_records_a_structured_reason() -> None:
    """revocation_for must expose the structured reason and who revoked it."""
    registry = AgentKeyRegistry()
    revocation = registry.revoke(
        "agent-01", "key-01", reason=KeyRevocationReason.AGENT_OFFBOARDED, revoked_by="hr-team", at=REFERENCE_NOW
    )
    assert revocation.reason is KeyRevocationReason.AGENT_OFFBOARDED
    assert revocation.revoked_by == "hr-team"
    looked_up = registry.revocation_for("agent-01", "key-01")
    assert looked_up == revocation


def test_re_revoking_replaces_rather_than_stacks() -> None:
    """A second revoke call for the same key must replace the first record, not create a second one."""
    registry = AgentKeyRegistry()
    registry.revoke("agent-01", "key-01", reason=KeyRevocationReason.OTHER, revoked_by="ops", at=REFERENCE_NOW)
    corrected = registry.revoke(
        "agent-01", "key-01", reason=KeyRevocationReason.COMPROMISED, revoked_by="security", at=REFERENCE_NOW
    )
    assert registry.revocation_for("agent-01", "key-01") == corrected
    assert registry.revocation_for("agent-01", "key-01").reason is KeyRevocationReason.COMPROMISED  # type: ignore[union-attr]


def test_revocation_check_cannot_be_evaded_by_a_backdated_now() -> None:
    """`now` drives the mandate's own time window, not revocation -- a stale `now` must not hide a live revocation."""
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key, agent_id="agent-01")
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    revoked_at = REFERENCE_NOW + timedelta(minutes=1)
    registry.revoke(
        mandate.agent_id, mandate.signer_key_id, reason=KeyRevocationReason.COMPROMISED, revoked_by="security-team",
        at=revoked_at,
    )

    # now is still before the revocation (as if a caller backdated the mandate's own time-window
    # check); the real decision instant, passed separately, must still catch the revocation.
    result = verify_mandate(
        signed, registry, MandateLedger(), now=REFERENCE_NOW, revocation_checked_at=revoked_at + timedelta(minutes=1)
    )
    assert not result.valid
    assert result.reasons == (VerificationFailureReason.KEY_REVOKED,)


def test_unrevoked_key_is_never_reported_as_revoked() -> None:
    """A key that was never revoked must report is_revoked False at any instant."""
    registry = AgentKeyRegistry()
    assert not registry.is_revoked("agent-01", "key-01", REFERENCE_NOW)
    assert registry.revocation_for("agent-01", "key-01") is None
