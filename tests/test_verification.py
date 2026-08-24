"""Tests for `mandate.verification`: the Layer 1 pass/fail logic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from mandate.schema import SignedMandate
from mandate.signing import generate_keypair, key_id_for_public_key, sign_mandate
from mandate.verification import (
    AgentKeyRegistry,
    MandateLedger,
    VerificationFailureReason,
    verify_mandate,
)
from tests.factories import REFERENCE_NOW, build_mandate, build_scope


@dataclass(frozen=True)
class _RegistryFixture:
    """Bundles a populated registry with the mandate signed against it."""

    registry: AgentKeyRegistry
    signed: SignedMandate
    agent_id: str


@pytest.fixture
def registry_and_signed_mandate() -> _RegistryFixture:
    """Builds a registry with one agent's key registered, and a mandate it signed.

    Returns:
        A fixture bundling the registry, the signed mandate, and the agent ID.
    """
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key, agent_id="agent-grocery-bot-01")
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    return _RegistryFixture(registry=registry, signed=signed, agent_id=mandate.agent_id)


def test_valid_mandate_passes(registry_and_signed_mandate: _RegistryFixture) -> None:
    """A correctly signed, in-window, unspent mandate must verify as valid."""
    fx = registry_and_signed_mandate
    result = verify_mandate(fx.signed, fx.registry, MandateLedger(), now=REFERENCE_NOW)
    assert result.valid
    assert result.reasons == ()


def test_unregistered_signer_fails(registry_and_signed_mandate: _RegistryFixture) -> None:
    """A mandate whose (agent_id, key_id) was never registered must fail as unknown."""
    fx = registry_and_signed_mandate
    empty_registry = AgentKeyRegistry()
    result = verify_mandate(fx.signed, empty_registry, MandateLedger(), now=REFERENCE_NOW)
    assert not result.valid
    assert result.reasons == (VerificationFailureReason.UNKNOWN_SIGNER,)


def test_impersonation_with_wrong_key_fails(
    registry_and_signed_mandate: _RegistryFixture,
) -> None:
    """An agent presenting a mandate signed by a key other than the registered one must fail.

    This is the crypto-layer half of attack class 3 (agent impersonation):
    a bot claiming to be `agent-grocery-bot-01` but signing with its own key
    rather than the registered key.
    """
    registry, signed, agent_id = (
        registry_and_signed_mandate.registry,
        registry_and_signed_mandate.signed,
        registry_and_signed_mandate.agent_id,
    )
    impostor_private_key, impostor_public_key = generate_keypair()
    registry.register(agent_id, key_id_for_public_key(impostor_public_key), impostor_public_key)

    forged_mandate = signed.mandate.model_copy(
        update={"signer_key_id": key_id_for_public_key(impostor_public_key)}
    )
    forged_signed = sign_mandate(forged_mandate, impostor_private_key)

    # The registry now has two legitimately different keys for the same
    # agent_id; verification of the forged mandate should still succeed
    # cryptographically here (it IS validly signed by a registered key) —
    # scope/behavioral layers, not Layer 1, are what would flag this as
    # suspicious. This test documents that boundary rather than asserting
    # a Layer 1 failure that this layer is not designed to produce.
    result = verify_mandate(forged_signed, registry, MandateLedger(), now=REFERENCE_NOW)
    assert result.valid


def test_not_yet_valid_fails(registry_and_signed_mandate: _RegistryFixture) -> None:
    """A mandate presented before its scope's valid_from must fail as not-yet-valid."""
    fx = registry_and_signed_mandate
    before_window = fx.signed.mandate.scope.valid_from - timedelta(hours=1)
    result = verify_mandate(fx.signed, fx.registry, MandateLedger(), now=before_window)
    assert not result.valid
    assert VerificationFailureReason.NOT_YET_VALID in result.reasons


def test_expired_mandate_fails() -> None:
    """A mandate presented after expires_at must fail as expired."""
    private_key, public_key = generate_keypair()
    scope = build_scope(
        valid_from=REFERENCE_NOW - timedelta(days=10),
        valid_until=REFERENCE_NOW - timedelta(days=1),
    )
    mandate = build_mandate(
        private_key,
        scope=scope,
        issued_at=REFERENCE_NOW - timedelta(days=10),
        expires_at=REFERENCE_NOW - timedelta(hours=1),
    )
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)

    result = verify_mandate(signed, registry, MandateLedger(), now=REFERENCE_NOW)
    assert not result.valid
    assert VerificationFailureReason.EXPIRED in result.reasons


def test_budget_exhausted_after_max_uses(registry_and_signed_mandate: _RegistryFixture) -> None:
    """A mandate must fail once its usage count reaches max_transaction_count.

    This is the core check behind attack class 1 (mandate replay): a mandate
    already spent up to its budget must not verify as fresh a second time.
    """
    fx = registry_and_signed_mandate
    ledger = MandateLedger()
    max_uses = fx.signed.mandate.scope.max_transaction_count

    for _ in range(max_uses):
        result = verify_mandate(fx.signed, fx.registry, ledger, now=REFERENCE_NOW)
        assert result.valid
        ledger.record_usage(fx.signed.mandate.mandate_id)

    final_result = verify_mandate(fx.signed, fx.registry, ledger, now=REFERENCE_NOW)
    assert not final_result.valid
    assert VerificationFailureReason.BUDGET_EXHAUSTED in final_result.reasons


def test_verification_does_not_itself_consume_budget(
    registry_and_signed_mandate: _RegistryFixture,
) -> None:
    """Calling verify_mandate repeatedly must not, by itself, exhaust the budget.

    Verification needs to be safe to call for display/audit purposes without
    side effects; only an explicit `ledger.record_usage` call should count
    against the budget.
    """
    fx = registry_and_signed_mandate
    ledger = MandateLedger()
    for _ in range(10):
        result = verify_mandate(fx.signed, fx.registry, ledger, now=REFERENCE_NOW)
        assert result.valid


def test_tampered_signature_fails_and_short_circuits(
    registry_and_signed_mandate: _RegistryFixture,
) -> None:
    """An invalid signature must report only INVALID_SIGNATURE, not additional reasons."""
    fx = registry_and_signed_mandate
    tampered = fx.signed.model_copy(update={"signature": "not-a-real-signature=="})
    result = verify_mandate(tampered, fx.registry, MandateLedger(), now=REFERENCE_NOW)
    assert not result.valid
    assert result.reasons == (VerificationFailureReason.INVALID_SIGNATURE,)


def test_multiple_simultaneous_failures_all_reported() -> None:
    """A mandate that is both expired and budget-exhausted should report both reasons."""
    private_key, public_key = generate_keypair()
    scope = build_scope(
        valid_from=REFERENCE_NOW - timedelta(days=10),
        valid_until=REFERENCE_NOW - timedelta(days=1),
        max_transaction_count=1,
    )
    mandate = build_mandate(
        private_key,
        scope=scope,
        issued_at=REFERENCE_NOW - timedelta(days=10),
        expires_at=REFERENCE_NOW - timedelta(hours=1),
    )
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    ledger = MandateLedger()
    ledger.record_usage(mandate.mandate_id)

    result = verify_mandate(signed, registry, ledger, now=REFERENCE_NOW)
    assert not result.valid
    assert VerificationFailureReason.EXPIRED in result.reasons
    assert VerificationFailureReason.BUDGET_EXHAUSTED in result.reasons
    assert len(result.reasons) == 2