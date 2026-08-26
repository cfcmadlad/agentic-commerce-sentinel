"""Tests for `generator.attacks.impersonation`: variant properties and invisibility."""

from __future__ import annotations

import pytest

from common.schema import AttackClass, EventType
from detect.scope import enforce_scope
from generator.attack_config import MAX_SCRIPTED_EVENT_GAP_SECONDS
from generator.attacks.common import AttackWorld, build_world
from generator.attacks.impersonation import (
    VARIANT_AGENT_BINDING_MISMATCH,
    VARIANT_BEHAVIORAL_ONLY,
    VARIANT_FORGED_SIGNATURE,
    VARIANT_UNREGISTERED_KEY,
    generate_impersonation_attacks,
)
from generator.legitimate import generate_legitimate_sessions
from mandate.signing import signature_is_valid
from mandate.verification import MandateLedger, verify_mandate

N_LEGIT = 800
N_ATTACKS = 150
SEED = 13


@pytest.fixture(scope="module")
def world() -> AttackWorld:
    """Builds one shared attack world for the module.

    Returns:
        The indexed legitimate corpus.
    """
    return build_world(generate_legitimate_sessions(N_LEGIT, seed=SEED))


def test_generates_requested_count(world: AttackWorld) -> None:
    """The generator must produce exactly the requested number of attacks."""
    assert len(generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)) == N_ATTACKS


def test_rejects_non_positive_count(world: AttackWorld) -> None:
    """A zero or negative attack count is a caller error."""
    with pytest.raises(ValueError, match="must be positive"):
        generate_impersonation_attacks(world, 0, seed=SEED)


def test_same_seed_is_byte_identical(world: AttackWorld) -> None:
    """Reproducibility must cover the minted key material, not just the traces."""
    a = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    b = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    assert [x.labeled.trace.model_dump() for x in a] == [
        y.labeled.trace.model_dump() for y in b
    ]
    assert [
        None if x.signed_mandate is None else x.signed_mandate.signature for x in a
    ] == [None if y.signed_mandate is None else y.signed_mandate.signature for y in b]


def test_all_labeled_as_impersonation(world: AttackWorld) -> None:
    """Every session this generator emits must carry the impersonation label."""
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    assert all(a.labeled.attack_class is AttackClass.AGENT_IMPERSONATION for a in attacks)


def test_all_variants_are_produced(world: AttackWorld) -> None:
    """A run large enough to cover the mix must exercise every variant."""
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    assert {a.variant for a in attacks} == {
        VARIANT_UNREGISTERED_KEY,
        VARIANT_FORGED_SIGNATURE,
        VARIANT_AGENT_BINDING_MISMATCH,
        VARIANT_BEHAVIORAL_ONLY,
    }


def test_unregistered_key_mandates_are_not_in_the_registry(world: AttackWorld) -> None:
    """The self-signed variant must be unknown to the key registry.

    That absence is the entire detection mechanism for this variant.
    """
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_UNREGISTERED_KEY):
        assert attack.signed_mandate is not None
        mandate = attack.signed_mandate.mandate
        result = verify_mandate(
            attack.signed_mandate,
            world.output.registry,
            MandateLedger(),
            now=attack.labeled.trace.started_at,
        )
        assert not result.valid
        assert world.output.registry.get(mandate.agent_id, mandate.signer_key_id) is None


def test_forged_signature_mandates_fail_the_signature_check(world: AttackWorld) -> None:
    """A tampered mandate must not verify against the genuine agent's key."""
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    forged = [a for a in attacks if a.variant == VARIANT_FORGED_SIGNATURE]
    assert forged, "expected the mix to produce forged-signature attacks"
    for attack in forged:
        assert attack.signed_mandate is not None
        mandate = attack.signed_mandate.mandate
        public_key = world.output.registry.get(mandate.agent_id, mandate.signer_key_id)
        assert public_key is not None, "the forgery targets a genuinely registered agent"
        assert not signature_is_valid(attack.signed_mandate, public_key)


def test_binding_mismatch_presents_another_agents_mandate(world: AttackWorld) -> None:
    """The binding variant must be cryptographically clean but bound to someone else."""
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    mismatched = [a for a in attacks if a.variant == VARIANT_AGENT_BINDING_MISMATCH]
    assert mismatched, "expected the mix to produce binding-mismatch attacks"
    for attack in mismatched:
        trace = attack.labeled.trace
        assert trace.mandate_id is not None
        signed = world.output.signed_mandates[trace.mandate_id]
        assert trace.agent_id != signed.mandate.agent_id
        result = verify_mandate(signed, world.output.registry, MandateLedger(), now=trace.started_at)
        assert result.valid, "the crypto layer must pass; only the scope binding check can catch this"


def test_behavioral_only_attacks_pass_every_deterministic_rule(world: AttackWorld) -> None:
    """The hard variant must pass mandate verification and scope enforcement both.

    If this test starts failing, the deterministic rules have gained a
    signal that was never meant to be there.
    """
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    behavioral = [a for a in attacks if a.variant == VARIANT_BEHAVIORAL_ONLY]
    assert behavioral, "expected the mix to produce behavioral-only attacks"
    for attack in behavioral:
        trace = attack.labeled.trace
        assert trace.mandate_id is not None
        signed = world.output.signed_mandates[trace.mandate_id]
        assert verify_mandate(signed, world.output.registry, MandateLedger(), now=trace.started_at).valid
        assert enforce_scope(trace, signed).in_scope


def test_scripted_sessions_are_paced_faster_than_configured_bound(world: AttackWorld) -> None:
    """Scripted variants must respect the configured scripted pacing range."""
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_BEHAVIORAL_ONLY):
        timestamps = [e.timestamp for e in attack.labeled.trace.events]
        gaps = [(b - a).total_seconds() for a, b in zip(timestamps, timestamps[1:], strict=False)]
        assert all(gap <= MAX_SCRIPTED_EVENT_GAP_SECONDS for gap in gaps)


def test_some_scripted_sessions_skip_catalog_browse(world: AttackWorld) -> None:
    """The browse-skip marker must be probabilistic, not universal.

    An always-present marker would be a single-rule giveaway and would make
    the class trivially separable for the wrong reason.
    """
    attacks = generate_impersonation_attacks(world, N_ATTACKS, seed=SEED)
    behavioral = [a for a in attacks if a.variant == VARIANT_BEHAVIORAL_ONLY]
    skipped = [
        a
        for a in behavioral
        if EventType.CATALOG_BROWSE not in {e.event_type for e in a.labeled.trace.events}
    ]
    assert 0 < len(skipped) < len(behavioral)