"""Tests for `generator.attacks.replay`: determinism and per-variant properties."""

from __future__ import annotations

import pytest

from common.schema import AttackClass
from generator.attacks.common import AttackWorld, build_world
from generator.attacks.replay import (
    VARIANT_BUDGET_EXHAUSTED,
    VARIANT_EXPIRED,
    VARIANT_RAPID_REUSE,
    generate_replay_attacks,
)
from generator.config import MIN_RECURRING_REUSE_GAP_HOURS
from generator.legitimate import generate_legitimate_sessions

N_LEGIT = 800
N_ATTACKS = 120
SEED = 7


@pytest.fixture(scope="module")
def world() -> AttackWorld:
    """Builds one shared attack world for the module.

    Returns:
        The indexed legitimate corpus.
    """
    return build_world(generate_legitimate_sessions(N_LEGIT, seed=SEED))


def test_generates_requested_count(world: AttackWorld) -> None:
    """The generator must produce exactly the requested number of attacks."""
    assert len(generate_replay_attacks(world, N_ATTACKS, seed=SEED)) == N_ATTACKS


def test_rejects_non_positive_count(world: AttackWorld) -> None:
    """A zero or negative attack count is a caller error, not zero output."""
    with pytest.raises(ValueError, match="must be positive"):
        generate_replay_attacks(world, 0, seed=SEED)


def test_same_seed_is_byte_identical(world: AttackWorld) -> None:
    """Reproducibility: the same seed must reproduce identical traces."""
    a = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    b = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    assert [x.labeled.trace.model_dump() for x in a] == [
        y.labeled.trace.model_dump() for y in b
    ]


def test_different_seed_differs(world: AttackWorld) -> None:
    """A different seed must not coincidentally reproduce the same first attack."""
    a = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    b = generate_replay_attacks(world, N_ATTACKS, seed=SEED + 1)
    assert a[0].labeled.trace.model_dump() != b[0].labeled.trace.model_dump()


def test_all_labeled_as_replay(world: AttackWorld) -> None:
    """Every session this generator emits must carry the replay label."""
    attacks = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    assert all(a.labeled.attack_class is AttackClass.MANDATE_REPLAY for a in attacks)
    assert all(a.labeled.is_attack for a in attacks)


def test_all_three_variants_are_produced(world: AttackWorld) -> None:
    """A run large enough to cover the mix must exercise every variant."""
    attacks = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    assert {a.variant for a in attacks} == {
        VARIANT_EXPIRED,
        VARIANT_BUDGET_EXHAUSTED,
        VARIANT_RAPID_REUSE,
    }


def test_expired_variant_starts_after_the_window_closes(world: AttackWorld) -> None:
    """The expired variant must actually fall outside the mandate's window."""
    attacks = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_EXPIRED):
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        scope = world.output.signed_mandates[mandate_id].mandate.scope
        assert attack.labeled.trace.started_at > scope.valid_until


def test_budget_exhausted_variant_stays_inside_the_window(world: AttackWorld) -> None:
    """Budget exhaustion must be tested without expiry also firing.

    If the session were also outside the time window, expiry would fire and
    the variant would stop measuring the ledger at all.
    """
    attacks = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_BUDGET_EXHAUSTED):
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        mandate = world.output.signed_mandates[mandate_id].mandate
        assert mandate.scope.valid_from <= attack.labeled.trace.started_at
        assert attack.labeled.trace.started_at <= mandate.scope.valid_until


def test_rapid_reuse_is_faster_than_any_legitimate_reuse(world: AttackWorld) -> None:
    """The rules-invisible variant must sit inside a gap legitimate traffic never uses.

    The legitimate generator enforces a minimum reuse gap; every rapid-reuse
    attack must fall strictly under it.
    """
    attacks = generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    rapid = [a for a in attacks if a.variant == VARIANT_RAPID_REUSE]
    assert rapid, "expected the mix to produce rapid-reuse attacks"
    for attack in rapid:
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        gap_hours = (
            attack.labeled.trace.started_at - world.mandate_last_used_at[mandate_id]
        ).total_seconds() / 3600
        assert 0 < gap_hours < MIN_RECURRING_REUSE_GAP_HOURS


def test_generator_does_not_mutate_the_world(world: AttackWorld) -> None:
    """Attack generation must leave the legitimate corpus untouched."""
    before = len(world.output.signed_mandates), len(world.output.labeled_sessions)
    generate_replay_attacks(world, N_ATTACKS, seed=SEED)
    assert (len(world.output.signed_mandates), len(world.output.labeled_sessions)) == before