"""Tests for `generator.attacks.scope_violation`: boundary hardness and correctness."""

from __future__ import annotations

import pytest

from common.schema import AttackClass
from detect.scope import ScopeViolationReason, enforce_scope
from generator.attack_config import MAX_CEILING_OVERSHOOT
from generator.attacks.common import AttackWorld, build_world
from generator.attacks.scope_violation import (
    VARIANT_AMOUNT_OVER_CEILING,
    VARIANT_CATEGORY_MISMATCH,
    VARIANT_ITEM_CATEGORY_MISMATCH,
    VARIANT_MERCHANT_NOT_ALLOWED,
    VARIANT_WINDOW_EDGE,
    generate_scope_violation_attacks,
)
from generator.legitimate import generate_legitimate_sessions

N_LEGIT = 800
N_ATTACKS = 150
SEED = 11


@pytest.fixture(scope="module")
def world() -> AttackWorld:
    """Builds one shared attack world for the module.

    Returns:
        The indexed legitimate corpus.
    """
    return build_world(generate_legitimate_sessions(N_LEGIT, seed=SEED))


def test_generates_requested_count(world: AttackWorld) -> None:
    """The generator must produce exactly the requested number of attacks."""
    assert len(generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)) == N_ATTACKS


def test_rejects_non_positive_count(world: AttackWorld) -> None:
    """A zero or negative attack count is a caller error."""
    with pytest.raises(ValueError, match="must be positive"):
        generate_scope_violation_attacks(world, 0, seed=SEED)


def test_same_seed_is_byte_identical(world: AttackWorld) -> None:
    """Reproducibility: the same seed must reproduce identical traces."""
    a = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    b = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    assert [x.labeled.trace.model_dump() for x in a] == [
        y.labeled.trace.model_dump() for y in b
    ]


def test_all_labeled_as_scope_violation(world: AttackWorld) -> None:
    """Every session this generator emits must carry the scope-violation label."""
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    assert all(a.labeled.attack_class is AttackClass.SCOPE_VIOLATION for a in attacks)


def test_all_variants_are_produced(world: AttackWorld) -> None:
    """A run large enough to cover the mix must exercise every variant."""
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    assert {a.variant for a in attacks} == {
        VARIANT_AMOUNT_OVER_CEILING,
        VARIANT_MERCHANT_NOT_ALLOWED,
        VARIANT_CATEGORY_MISMATCH,
        VARIANT_ITEM_CATEGORY_MISMATCH,
        VARIANT_WINDOW_EDGE,
    }


def test_every_attack_genuinely_violates_its_own_mandate(world: AttackWorld) -> None:
    """Ground truth must be earned: each session must actually be out of scope.

    A mislabeled in-scope session would be an unfixable false negative and
    would silently cap the measured recall of every downstream model.
    """
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    for attack in attacks:
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        signed = world.output.signed_mandates[mandate_id]
        result = enforce_scope(attack.labeled.trace, signed)
        assert not result.in_scope, f"{attack.variant} produced an in-scope session"


def test_amount_violations_sit_at_the_boundary(world: AttackWorld) -> None:
    """Over-ceiling violations must be marginal, not egregious.

    A detector that only catches large overshoots would score well on easy
    data and fail against realistic ones.
    """
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    marginal = [a for a in attacks if a.variant == VARIANT_AMOUNT_OVER_CEILING]
    assert marginal, "expected the mix to produce amount violations"
    for attack in marginal:
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        ceiling = world.output.signed_mandates[mandate_id].mandate.scope.max_amount
        assert attack.labeled.trace.amount > ceiling
        assert attack.labeled.trace.amount <= ceiling * MAX_CEILING_OVERSHOOT * 2


def test_merchant_violations_stay_inside_the_authorized_category(world: AttackWorld) -> None:
    """A merchant violation must not also be a category violation.

    Otherwise the merchant allowlist rule is never the thing being tested.
    """
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_MERCHANT_NOT_ALLOWED):
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        scope = world.output.signed_mandates[mandate_id].mandate.scope
        result = enforce_scope(attack.labeled.trace, world.output.signed_mandates[mandate_id])
        assert attack.labeled.trace.merchant_category in scope.allowed_merchant_categories
        assert ScopeViolationReason.MERCHANT_NOT_ALLOWED in result.reasons


def test_window_violations_are_minutes_not_months_past_the_limit(world: AttackWorld) -> None:
    """Time-window violations must sit just past the edge, not far beyond it."""
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    edge = [a for a in attacks if a.variant == VARIANT_WINDOW_EDGE]
    assert edge, "expected the mix to produce window violations"
    for attack in edge:
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        scope = world.output.signed_mandates[mandate_id].mandate.scope
        overshoot_hours = (
            attack.labeled.trace.started_at - scope.valid_until
        ).total_seconds() / 3600
        assert 0 < overshoot_hours <= 4


def test_item_category_violations_keep_merchant_in_scope(world: AttackWorld) -> None:
    """An item-category violation must be caught by the item rule alone."""
    attacks = generate_scope_violation_attacks(world, N_ATTACKS, seed=SEED)
    for attack in (a for a in attacks if a.variant == VARIANT_ITEM_CATEGORY_MISMATCH):
        mandate_id = attack.labeled.trace.mandate_id
        assert mandate_id is not None
        signed = world.output.signed_mandates[mandate_id]
        result = enforce_scope(attack.labeled.trace, signed)
        assert result.reasons == (ScopeViolationReason.ITEM_CATEGORY_NOT_ALLOWED,)