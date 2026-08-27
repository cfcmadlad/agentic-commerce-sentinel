"""Tests for the mandate chaining / privilege-escalation attack generator.

The legitimate substrate and one large attack batch are built once, as
module-level constants, and reused read-only by every test below (mirroring
how the rest of this project scopes expensive corpus generation, but
avoiding rebuilding a 150-session corpus and a 150-attack batch per test).
Covers the entry point's own contract (positive `n_attacks`, an eligible
world, exact-count output, reproducibility) plus, per variant, the specific
structural property each one claims in
`generator/attacks/chaining.py`'s module docstring.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from common.schema import AttackClass, EventType, LabeledSession, SessionEvent, SessionTrace
from generator.attacks.chaining import (
    BUDGET_ESCALATION_MULTIPLE,
    TEMPORAL_OUTLIVE_EXTRA,
    VARIANT_BREADTH_ESCALATION,
    VARIANT_BUDGET_ESCALATION,
    VARIANT_FANOUT_STRUCTURING,
    VARIANT_TEMPORAL_OUTLIVE,
    VARIANT_UNAUTHORIZED_SUBDELEGATION,
    generate_mandate_chaining_attacks,
)
from generator.attacks.common import AttackWorld, GeneratedAttack, agent_by_id, build_world
from generator.config import DEFAULT_GENERATOR_CONFIG
from generator.legitimate import LegitimateGeneratorOutput, generate_legitimate_sessions
from mandate.schema import Mandate
from mandate.signing import signature_is_valid
from mandate.verification import AgentKeyRegistry, MandateLedger

ALL_VARIANTS = frozenset(
    {
        VARIANT_BUDGET_ESCALATION,
        VARIANT_BREADTH_ESCALATION,
        VARIANT_TEMPORAL_OUTLIVE,
        VARIANT_UNAUTHORIZED_SUBDELEGATION,
        VARIANT_FANOUT_STRUCTURING,
    }
)

# Legitimate substrate every test builds attacks against.
LEGIT_N_SESSIONS = 150
LEGIT_SEED = 4242

# Large enough that, with five roughly-equal-weight variants, missing one
# entirely across the run is not a realistic outcome for a correct
# implementation (this is deterministic given the fixed seed below, not a
# flaky probabilistic check).
LARGE_N_ATTACKS = 150
LARGE_SEED = 2026

_FIXTURE_NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)

_WORLD: AttackWorld = build_world(generate_legitimate_sessions(LEGIT_N_SESSIONS, seed=LEGIT_SEED))
_LARGE_BATCH: tuple[GeneratedAttack, ...] = generate_mandate_chaining_attacks(
    _WORLD, LARGE_N_ATTACKS, seed=LARGE_SEED
)


def _empty_legitimate_output() -> LegitimateGeneratorOutput:
    """Builds a minimal legitimate output with no mandate to chain from.

    Returns:
        An output whose single session presents no mandate at all, so no
        parent candidate can ever be constructed from it.
    """
    session = SessionTrace(
        session_id=uuid4(),
        agent_id="agent-000",
        user_id="user-0000",
        mandate_id=None,
        merchant_id="zomato",
        merchant_category="food_delivery",
        item_category="restaurant_order",
        amount=Decimal("300.00"),
        currency="INR",
        events=[SessionEvent(event_type=EventType.PAYMENT_RESULT, timestamp=_FIXTURE_NOW, payload={})],
        started_at=_FIXTURE_NOW,
        completed_at=_FIXTURE_NOW,
    )
    labeled = LabeledSession(
        trace=session,
        attack_class=AttackClass.LEGITIMATE,
        is_attack=False,
        generator_seed=0,
        generator_params_digest="fixture",
    )
    return LegitimateGeneratorOutput(
        labeled_sessions=(labeled,),
        signed_mandates={},
        registry=AgentKeyRegistry(),
        ledger=MandateLedger(),
        agents=(),
        seed=0,
        params_digest="fixture",
        config=DEFAULT_GENERATOR_CONFIG,
    )


def test_rejects_zero_and_negative_n_attacks() -> None:
    """`n_attacks <= 0` must raise, for zero and for negative counts alike."""
    for bad_n in (0, -1, -100):
        with pytest.raises(ValueError, match="n_attacks"):
            generate_mandate_chaining_attacks(_WORLD, bad_n, seed=1)


def test_rejects_world_with_no_eligible_parent() -> None:
    """A world with no mandate to chain from must raise, not return an empty tuple."""
    empty_world = build_world(_empty_legitimate_output())
    with pytest.raises(ValueError):
        generate_mandate_chaining_attacks(empty_world, 5, seed=1)


def test_returns_exactly_n_attacks_requested() -> None:
    """Output length must equal `n_attacks` exactly, even when a fan-out group would overshoot it."""
    for n_attacks in (1, 2, 3, 7, 25):
        attacks = generate_mandate_chaining_attacks(_WORLD, n_attacks, seed=n_attacks)
        assert len(attacks) == n_attacks


def test_reproducible_for_fixed_seed() -> None:
    """The same `(world, n_attacks, seed)` triple must reproduce byte-identically."""
    first = generate_mandate_chaining_attacks(_WORLD, 40, seed=99)
    second = generate_mandate_chaining_attacks(_WORLD, 40, seed=99)

    assert len(first) == len(second)
    for a, b in zip(first, second, strict=True):
        assert a.variant == b.variant
        assert a.labeled.trace.session_id == b.labeled.trace.session_id
        assert a.labeled.trace.amount == b.labeled.trace.amount
        assert a.labeled.trace.started_at == b.labeled.trace.started_at
        assert a.signed_mandate is not None
        assert b.signed_mandate is not None
        assert a.signed_mandate.mandate.mandate_id == b.signed_mandate.mandate.mandate_id
        assert a.signed_mandate.mandate.nonce == b.signed_mandate.mandate.nonce
        assert a.signed_mandate.signature == b.signed_mandate.signature


def test_different_seed_produces_different_sessions() -> None:
    """Changing only the seed must change which sessions are produced."""
    first = generate_mandate_chaining_attacks(_WORLD, 40, seed=1)
    second = generate_mandate_chaining_attacks(_WORLD, 40, seed=2)

    first_ids = {a.labeled.trace.session_id for a in first}
    second_ids = {a.labeled.trace.session_id for a in second}
    assert first_ids.isdisjoint(second_ids)


def test_every_attack_is_labeled_mandate_chaining() -> None:
    """Every generated session must carry the MANDATE_CHAINING ground truth."""
    for attack in _LARGE_BATCH:
        assert attack.labeled.attack_class == AttackClass.MANDATE_CHAINING
        assert attack.labeled.is_attack is True


def test_every_attack_carries_a_valid_chained_mandate() -> None:
    """Every attack's mandate must genuinely chain from a real legitimate parent."""
    for attack in _LARGE_BATCH:
        assert attack.signed_mandate is not None
        mandate = attack.signed_mandate.mandate

        # Chained from a mandate that genuinely exists in the legitimate
        # corpus, never a fabricated parent.
        assert mandate.parent_mandate_id is not None
        assert mandate.parent_mandate_id in _WORLD.output.signed_mandates

        # The session presents exactly this child mandate.
        assert attack.labeled.trace.mandate_id == mandate.mandate_id

        # Internal mandate/scope invariants (also enforced by Mandate's own
        # pydantic validators at construction time; re-asserted here so a
        # future relaxation of those validators cannot silently let an
        # inconsistent chain through undetected).
        assert mandate.expires_at > mandate.issued_at
        assert mandate.scope.valid_until <= mandate.expires_at
        assert mandate.scope.valid_from <= mandate.scope.valid_until


def test_every_child_mandate_is_genuinely_signed() -> None:
    """The signature must verify against the claimed signer's real registered key.

    This is what separates every variant here from forgery: nothing in this
    module ever signs with a key that does not belong to the agent named on
    the mandate.
    """
    for attack in _LARGE_BATCH:
        assert attack.signed_mandate is not None
        mandate = attack.signed_mandate.mandate
        signer = agent_by_id(_WORLD, mandate.agent_id)
        assert signature_is_valid(attack.signed_mandate, signer.private_key.public_key())


def test_variant_coverage() -> None:
    """All five documented sub-variants must appear in a large batch."""
    observed = {attack.variant for attack in _LARGE_BATCH}
    assert observed == ALL_VARIANTS


def test_budget_escalation_inflates_ceiling_beyond_parent() -> None:
    """`budget_escalation` children must declare the configured multiple of the parent's ceiling."""
    matches = [a for a in _LARGE_BATCH if a.variant == VARIANT_BUDGET_ESCALATION]
    assert matches, "no budget_escalation attacks generated"
    for attack in matches:
        assert attack.signed_mandate is not None
        child_mandate = attack.signed_mandate.mandate
        assert child_mandate.parent_mandate_id is not None
        parent = _WORLD.output.signed_mandates[child_mandate.parent_mandate_id]

        expected_ceiling = parent.mandate.scope.max_amount * BUDGET_ESCALATION_MULTIPLE
        assert child_mandate.scope.max_amount == expected_ceiling

        # The session itself spends more than the parent alone ever
        # authorized, but stays inside the inflated child ceiling.
        amount = attack.labeled.trace.amount
        assert amount > parent.mandate.scope.max_amount
        assert amount <= child_mandate.scope.max_amount


def test_breadth_escalation_reaches_new_category() -> None:
    """`breadth_escalation` children must authorize a category the parent never granted."""
    matches = [a for a in _LARGE_BATCH if a.variant == VARIANT_BREADTH_ESCALATION]
    assert matches, "no breadth_escalation attacks generated"
    for attack in matches:
        assert attack.signed_mandate is not None
        child_mandate = attack.signed_mandate.mandate
        assert child_mandate.parent_mandate_id is not None
        parent = _WORLD.output.signed_mandates[child_mandate.parent_mandate_id]
        parent_categories = parent.mandate.scope.allowed_merchant_categories
        child_categories = child_mandate.scope.allowed_merchant_categories

        new_categories = child_categories - parent_categories
        assert new_categories, "breadth escalation must add at least one new category"

        # Amount ceiling is untouched: this variant is isolated to the
        # breadth dimension, unlike budget_escalation.
        assert child_mandate.scope.max_amount == parent.mandate.scope.max_amount

        # The session's own merchant category is one the parent could never
        # have authorized.
        assert attack.labeled.trace.merchant_category not in parent_categories
        assert attack.labeled.trace.merchant_category in child_categories


def test_temporal_outlive_survives_parent_expiry() -> None:
    """`temporal_outlive` children must remain valid, and transact, after the parent expires."""
    matches = [a for a in _LARGE_BATCH if a.variant == VARIANT_TEMPORAL_OUTLIVE]
    assert matches, "no temporal_outlive attacks generated"
    for attack in matches:
        assert attack.signed_mandate is not None
        child_mandate = attack.signed_mandate.mandate
        assert child_mandate.parent_mandate_id is not None
        parent = _WORLD.output.signed_mandates[child_mandate.parent_mandate_id]

        assert child_mandate.expires_at == parent.mandate.expires_at + TEMPORAL_OUTLIVE_EXTRA
        # Amount and categories are untouched: isolated to the temporal
        # dimension only.
        assert child_mandate.scope.max_amount == parent.mandate.scope.max_amount
        assert (
            child_mandate.scope.allowed_merchant_categories
            == parent.mandate.scope.allowed_merchant_categories
        )

        # The defining property: the session happens strictly after the
        # parent's own authority lapsed, while still inside the child's
        # (illegitimately extended) window.
        trace = attack.labeled.trace
        assert trace.started_at > parent.mandate.expires_at
        assert trace.completed_at <= child_mandate.expires_at


def test_unauthorized_subdelegation_hands_off_to_new_agent() -> None:
    """`unauthorized_subdelegation` children must be genuinely signed by a different agent."""
    matches = [a for a in _LARGE_BATCH if a.variant == VARIANT_UNAUTHORIZED_SUBDELEGATION]
    assert matches, "no unauthorized_subdelegation attacks generated"
    for attack in matches:
        assert attack.signed_mandate is not None
        child_mandate = attack.signed_mandate.mandate
        assert child_mandate.parent_mandate_id is not None
        parent = _WORLD.output.signed_mandates[child_mandate.parent_mandate_id]

        # A different agent identity now holds the derived authority.
        assert child_mandate.agent_id != parent.mandate.agent_id
        # Same human principal throughout: this is not a user mix-up, it is
        # an unsanctioned hop in the delegation chain.
        assert child_mandate.user_id == parent.mandate.user_id

        # And the signature is completely genuine: a real, independently
        # registered key belonging to the named delegate agent, not a
        # forged or stolen one.
        delegate = agent_by_id(_WORLD, child_mandate.agent_id)
        assert signature_is_valid(attack.signed_mandate, delegate.private_key.public_key())
        original_holder = agent_by_id(_WORLD, parent.mandate.agent_id)
        assert not signature_is_valid(attack.signed_mandate, original_holder.private_key.public_key())

        assert attack.labeled.trace.agent_id == child_mandate.agent_id


def test_fanout_structuring_aggregate_exceeds_parent_ceiling() -> None:
    """`fanout_structuring` siblings must individually look small but sum past the parent's ceiling."""
    matches = [a for a in _LARGE_BATCH if a.variant == VARIANT_FANOUT_STRUCTURING]
    assert matches, "no fanout_structuring attacks generated"

    groups: dict[UUID, list[Mandate]] = {}
    for attack in matches:
        assert attack.signed_mandate is not None
        child_mandate = attack.signed_mandate.mandate
        assert child_mandate.parent_mandate_id is not None
        groups.setdefault(child_mandate.parent_mandate_id, []).append(child_mandate)

    for parent_id, children in groups.items():
        parent = _WORLD.output.signed_mandates[parent_id]
        parent_ceiling = parent.mandate.scope.max_amount

        # No single sibling looks escalated on its own...
        for child in children:
            assert child.scope.max_amount < parent_ceiling

        # ...but a group has at least two siblings...
        assert len(children) >= 2
        # ...and their combined authorized value is well over what the
        # single parent was ever sized for.
        total = sum((child.scope.max_amount for child in children), start=Decimal("0"))
        assert total > parent_ceiling
