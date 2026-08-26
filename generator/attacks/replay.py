"""Attack class 1: mandate replay.

An agent presents an authorization it has already used up, or one that has
lapsed, or one it is entitled to use but is using far faster than the human
who granted it would expect. Three variants, deliberately spanning easy to
rules-invisible:

- EXPIRED: the mandate lapsed hours to days ago. Layer 1 catches this on the
  time window. Included because it is realistic, not because it is hard.
- BUDGET_EXHAUSTED: the mandate's transaction count is already fully consumed
  by legitimate sessions. Layer 1 catches this, but only if the verifier is
  replaying sessions chronologically through a shared ledger - which is
  exactly the property this variant exists to test.
- RAPID_REUSE: the mandate is genuine, unexpired, in-scope, and still has
  budget remaining. Layers 1 and 2 both pass it. The only thing wrong is the
  cadence: a reuse seconds-to-minutes behind the previous one, where the
  legitimate generator never reuses a mandate inside six hours. This is the
  variant that justifies Layer 3 existing at all, and the one whose recall
  the rules-baseline evaluation should be read against most carefully.

Every session here reuses a real merchant, item category and amount drawn
from a genuine session on the same mandate, so nothing but the authorization
timing distinguishes an attack from the legitimate traffic around it.

Defense-only: this produces synthetic traffic against this project's own
detector and encodes nothing transferable to a real payment system.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import numpy as np

from common.schema import AttackClass, SessionTrace
from generator.attack_config import (
    DEFAULT_ATTACK_CONFIG,
    VARIANT_BUDGET_EXHAUSTED,
    VARIANT_EXPIRED,
    VARIANT_RAPID_REUSE,
    AttackConfig,
)
from generator.attacks.common import AttackWorld, GeneratedAttack, label_attack, pick_weighted
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.rng import rng_uuid
from mandate.schema import SignedMandate

logger = logging.getLogger(__name__)

# Variant names are re-exported from the attack config, which owns them, so a
# rename cannot leave the weights and the generator disagreeing.
__all__ = [
    "VARIANT_BUDGET_EXHAUSTED",
    "VARIANT_EXPIRED",
    "VARIANT_RAPID_REUSE",
    "generate_replay_attacks",
]

# Minimum remaining validity a mandate must have for a rapid-reuse replay to
# land inside its window rather than tipping past expiry, which would make
# Layer 1 catch it on the wrong signal.
MIN_RAPID_REUSE_WINDOW_HEADROOM_HOURS = 1


def _eligible_mandates(world: AttackWorld, variant: str) -> list[SignedMandate]:
    """Selects mandates from the world that a given replay variant can target.

    Args:
        world: The indexed legitimate corpus.
        variant: One of the module's VARIANT_* constants.

    Returns:
        Candidate signed mandates, possibly empty.

    Raises:
        ValueError: If `variant` is not a known variant.
    """
    mandates = [
        world.output.signed_mandates[mandate_id]
        for mandate_id in sorted(world.session_by_mandate, key=str)
    ]
    if variant == VARIANT_EXPIRED:
        return mandates
    if variant == VARIANT_BUDGET_EXHAUSTED:
        return [
            signed
            for signed in mandates
            if world.mandate_use_count.get(signed.mandate.mandate_id, 0)
            >= signed.mandate.scope.max_transaction_count
        ]
    if variant == VARIANT_RAPID_REUSE:
        # Needs headroom: if the budget is already spent, Layer 1 catches it
        # on budget rather than the cadence, which is the other variant.
        return [
            signed
            for signed in mandates
            if world.mandate_use_count.get(signed.mandate.mandate_id, 0)
            < signed.mandate.scope.max_transaction_count
            and world.mandate_last_used_at.get(signed.mandate.mandate_id) is not None
            and world.mandate_last_used_at[signed.mandate.mandate_id]
            < signed.mandate.scope.valid_until
            - timedelta(hours=MIN_RAPID_REUSE_WINDOW_HEADROOM_HOURS)
        ]
    raise ValueError(f"unknown replay variant {variant!r}")


def _build_replay_trace(
    rng: np.random.Generator,
    world: AttackWorld,
    signed: SignedMandate,
    variant: str,
    config: AttackConfig,
) -> SessionTrace:
    """Builds one replay session against an already-used mandate.

    Args:
        rng: Seeded random generator.
        world: The indexed legitimate corpus.
        signed: The mandate being replayed.
        variant: One of the module's VARIANT_* constants.
        config: Attack parameters supplying the replay lag and gap bounds.

    Returns:
        The synthetic session trace.

    Raises:
        ValueError: If `variant` is not a known variant.
    """
    mandate = signed.mandate
    donor_sessions = world.session_by_mandate[mandate.mandate_id]
    donor = donor_sessions[int(rng.integers(0, len(donor_sessions)))]
    last_used = world.mandate_last_used_at[mandate.mandate_id]

    if variant == VARIANT_EXPIRED:
        lag_hours = float(
            rng.uniform(config.min_expired_replay_lag_hours, config.max_expired_replay_lag_hours)
        )
        session_start = mandate.scope.valid_until + timedelta(hours=lag_hours)
    elif variant == VARIANT_BUDGET_EXHAUSTED:
        # Placed inside the still-valid window on purpose: the mandate has not
        # lapsed, it has simply been spent, so EXPIRED must not also fire or
        # the variant stops testing the ledger.
        remaining = mandate.scope.valid_until - last_used
        offset = timedelta(seconds=float(rng.uniform(0, max(remaining.total_seconds(), 1.0))))
        session_start = min(last_used + offset, mandate.scope.valid_until - timedelta(minutes=1))
    elif variant == VARIANT_RAPID_REUSE:
        gap = float(
            rng.uniform(config.min_rapid_reuse_gap_seconds, config.max_rapid_reuse_gap_seconds)
        )
        session_start = last_used + timedelta(seconds=gap)
    else:
        raise ValueError(f"unknown replay variant {variant!r}")

    # Legitimate pacing on purpose: a replay is defined by the authorization
    # being wrong, not by the session looking odd. Drawing from the world's own
    # generator config keeps that guarantee under a perturbed sensitivity grid.
    generator_config = world.output.config
    events, completed_at = build_events(
        rng,
        session_start,
        LEGITIMATE_LIFECYCLE,
        generator_config.min_event_gap_seconds,
        generator_config.max_event_gap_seconds,
    )
    return SessionTrace(
        session_id=rng_uuid(rng),
        agent_id=donor.agent_id,
        user_id=donor.user_id,
        mandate_id=mandate.mandate_id,
        merchant_id=donor.merchant_id,
        merchant_category=donor.merchant_category,
        item_category=donor.item_category,
        amount=donor.amount,
        currency=donor.currency,
        events=events,
        started_at=session_start,
        completed_at=completed_at,
    )


def generate_replay_attacks(
    world: AttackWorld,
    n_attacks: int,
    seed: int,
    config: AttackConfig = DEFAULT_ATTACK_CONFIG,
    params_digest: str | None = None,
) -> tuple[GeneratedAttack, ...]:
    """Generates mandate-replay attack sessions against a legitimate corpus.

    Args:
        world: The indexed legitimate corpus to build attacks against.
        n_attacks: Number of attack sessions to produce. Must be positive.
        seed: Seed for this generator's random draws.
        config: Attack parameters. The default reproduces the parameter set
            every reported headline number was measured under.
        params_digest: Digest stamped on each generated session. Defaults to
            the legitimate world's own digest, which covers the generator
            parameters but not the attack ones; the corpus builder passes a
            combined digest instead so a sensitivity grid point that varies
            only attack parameters is still distinguishable.

    Returns:
        The generated attacks, in generation order.

    Raises:
        ValueError: If `n_attacks` is not positive, or if the world contains
            no mandate any replay variant can target. The latter means the
            legitimate corpus is too small or too short-horizoned to support
            replay traffic, and silently returning fewer attacks than asked
            would corrupt the base rate reported alongside every metric.
    """
    if n_attacks <= 0:
        raise ValueError(f"n_attacks must be positive, got {n_attacks}")

    rng = np.random.default_rng(seed)
    digest = world.output.params_digest if params_digest is None else params_digest
    variant_weights = config.replay_variant_mix
    attacks: list[GeneratedAttack] = []

    candidates_by_variant = {
        variant: _eligible_mandates(world, variant) for variant in variant_weights
    }
    available = {
        variant: weight
        for variant, weight in variant_weights.items()
        if candidates_by_variant[variant]
    }
    if not available:
        raise ValueError(
            "no mandate in the legitimate corpus is eligible for any replay variant; "
            "generate a larger legitimate corpus first"
        )
    for variant in variant_weights:
        if variant not in available:
            logger.warning(
                "replay variant %s has no eligible mandates and will not be generated", variant
            )

    for _ in range(n_attacks):
        variant = pick_weighted(rng, available)
        pool = candidates_by_variant[variant]
        signed = pool[int(rng.integers(0, len(pool)))]
        trace = _build_replay_trace(rng, world, signed, variant, config)
        attacks.append(
            GeneratedAttack(
                labeled=label_attack(trace, AttackClass.MANDATE_REPLAY, seed, digest),
                signed_mandate=None,
                variant=variant,
            )
        )

    return tuple(attacks)