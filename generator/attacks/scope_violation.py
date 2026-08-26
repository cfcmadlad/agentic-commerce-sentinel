"""Attack class 2: scope violation.

The mandate is genuine, correctly signed, unexpired and unspent. The agent
simply spends it on something the human did not authorize: more money, a
different merchant, a different category of goods, or outside the agreed time
window.

Layer 2 is by construction the oracle for this class: if the scope engine
checks all six scope dimensions correctly, any session that violates one of
them is caught with certainty. Near-perfect recall on this class is therefore
a statement about Layer 2's correctness, not about the attacks being weak.
What the attacks here can be made hard on is the *margin*: a violation that
sits 0.05% past the ceiling, or four minutes past the window, is caught only
by an engine that compares exactly and does not round, clamp, or apply a
tolerance. Every variant below is generated at that margin deliberately, so a
sloppy implementation of Layer 2 fails visibly instead of scoring well on
comfortable 10x overshoots.

The genuinely hard part of the agentic-commerce problem does not live in this
class; it lives in the rules-invisible variants of classes 1 and 3.

Defense-only: synthetic traffic against this project's own detector only.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal

import numpy as np

from common.schema import AttackClass, SessionTrace
from generator.attack_config import (
    DEFAULT_ATTACK_CONFIG,
    VARIANT_AMOUNT_OVER_CEILING,
    VARIANT_CATEGORY_MISMATCH,
    VARIANT_ITEM_CATEGORY_MISMATCH,
    VARIANT_MERCHANT_NOT_ALLOWED,
    VARIANT_WINDOW_EDGE,
    AttackConfig,
)
from generator.attacks.common import AttackWorld, GeneratedAttack, label_attack, pick_weighted
from generator.config import CategoryConfig, GeneratorConfig
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.legitimate import AMOUNT_QUANTIZE, sample_amount
from generator.rng import rng_uuid
from mandate.schema import SignedMandate

logger = logging.getLogger(__name__)

# Variant names are re-exported from the attack config, which owns them, so a
# rename cannot leave the weights and the generator disagreeing.
__all__ = [
    "VARIANT_AMOUNT_OVER_CEILING",
    "VARIANT_CATEGORY_MISMATCH",
    "VARIANT_ITEM_CATEGORY_MISMATCH",
    "VARIANT_MERCHANT_NOT_ALLOWED",
    "VARIANT_WINDOW_EDGE",
    "generate_scope_violation_attacks",
]

# Validity of a variant name is a property of the taxonomy, not of the weights
# a particular config assigns: a config may legitimately zero a variant's
# weight, and that must not make the name itself unknown.
_KNOWN_VARIANTS: frozenset[str] = frozenset(
    {
        VARIANT_AMOUNT_OVER_CEILING,
        VARIANT_MERCHANT_NOT_ALLOWED,
        VARIANT_CATEGORY_MISMATCH,
        VARIANT_ITEM_CATEGORY_MISMATCH,
        VARIANT_WINDOW_EDGE,
    }
)


def _has_budget_headroom(world: AttackWorld, signed: SignedMandate) -> bool:
    """Reports whether a mandate has at least one unspent redemption left.

    A scope violation must be caught *for being out of scope*. If the target
    mandate were already budget-exhausted, Layer 1 would reject the session on
    budget before Layer 2 ever evaluated the scope, and the variant would stop
    measuring what it claims to measure.

    Args:
        world: The indexed legitimate corpus.
        signed: The candidate mandate.

    Returns:
        True if the mandate has redemptions remaining.
    """
    used = world.mandate_use_count.get(signed.mandate.mandate_id, 0)
    return used < signed.mandate.scope.max_transaction_count


def _eligible_mandates(world: AttackWorld, variant: str) -> list[SignedMandate]:
    """Selects mandates a given scope-violation variant can target.

    Args:
        world: The indexed legitimate corpus.
        variant: One of the module's VARIANT_* constants.

    Returns:
        Candidate signed mandates, possibly empty.

    Raises:
        ValueError: If `variant` is not a known variant.
    """
    if variant not in _KNOWN_VARIANTS:
        raise ValueError(f"unknown scope-violation variant {variant!r}")

    mandates = [
        world.output.signed_mandates[mandate_id]
        for mandate_id in sorted(world.session_by_mandate, key=str)
        if _has_budget_headroom(world, world.output.signed_mandates[mandate_id])
    ]
    if variant == VARIANT_MERCHANT_NOT_ALLOWED:
        # Only a mandate pinned to an explicit merchant allowlist can be
        # violated on merchant identity; a category-scoped mandate cannot.
        return [s for s in mandates if s.mandate.scope.allowed_merchant_ids is not None]
    if variant == VARIANT_ITEM_CATEGORY_MISMATCH:
        return [s for s in mandates if _out_of_scope_item_categories(s, world.output.config)]
    return mandates


def _out_of_scope_item_categories(
    signed: SignedMandate, generator_config: GeneratorConfig
) -> tuple[str, ...]:
    """Lists item categories that exist in the catalog but not in this scope.

    Sorted for determinism: iterating a set would make the choice depend on
    Python's hash seed rather than only on the generator's own seed.

    Args:
        signed: The mandate whose scope is being violated.
        generator_config: Generator parameters supplying the item catalog.

    Returns:
        Out-of-scope item category labels, sorted.
    """
    catalog = {
        item for category in generator_config.categories for item in category.item_categories
    }
    return tuple(sorted(catalog - set(signed.mandate.scope.allowed_item_categories)))


def _category_for_name(name: str, generator_config: GeneratorConfig) -> CategoryConfig:
    """Resolves a merchant category label to its config.

    Args:
        name: The merchant category label.
        generator_config: Generator parameters supplying the category catalog.

    Returns:
        The matching `CategoryConfig`.

    Raises:
        KeyError: If the label is not in the configured catalog, which would
            mean the mandate and the generator config have drifted apart.
    """
    for category in generator_config.categories:
        if category.name == name:
            return category
    raise KeyError(f"merchant category {name!r} is not in the generator catalog")


def _build_violation_trace(
    rng: np.random.Generator,
    world: AttackWorld,
    signed: SignedMandate,
    variant: str,
    config: AttackConfig,
) -> SessionTrace:
    """Builds one session that violates exactly one dimension of a mandate's scope.

    One dimension is targeted per session on purpose: a session that breached
    several at once would be caught by any of several independent rules and
    would inflate the baseline's apparent recall while testing none of them
    individually. The one unavoidable exception is CATEGORY_MISMATCH, where
    shopping in a different merchant category necessarily also means buying a
    different category of item. That co-firing is inherent to the violation
    rather than a generator shortcut, and the per-rule counts in the
    evaluation report show it explicitly rather than hiding it.

    Args:
        rng: Seeded random generator.
        world: The indexed legitimate corpus.
        signed: The mandate being violated.
        variant: One of the module's VARIANT_* constants.
        config: Attack parameters supplying the overshoot bounds.

    Returns:
        The synthetic session trace.

    Raises:
        ValueError: If `variant` is not a known variant.
    """
    mandate = signed.mandate
    scope = mandate.scope
    generator_config = world.output.config
    donor_sessions = world.session_by_mandate[mandate.mandate_id]
    donor = donor_sessions[int(rng.integers(0, len(donor_sessions)))]
    home_category = _category_for_name(donor.merchant_category, generator_config)

    # Baseline: an entirely in-scope session, mutated on one axis below.
    merchant_id = donor.merchant_id
    merchant_category = donor.merchant_category
    item_category = donor.item_category
    amount = donor.amount
    last_used = world.mandate_last_used_at[mandate.mandate_id]
    window_end = scope.valid_until
    session_start = last_used + timedelta(
        seconds=float(rng.uniform(0, max((window_end - last_used).total_seconds(), 1.0)))
    )

    if variant == VARIANT_AMOUNT_OVER_CEILING:
        overshoot = Decimal(
            str(
                rng.uniform(
                    float(config.min_ceiling_overshoot), float(config.max_ceiling_overshoot)
                )
            )
        )
        amount = (scope.max_amount * overshoot).quantize(
            AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP
        )
        if amount <= scope.max_amount:
            # Quantization can round a very small overshoot back onto the
            # ceiling, which would silently mislabel an in-scope session as an
            # attack. Step to the smallest representable violation instead.
            amount = scope.max_amount + AMOUNT_QUANTIZE
    elif variant == VARIANT_MERCHANT_NOT_ALLOWED:
        allowed = scope.allowed_merchant_ids or frozenset()
        others = tuple(sorted(set(home_category.merchant_ids) - set(allowed)))
        # Staying inside the authorized *category* is what makes this hard:
        # only the merchant allowlist check can catch it.
        merchant_id = others[int(rng.integers(0, len(others)))] if others else "merchant-unlisted"
    elif variant == VARIANT_CATEGORY_MISMATCH:
        foreign = tuple(
            c
            for c in generator_config.categories
            if c.name not in scope.allowed_merchant_categories
        )
        chosen = foreign[int(rng.integers(0, len(foreign)))]
        merchant_category = chosen.name
        merchant_id = chosen.merchant_ids[int(rng.integers(0, len(chosen.merchant_ids)))]
        item_category = chosen.item_categories[int(rng.integers(0, len(chosen.item_categories)))]
        # Amount drawn from the foreign category's own distribution and capped
        # at the ceiling, so the session is not additionally an amount
        # violation and cannot be caught on amount alone.
        amount = sample_amount(rng, chosen, ceiling=scope.max_amount, config=generator_config)
    elif variant == VARIANT_ITEM_CATEGORY_MISMATCH:
        out_of_scope = _out_of_scope_item_categories(signed, generator_config)
        item_category = out_of_scope[int(rng.integers(0, len(out_of_scope)))]
    elif variant == VARIANT_WINDOW_EDGE:
        overshoot_minutes = float(
            rng.uniform(config.min_window_overshoot_minutes, config.max_window_overshoot_minutes)
        )
        session_start = window_end + timedelta(minutes=overshoot_minutes)
    else:
        raise ValueError(f"unknown scope-violation variant {variant!r}")

    # Legitimate pacing on purpose: a scope violation is defined by the
    # authorization being wrong, not by the session looking odd.
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
        merchant_id=merchant_id,
        merchant_category=merchant_category,
        item_category=item_category,
        amount=amount,
        currency=donor.currency,
        events=events,
        started_at=session_start,
        completed_at=completed_at,
    )


def generate_scope_violation_attacks(
    world: AttackWorld,
    n_attacks: int,
    seed: int,
    config: AttackConfig = DEFAULT_ATTACK_CONFIG,
    params_digest: str | None = None,
) -> tuple[GeneratedAttack, ...]:
    """Generates scope-violation attack sessions against a legitimate corpus.

    Args:
        world: The indexed legitimate corpus to build attacks against.
        n_attacks: Number of attack sessions to produce. Must be positive.
        seed: Seed for this generator's random draws.
        config: Attack parameters. The default reproduces the parameter set
            every reported headline number was measured under.
        params_digest: Digest stamped on each generated session. Defaults to
            the legitimate world's own digest; the corpus builder passes a
            digest covering both parameter halves instead.

    Returns:
        The generated attacks, in generation order.

    Raises:
        ValueError: If `n_attacks` is not positive, or if no mandate in the
            world is eligible for any variant.
    """
    if n_attacks <= 0:
        raise ValueError(f"n_attacks must be positive, got {n_attacks}")

    rng = np.random.default_rng(seed)
    digest = world.output.params_digest if params_digest is None else params_digest
    variant_weights = config.scope_variant_mix

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
            "no mandate in the legitimate corpus is eligible for any scope-violation "
            "variant; generate a larger legitimate corpus first"
        )
    for variant in variant_weights:
        if variant not in available:
            logger.warning(
                "scope-violation variant %s has no eligible mandates and will not "
                "be generated",
                variant,
            )

    attacks: list[GeneratedAttack] = []
    for _ in range(n_attacks):
        variant = pick_weighted(rng, available)
        pool = candidates_by_variant[variant]
        signed = pool[int(rng.integers(0, len(pool)))]
        trace = _build_violation_trace(rng, world, signed, variant, config)
        attacks.append(
            GeneratedAttack(
                labeled=label_attack(trace, AttackClass.SCOPE_VIOLATION, seed, digest),
                signed_mandate=None,
                variant=variant,
            )
        )

    return tuple(attacks)