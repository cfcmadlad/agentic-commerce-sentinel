"""Configuration for the attack generators (training classes only).

Every difficulty knob in the attack taxonomy lives here rather than inline in
the generators, for two reasons. First, the evaluation reports a sensitivity
analysis across generator parameters, and that needs a single place to vary
them. Second, the question of whether the attacks are too easy to be worth
modelling is answered by moving the rules-invisible variant weights, so those
weights must be explicit and named rather than buried.

Scope note: the held-out class (mandate chaining / privilege escalation) is
deliberately absent from this module. It is specified in the attack taxonomy
but is not implemented, parameterized, or referenced anywhere in the training
or tuning code, and is generated and evaluated exactly once at the end.

Defense-only note: these parameters describe how to produce synthetic traffic
that violates this project's own mandate format, in order to measure this
project's own detector. They encode no technique against any real payment
system and do not generalize off this repo's synthetic schema.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import TypeVar

from common.schema import AttackClass
from generator.config import (
    GeneratorConfig,
    check_ordered,
    check_probability,
    digest_payload,
)

# Fraction of the generated corpus that is attack traffic. A low single-digit
# base rate rather than a balanced split, because that is what the real
# problem looks like; the realized rate is reported alongside every metric.
DEFAULT_ATTACK_BASE_RATE = 0.04

# Relative share of attack traffic assigned to each of the three training
# classes. Roughly even, tilted toward scope violation because that is the
# class Layer 2 exists to catch and therefore the one that most needs volume
# for its per-rule breakdown to mean anything.
CLASS_MIX_MANDATE_REPLAY = 0.30
CLASS_MIX_SCOPE_VIOLATION = 0.40
CLASS_MIX_AGENT_IMPERSONATION = 0.30

# --- Class 1: mandate replay -------------------------------------------------

# Within replay traffic, the share of each variant. RAPID_REUSE is the
# rules-invisible variant: the mandate is genuine, unexpired and still inside
# its transaction budget, so Layers 1 and 2 both pass and only behavioral
# signal can separate it. Raising this weight is the primary lever for making
# class 1 harder.
REPLAY_MIX_EXPIRED = 0.30
REPLAY_MIX_BUDGET_EXHAUSTED = 0.30
REPLAY_MIX_RAPID_REUSE = 0.40

# How long after a mandate's expiry an expired-replay attempt is made. Bounded
# to hours-to-days, not months: an attacker replaying a year-old mandate is a
# strawman, and a detector tuned on one would not transfer.
MIN_EXPIRED_REPLAY_LAG_HOURS = 1
MAX_EXPIRED_REPLAY_LAG_HOURS = 96

# Gap between a mandate's last legitimate use and a rapid-reuse replay. The
# legitimate generator enforces a minimum 6-hour gap between reuses, so this
# range sits entirely inside territory the legitimate generator never visits -
# which is precisely the behavioral signal Layer 3 is expected to learn.
MIN_RAPID_REUSE_GAP_SECONDS = 20
MAX_RAPID_REUSE_GAP_SECONDS = 900

# --- Class 2: scope violation ------------------------------------------------

SCOPE_MIX_AMOUNT_OVER_CEILING = 0.30
SCOPE_MIX_MERCHANT_NOT_ALLOWED = 0.15
SCOPE_MIX_CATEGORY_MISMATCH = 0.20
SCOPE_MIX_ITEM_CATEGORY_MISMATCH = 0.15
SCOPE_MIX_WINDOW_EDGE = 0.20

# Boundary hardness for over-ceiling violations: the overshoot is drawn from
# this multiplier range, so a violation typically sits fractions of a percent
# past the limit rather than at an obvious multiple of it. A detector that
# only catches 10x overshoots would report excellent recall here and fail in
# production; this range is what stops that from happening.
MIN_CEILING_OVERSHOOT = Decimal("1.0005")
MAX_CEILING_OVERSHOOT = Decimal("1.0400")

# How far past the mandate's valid_until a window-edge violation sits. Minutes,
# not days, for the same boundary-hardness reason.
MIN_WINDOW_OVERSHOOT_MINUTES = 2
MAX_WINDOW_OVERSHOOT_MINUTES = 240

# --- Class 3: agent impersonation --------------------------------------------

# BEHAVIORAL_ONLY is the rules-invisible variant: an impersonating client that
# has obtained a genuine, in-scope mandate and transacts entirely within it,
# betrayed only by how the session is driven. It is weighted heavily on
# purpose - impersonation that fails a signature check is the easy half of the
# class and over-weighting it would inflate the rules baseline's recall.
IMPERSONATION_MIX_UNREGISTERED_KEY = 0.25
IMPERSONATION_MIX_FORGED_SIGNATURE = 0.15
IMPERSONATION_MIX_AGENT_BINDING_MISMATCH = 0.15
IMPERSONATION_MIX_BEHAVIORAL_ONLY = 0.45

# Event pacing for a scripted client. Legitimate sessions jitter 2-45s between
# lifecycle stages; a scripted one is faster and far more regular. The ranges
# overlap the legitimate floor deliberately so the two distributions are not
# linearly separable on a single timing feature. Widened to 1-20s (rather
# than a narrower fast-only band) so the upper end of scripted pacing sits
# well inside legitimate territory - a model that separates this class has
# to use more than raw speed.
MIN_SCRIPTED_EVENT_GAP_SECONDS = 1
MAX_SCRIPTED_EVENT_GAP_SECONDS = 20

# Probability a behavioral-only impersonation skips the catalog-browse stage
# entirely (a scripted client that already knows the SKU it wants). Held
# below 0.5 so browse-skipping is a minority pattern within the class, not a
# majority one - an always-or-mostly-present marker would still function as
# a near-single-rule giveaway even at less than 1.0.
SKIP_BROWSE_PROBABILITY = 0.35

# Sub-variant identifiers, defined here rather than in each generator so the
# variant mix weights below and the generators that consume them cannot drift
# apart on a renamed string. The generators re-export these names.
VARIANT_EXPIRED = "expired"
VARIANT_BUDGET_EXHAUSTED = "budget_exhausted"
VARIANT_RAPID_REUSE = "rapid_reuse"

VARIANT_AMOUNT_OVER_CEILING = "amount_over_ceiling"
VARIANT_MERCHANT_NOT_ALLOWED = "merchant_not_allowed"
VARIANT_CATEGORY_MISMATCH = "category_mismatch"
VARIANT_ITEM_CATEGORY_MISMATCH = "item_category_mismatch"
VARIANT_WINDOW_EDGE = "window_edge"

VARIANT_UNREGISTERED_KEY = "unregistered_key"
VARIANT_FORGED_SIGNATURE = "forged_signature"
VARIANT_AGENT_BINDING_MISMATCH = "agent_binding_mismatch"
VARIANT_BEHAVIORAL_ONLY = "behavioral_only"

# The two variants no deterministic rule can see. Named as a set because the
# evaluation reports them separately from the rules-visible ones: they are the
# only variants where Layer 3 can change an outcome, so an aggregate that
# blends them with the rest hides the number that matters.
RULES_INVISIBLE_VARIANTS: frozenset[str] = frozenset({VARIANT_RAPID_REUSE, VARIANT_BEHAVIORAL_ONLY})


# Mapping is invariant in its key type, so the class mix (keyed by AttackClass)
# and the variant mixes (keyed by str) need a type variable to share one check.
_MixKeyT = TypeVar("_MixKeyT")


def _check_mix(label: str, mix: Mapping[_MixKeyT, float]) -> None:
    """Rejects a class or variant weight map that cannot be sampled from.

    Args:
        label: Human-readable name of the mix, for the error message.
        mix: Choice to relative weight.

    Raises:
        ValueError: If any weight is negative or the weights sum to zero.
    """
    negative = {name: weight for name, weight in mix.items() if weight < 0}
    if negative:
        raise ValueError(f"{label}: weights must be non-negative, got {negative}")
    if sum(mix.values()) <= 0:
        raise ValueError(f"{label}: weights must sum to a positive value, got {dict(mix)}")


@dataclass(frozen=True)
class AttackConfig:
    """Every tunable parameter of the three training-class attack generators.

    Field defaults are the module-level constants above, so `AttackConfig()`
    reproduces the attack generators' established behaviour byte-for-byte. It
    exists for the same reason as `GeneratorConfig`: the sensitivity analysis
    has to re-run generation under perturbed variant mixes and pacing bounds,
    and the generators bind these constants by name at import time, which puts
    them out of a caller's reach.

    Scope note: the held-out class (mandate chaining / privilege escalation)
    has no field here, exactly as it has no constant above. Adding one would
    be the first step toward tuning against it.

    Attributes:
        attack_base_rate: Target fraction of a corpus that is attack traffic.
        class_mix_mandate_replay: Relative share of attack traffic assigned
            to mandate replay.
        class_mix_scope_violation: Relative share assigned to scope violation.
        class_mix_agent_impersonation: Relative share assigned to agent
            impersonation.
        replay_mix_expired: Within replay, relative weight of the expired
            variant.
        replay_mix_budget_exhausted: Relative weight of budget exhaustion.
        replay_mix_rapid_reuse: Relative weight of the rules-invisible
            rapid-reuse variant. The primary lever for class-1 hardness.
        min_expired_replay_lag_hours: Lower bound on how long after expiry an
            expired replay is attempted.
        max_expired_replay_lag_hours: Upper bound on the same.
        min_rapid_reuse_gap_seconds: Lower bound on the gap between a
            mandate's last legitimate use and a rapid-reuse replay.
        max_rapid_reuse_gap_seconds: Upper bound on the same.
        scope_mix_amount_over_ceiling: Relative weight of over-ceiling amounts
            within scope violation.
        scope_mix_merchant_not_allowed: Relative weight of wrong-merchant.
        scope_mix_category_mismatch: Relative weight of wrong merchant
            category.
        scope_mix_item_category_mismatch: Relative weight of wrong item
            category.
        scope_mix_window_edge: Relative weight of out-of-window.
        min_ceiling_overshoot: Lower bound on the multiplier a violating
            amount exceeds the mandate ceiling by.
        max_ceiling_overshoot: Upper bound on the same. Kept close to 1 so
            violations sit at the boundary rather than at an obvious multiple
            of the limit.
        min_window_overshoot_minutes: Lower bound on how far past
            `valid_until` a window-edge violation sits.
        max_window_overshoot_minutes: Upper bound on the same.
        impersonation_mix_unregistered_key: Relative weight of a self-signed
            mandate from an unregistered key.
        impersonation_mix_forged_signature: Relative weight of a forged
            signature.
        impersonation_mix_agent_binding_mismatch: Relative weight of
            presenting another agent's genuine mandate.
        impersonation_mix_behavioral_only: Relative weight of the
            rules-invisible behavioral-only variant. The primary lever for
            class-3 hardness.
        min_scripted_event_gap_seconds: Lower bound on a scripted client's
            inter-event pacing.
        max_scripted_event_gap_seconds: Upper bound on the same. Deliberately
            overlapping the legitimate jitter range; see
            `docs/adr/0001-attack-variant-hardness.md`.
        skip_browse_probability: Probability a behavioral-only impersonation
            skips the catalog-browse stage.

    Raises:
        ValueError: If `attack_base_rate` or `skip_browse_probability` falls
            outside its valid range, if any mix weight is negative, if any mix
            sums to zero (leaving a class or variant unreachable while still
            being reported with an undefined recall), if any bound pair is
            inverted, or if `min_ceiling_overshoot` does not exceed 1.
    """

    attack_base_rate: float = DEFAULT_ATTACK_BASE_RATE

    class_mix_mandate_replay: float = CLASS_MIX_MANDATE_REPLAY
    class_mix_scope_violation: float = CLASS_MIX_SCOPE_VIOLATION
    class_mix_agent_impersonation: float = CLASS_MIX_AGENT_IMPERSONATION

    replay_mix_expired: float = REPLAY_MIX_EXPIRED
    replay_mix_budget_exhausted: float = REPLAY_MIX_BUDGET_EXHAUSTED
    replay_mix_rapid_reuse: float = REPLAY_MIX_RAPID_REUSE
    min_expired_replay_lag_hours: int = MIN_EXPIRED_REPLAY_LAG_HOURS
    max_expired_replay_lag_hours: int = MAX_EXPIRED_REPLAY_LAG_HOURS
    min_rapid_reuse_gap_seconds: int = MIN_RAPID_REUSE_GAP_SECONDS
    max_rapid_reuse_gap_seconds: int = MAX_RAPID_REUSE_GAP_SECONDS

    scope_mix_amount_over_ceiling: float = SCOPE_MIX_AMOUNT_OVER_CEILING
    scope_mix_merchant_not_allowed: float = SCOPE_MIX_MERCHANT_NOT_ALLOWED
    scope_mix_category_mismatch: float = SCOPE_MIX_CATEGORY_MISMATCH
    scope_mix_item_category_mismatch: float = SCOPE_MIX_ITEM_CATEGORY_MISMATCH
    scope_mix_window_edge: float = SCOPE_MIX_WINDOW_EDGE
    min_ceiling_overshoot: Decimal = MIN_CEILING_OVERSHOOT
    max_ceiling_overshoot: Decimal = MAX_CEILING_OVERSHOOT
    min_window_overshoot_minutes: int = MIN_WINDOW_OVERSHOOT_MINUTES
    max_window_overshoot_minutes: int = MAX_WINDOW_OVERSHOOT_MINUTES

    impersonation_mix_unregistered_key: float = IMPERSONATION_MIX_UNREGISTERED_KEY
    impersonation_mix_forged_signature: float = IMPERSONATION_MIX_FORGED_SIGNATURE
    impersonation_mix_agent_binding_mismatch: float = IMPERSONATION_MIX_AGENT_BINDING_MISMATCH
    impersonation_mix_behavioral_only: float = IMPERSONATION_MIX_BEHAVIORAL_ONLY
    min_scripted_event_gap_seconds: int = MIN_SCRIPTED_EVENT_GAP_SECONDS
    max_scripted_event_gap_seconds: int = MAX_SCRIPTED_EVENT_GAP_SECONDS
    skip_browse_probability: float = SKIP_BROWSE_PROBABILITY

    def __post_init__(self) -> None:
        """Validates the parameter set at construction time.

        Raises:
            ValueError: If any invariant in the class docstring is violated.
        """
        if not 0.0 < self.attack_base_rate < 1.0:
            raise ValueError(f"attack_base_rate must be in (0, 1), got {self.attack_base_rate}")
        check_probability("skip_browse_probability", self.skip_browse_probability)
        _check_mix("class mix", self.class_mix)
        _check_mix("replay variant mix", self.replay_variant_mix)
        _check_mix("scope-violation variant mix", self.scope_variant_mix)
        _check_mix("impersonation variant mix", self.impersonation_variant_mix)
        check_ordered(
            "expired replay lag hours",
            self.min_expired_replay_lag_hours,
            self.max_expired_replay_lag_hours,
        )
        check_ordered(
            "rapid reuse gap seconds",
            self.min_rapid_reuse_gap_seconds,
            self.max_rapid_reuse_gap_seconds,
        )
        check_ordered(
            "ceiling overshoot",
            float(self.min_ceiling_overshoot),
            float(self.max_ceiling_overshoot),
        )
        check_ordered(
            "window overshoot minutes",
            self.min_window_overshoot_minutes,
            self.max_window_overshoot_minutes,
        )
        check_ordered(
            "scripted event gap seconds",
            self.min_scripted_event_gap_seconds,
            self.max_scripted_event_gap_seconds,
        )
        if self.min_ceiling_overshoot <= 1:
            raise ValueError(
                f"min_ceiling_overshoot must exceed 1 or the 'violation' stays inside the "
                f"ceiling, got {self.min_ceiling_overshoot}"
            )

    @property
    def class_mix(self) -> dict[AttackClass, float]:
        """Maps each training attack class to its relative share.

        Returns:
            Attack class to weight, in the canonical class order. Never
            includes the held-out class.
        """
        return {
            AttackClass.MANDATE_REPLAY: self.class_mix_mandate_replay,
            AttackClass.SCOPE_VIOLATION: self.class_mix_scope_violation,
            AttackClass.AGENT_IMPERSONATION: self.class_mix_agent_impersonation,
        }

    @property
    def replay_variant_mix(self) -> dict[str, float]:
        """Maps each mandate-replay variant to its relative weight.

        Returns:
            Variant name to weight, in the generator's canonical order.
        """
        return {
            VARIANT_EXPIRED: self.replay_mix_expired,
            VARIANT_BUDGET_EXHAUSTED: self.replay_mix_budget_exhausted,
            VARIANT_RAPID_REUSE: self.replay_mix_rapid_reuse,
        }

    @property
    def scope_variant_mix(self) -> dict[str, float]:
        """Maps each scope-violation variant to its relative weight.

        Returns:
            Variant name to weight, in the generator's canonical order.
        """
        return {
            VARIANT_AMOUNT_OVER_CEILING: self.scope_mix_amount_over_ceiling,
            VARIANT_MERCHANT_NOT_ALLOWED: self.scope_mix_merchant_not_allowed,
            VARIANT_CATEGORY_MISMATCH: self.scope_mix_category_mismatch,
            VARIANT_ITEM_CATEGORY_MISMATCH: self.scope_mix_item_category_mismatch,
            VARIANT_WINDOW_EDGE: self.scope_mix_window_edge,
        }

    @property
    def impersonation_variant_mix(self) -> dict[str, float]:
        """Maps each agent-impersonation variant to its relative weight.

        Returns:
            Variant name to weight, in the generator's canonical order.
        """
        return {
            VARIANT_UNREGISTERED_KEY: self.impersonation_mix_unregistered_key,
            VARIANT_FORGED_SIGNATURE: self.impersonation_mix_forged_signature,
            VARIANT_AGENT_BINDING_MISMATCH: self.impersonation_mix_agent_binding_mismatch,
            VARIANT_BEHAVIORAL_ONLY: self.impersonation_mix_behavioral_only,
        }

    def params_digest(self) -> str:
        """Hashes this parameter set into a stable identifier.

        Returns:
            A hex SHA-256 digest of a canonical JSON encoding of every field.
        """
        return digest_payload({"attack": asdict(self)})


DEFAULT_ATTACK_CONFIG = AttackConfig()


def combined_params_digest(generator_config: GeneratorConfig, attack_config: AttackConfig) -> str:
    """Hashes a generator and an attack parameter set together.

    A corpus is defined by both halves, so the sensitivity analysis needs one
    identifier covering both rather than two that each miss half the change.

    Args:
        generator_config: The legitimate-traffic parameters in effect.
        attack_config: The attack-generation parameters in effect.

    Returns:
        A hex SHA-256 digest over both parameter sets.
    """
    return digest_payload({"generator": asdict(generator_config), "attack": asdict(attack_config)})
