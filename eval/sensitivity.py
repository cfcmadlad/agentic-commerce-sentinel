"""Sensitivity of the headline result to the generator's own parameters.

Every number this project reports was measured on synthetic traffic, which
means every number is conditional on the parameters that produced that
traffic. The honest question is not whether the model performs well at one
parameter setting -- it does, and that is Milestone A's result -- but how much
of that performance survives the setting being wrong. This module answers it by
regenerating the corpus, retraining Layer 3, and re-evaluating from scratch at
each point of a parameter grid, then reporting how far the headline numbers
move.

Grid design
-----------
One factor at a time, three levels each: the established value plus a lower and
a higher perturbation. The alternative, a full factorial, would capture
interactions between factors but at this budget would cover fewer factors, and
the question a reviewer actually asks is "which single assumption is this
result most fragile to" -- which is what a one-factor-at-a-time design isolates
and a factorial design blurs. That the design cannot see interactions is a
stated limitation, not an oversight.

The six factors are the ones the evaluation brief names: the amount
distribution's location and spread, the variant mix weights for each of the two
rules-invisible attack variants, and the scripted client's pacing bound and
browse-skip probability. The last three are the levers
`docs/adr/0001-attack-variant-hardness.md` records a deliberate decision about,
so they are exactly where a reviewer should expect the result to be sensitive,
and exactly where refusing to look would be self-serving.

Reading the output
------------------
A degradation is reported, never suppressed. `SensitivityReport.worst_case`
picks out the grid point where the ensemble's AUC-PR falls furthest below the
established setting, and that point is reported whether or not it is
comfortable. A result that holds only at one parameter setting is a result
about that setting, and saying so is the point of running this.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from decimal import Decimal

import numpy as np

from generator.attack_config import (
    DEFAULT_ATTACK_CONFIG,
    RULES_INVISIBLE_VARIANTS,
    AttackConfig,
)
from generator.config import DEFAULT_GENERATOR_CONFIG, CategoryConfig, GeneratorConfig

logger = logging.getLogger(__name__)

BASELINE_POINT_NAME = "established_setting"

# Multipliers applied to every category's median amount and log-normal spread.
# Chosen to span a plausible disagreement about basket sizes rather than an
# extreme one: halving or doubling median order value covers the spread between
# the market reports `generator/config.py` cites, which is the actual
# uncertainty in play.
AMOUNT_MEDIAN_SCALES: tuple[float, ...] = (0.5, 2.0)
AMOUNT_SIGMA_SCALES: tuple[float, ...] = (0.7, 1.4)

# Alternative weights for the two rules-invisible variants. The established
# values are 0.40 (rapid reuse, within replay) and 0.45 (behavioral only,
# within impersonation); these bracket them roughly symmetrically.
RAPID_REUSE_WEIGHTS: tuple[float, ...] = (0.20, 0.60)
BEHAVIORAL_ONLY_WEIGHTS: tuple[float, ...] = (0.25, 0.65)

# Scripted-client pacing upper bound, in seconds. The established value is 20,
# widened from 6 by ADR 0001 specifically to overlap legitimate jitter. Level
# 10 partially reverts that decision and level 35 pushes scripted pacing
# entirely inside the legitimate 2-45s range, which should be the hardest
# setting for the model.
SCRIPTED_PACING_UPPER_BOUNDS: tuple[int, ...] = (10, 35)

# Browse-skip probability for behavioral-only impersonation. The established
# value is 0.35; 0.10 makes the marker nearly absent, 0.60 makes it a majority
# pattern and therefore an easier giveaway.
SKIP_BROWSE_PROBABILITIES: tuple[float, ...] = (0.10, 0.60)


@dataclass(frozen=True)
class GridPoint:
    """One parameter setting to evaluate.

    Attributes:
        name: Short identifier naming the factor and its level.
        factor: The factor being varied, so results can be grouped by it.
        description: What was changed, relative to the established setting.
        generator_config: Legitimate-traffic parameters for this point.
        attack_config: Attack-generation parameters for this point.
    """

    name: str
    factor: str
    description: str
    generator_config: GeneratorConfig
    attack_config: AttackConfig


@dataclass(frozen=True)
class GridOutcome:
    """The headline numbers measured at one grid point.

    Attributes:
        point: The parameter setting evaluated.
        params_digest: Digest of both configs, identifying the corpus.
        n_sessions: Corpus size.
        attack_base_rate: Realized attack fraction.
        baseline_precision: Rules-only precision on the test block.
        baseline_recall: Rules-only recall on the test block.
        ensemble_precision: Ensemble precision on the test block.
        ensemble_recall: Ensemble recall on the test block.
        ensemble_auc_pr: Ensemble AUC-PR on the test block. The headline the
            sensitivity of which this module exists to report.
        baseline_auc_pr: Rules-only AUC-PR on the same rows, for context.
        rules_invisible_recall: Ensemble recall restricted to the two variants
            no deterministic rule can catch -- the variants Layer 3 exists for,
            and the ones a parameter change is most likely to move.
        threshold: The calibrated operating threshold at this point.
        beats_baseline: Whether the ensemble significantly outperformed the
            rules-only baseline here.
    """

    point: GridPoint
    params_digest: str
    n_sessions: int
    attack_base_rate: float
    baseline_precision: float
    baseline_recall: float
    ensemble_precision: float
    ensemble_recall: float
    ensemble_auc_pr: float
    baseline_auc_pr: float
    rules_invisible_recall: float
    threshold: float
    beats_baseline: bool


@dataclass(frozen=True)
class SensitivityReport:
    """Outcomes across the whole grid, relative to the established setting.

    Attributes:
        baseline_outcome: The established setting's outcome, the reference
            every delta is measured against.
        outcomes: Every perturbed grid point's outcome, in grid order.
    """

    baseline_outcome: GridOutcome
    outcomes: tuple[GridOutcome, ...]

    @property
    def all_outcomes(self) -> tuple[GridOutcome, ...]:
        """Every evaluated point, established setting first.

        Returns:
            The full grid, so summaries do not have to special-case the
            reference point.
        """
        return (self.baseline_outcome, *self.outcomes)

    @property
    def worst_case(self) -> GridOutcome:
        """The grid point with the lowest ensemble AUC-PR.

        Includes the established setting, so a grid whose perturbations all
        improve on it still reports a real worst case rather than an empty
        one. Reported regardless of whether it is flattering; a robustness
        check that only surfaces good news is not a robustness check.

        Returns:
            The worst outcome measured across the whole grid.
        """
        return min(self.all_outcomes, key=lambda outcome: outcome.ensemble_auc_pr)

    @property
    def auc_pr_range(self) -> tuple[float, float]:
        """Lowest and highest ensemble AUC-PR across the grid.

        Returns:
            A (minimum, maximum) tuple over every point including the
            established setting.
        """
        values = [outcome.ensemble_auc_pr for outcome in self.all_outcomes]
        return min(values), max(values)

    @property
    def holds_everywhere(self) -> bool:
        """Whether the ensemble beat the baseline at every grid point.

        Returns:
            True only if `beats_baseline` held at the established setting and
            at every perturbation of it.
        """
        return self.baseline_outcome.beats_baseline and all(
            outcome.beats_baseline for outcome in self.outcomes
        )

    def delta_auc_pr(self, outcome: GridOutcome) -> float:
        """Change in ensemble AUC-PR relative to the established setting.

        Args:
            outcome: The grid point to compare.

        Returns:
            `outcome.ensemble_auc_pr - baseline_outcome.ensemble_auc_pr`.
        """
        return outcome.ensemble_auc_pr - self.baseline_outcome.ensemble_auc_pr


def scale_category_amounts(
    categories: tuple[CategoryConfig, ...], median_scale: float, sigma_scale: float
) -> tuple[CategoryConfig, ...]:
    """Rescales every category's amount distribution by fixed multipliers.

    Scales rather than replaces, so the relative ordering between categories --
    electronics well above grocery, and so on -- is preserved. A perturbation
    that flattened that ordering would be testing a different generator, not a
    different parameterisation of this one.

    Args:
        categories: The categories to rescale.
        median_scale: Multiplier applied to each `amount_median`.
        sigma_scale: Multiplier applied to each `amount_sigma`.

    Returns:
        The rescaled categories, in the input order.

    Raises:
        ValueError: If either scale is not positive.
    """
    if median_scale <= 0 or sigma_scale <= 0:
        raise ValueError(
            f"amount scales must be positive, got median={median_scale} sigma={sigma_scale}"
        )
    return tuple(
        replace(
            category,
            amount_median=(category.amount_median * Decimal(str(median_scale))).quantize(
                Decimal("0.01")
            ),
            amount_sigma=category.amount_sigma * sigma_scale,
        )
        for category in categories
    )


def rebalance_mix(weights: dict[str, float], key: str, target: float) -> dict[str, float]:
    """Sets one weight in a mix and rescales the rest to keep the total fixed.

    Raising one variant's share has to come out of the others, and taking it
    proportionally rather than from one arbitrary sibling keeps the
    perturbation a change in that one variant's prevalence rather than a
    simultaneous change in the ratio between the remaining ones.

    Args:
        weights: The mix to adjust. Must be non-empty and sum to a positive.
        key: The weight to set. Must be present in `weights`.
        target: The new value for that weight.

    Returns:
        A new mix with `key` at `target` and the same total as the input.

    Raises:
        ValueError: If `key` is absent, if `target` is negative, if `target`
            exceeds the original total (leaving nothing for the others), or if
            the remaining weights sum to zero and so cannot absorb the change.
    """
    if key not in weights:
        raise ValueError(f"{key!r} is not in the mix {sorted(weights)}")
    if target < 0:
        raise ValueError(f"target weight must not be negative, got {target}")

    total = sum(weights.values())
    remaining_total = total - weights[key]
    if target > total:
        raise ValueError(f"target {target} exceeds the mix total {total}")
    if remaining_total <= 0:
        raise ValueError(f"mix {weights} has no other weight to absorb the change")

    scale = (total - target) / remaining_total
    return {
        name: target if name == key else weight * scale for name, weight in weights.items()
    }


def _replay_mix_point(weight: float) -> AttackConfig:
    """Builds an attack config with a given rapid-reuse share.

    Args:
        weight: Target weight for the rapid-reuse variant within replay.

    Returns:
        The perturbed attack config.
    """
    mix = rebalance_mix(DEFAULT_ATTACK_CONFIG.replay_variant_mix, "rapid_reuse", weight)
    return replace(
        DEFAULT_ATTACK_CONFIG,
        replay_mix_expired=mix["expired"],
        replay_mix_budget_exhausted=mix["budget_exhausted"],
        replay_mix_rapid_reuse=mix["rapid_reuse"],
    )


def _impersonation_mix_point(weight: float) -> AttackConfig:
    """Builds an attack config with a given behavioral-only share.

    Args:
        weight: Target weight for the behavioral-only variant within
            impersonation.

    Returns:
        The perturbed attack config.
    """
    mix = rebalance_mix(
        DEFAULT_ATTACK_CONFIG.impersonation_variant_mix, "behavioral_only", weight
    )
    return replace(
        DEFAULT_ATTACK_CONFIG,
        impersonation_mix_unregistered_key=mix["unregistered_key"],
        impersonation_mix_forged_signature=mix["forged_signature"],
        impersonation_mix_agent_binding_mismatch=mix["agent_binding_mismatch"],
        impersonation_mix_behavioral_only=mix["behavioral_only"],
    )


def build_grid() -> tuple[GridPoint, ...]:
    """Constructs the one-factor-at-a-time sensitivity grid.

    Returns:
        The established setting first, then two perturbations of each of the
        six factors, in a stable order.
    """
    points: list[GridPoint] = [
        GridPoint(
            name=BASELINE_POINT_NAME,
            factor="none",
            description="the parameter set every reported headline number was measured under",
            generator_config=DEFAULT_GENERATOR_CONFIG,
            attack_config=DEFAULT_ATTACK_CONFIG,
        )
    ]

    for scale in AMOUNT_MEDIAN_SCALES:
        points.append(
            GridPoint(
                name=f"amount_median_x{scale:g}",
                factor="amount_median",
                description=f"every category median order value scaled by {scale:g}",
                generator_config=replace(
                    DEFAULT_GENERATOR_CONFIG,
                    categories=scale_category_amounts(
                        DEFAULT_GENERATOR_CONFIG.categories, scale, 1.0
                    ),
                ),
                attack_config=DEFAULT_ATTACK_CONFIG,
            )
        )

    for scale in AMOUNT_SIGMA_SCALES:
        points.append(
            GridPoint(
                name=f"amount_sigma_x{scale:g}",
                factor="amount_sigma",
                description=f"every category amount spread scaled by {scale:g}",
                generator_config=replace(
                    DEFAULT_GENERATOR_CONFIG,
                    categories=scale_category_amounts(
                        DEFAULT_GENERATOR_CONFIG.categories, 1.0, scale
                    ),
                ),
                attack_config=DEFAULT_ATTACK_CONFIG,
            )
        )

    for weight in RAPID_REUSE_WEIGHTS:
        points.append(
            GridPoint(
                name=f"rapid_reuse_w{weight:g}",
                factor="rapid_reuse_mix",
                description=f"rapid-reuse share of replay traffic set to {weight:g}",
                generator_config=DEFAULT_GENERATOR_CONFIG,
                attack_config=_replay_mix_point(weight),
            )
        )

    for weight in BEHAVIORAL_ONLY_WEIGHTS:
        points.append(
            GridPoint(
                name=f"behavioral_only_w{weight:g}",
                factor="behavioral_only_mix",
                description=f"behavioral-only share of impersonation set to {weight:g}",
                generator_config=DEFAULT_GENERATOR_CONFIG,
                attack_config=_impersonation_mix_point(weight),
            )
        )

    for bound in SCRIPTED_PACING_UPPER_BOUNDS:
        points.append(
            GridPoint(
                name=f"scripted_pacing_max{bound}",
                factor="scripted_pacing",
                description=f"scripted-client inter-event gap upper bound set to {bound}s",
                generator_config=DEFAULT_GENERATOR_CONFIG,
                attack_config=replace(
                    DEFAULT_ATTACK_CONFIG, max_scripted_event_gap_seconds=bound
                ),
            )
        )

    for probability in SKIP_BROWSE_PROBABILITIES:
        points.append(
            GridPoint(
                name=f"skip_browse_p{probability:g}",
                factor="skip_browse",
                description=f"browse-skip probability set to {probability:g}",
                generator_config=DEFAULT_GENERATOR_CONFIG,
                attack_config=replace(
                    DEFAULT_ATTACK_CONFIG, skip_browse_probability=probability
                ),
            )
        )

    return tuple(points)


def evaluate_grid(
    n_legitimate: int,
    seed: int,
    evaluator: Callable[[GridPoint], GridOutcome],
    grid: tuple[GridPoint, ...] | None = None,
) -> SensitivityReport:
    """Evaluates every grid point and assembles the report.

    The per-point evaluation is injected rather than performed here, so this
    module owns the grid design and nothing else: the full metric computation
    lives in `eval/milestone_b.py`, and importing it here would make the two
    mutually dependent.

    Args:
        n_legitimate: Legitimate sessions per grid point, recorded for the
            report's provenance rather than used directly here.
        seed: Corpus seed shared by every grid point, so differences between
            points come from the parameters and not from the draw.
        evaluator: Produces the outcome for one grid point.
        grid: The grid to evaluate. Defaults to `build_grid()`.

    Returns:
        The assembled report.

    Raises:
        ValueError: If the grid is empty or does not begin with the
            established setting, which every delta is measured against.
    """
    points = build_grid() if grid is None else grid
    if not points:
        raise ValueError("sensitivity grid must be non-empty")
    if points[0].name != BASELINE_POINT_NAME:
        raise ValueError(
            f"grid must begin with {BASELINE_POINT_NAME!r}, got {points[0].name!r}"
        )

    logger.info(
        "sensitivity: evaluating %d grid points at n_legitimate=%d seed=%d",
        len(points),
        n_legitimate,
        seed,
    )
    outcomes = [evaluator(point) for point in points]
    return SensitivityReport(baseline_outcome=outcomes[0], outcomes=tuple(outcomes[1:]))


def rules_invisible_recall(
    corpus_variants: dict[str, tuple[int, int]],
) -> float:
    """Aggregates recall over the two variants no deterministic rule can catch.

    Args:
        corpus_variants: Variant name to a (caught, total) pair.

    Returns:
        Combined recall across the rules-invisible variants, or 0.0 if none
        were generated.
    """
    caught = sum(
        pair[0] for name, pair in corpus_variants.items() if name in RULES_INVISIBLE_VARIANTS
    )
    total = sum(
        pair[1] for name, pair in corpus_variants.items() if name in RULES_INVISIBLE_VARIANTS
    )
    return caught / total if total else 0.0


def format_sensitivity_report(report: SensitivityReport) -> str:
    """Renders a sensitivity report as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary, worst case called out explicitly.
    """
    baseline = report.baseline_outcome
    low, high = report.auc_pr_range
    lines = [
        "Sensitivity to generator parameters "
        f"(one factor at a time, {len(report.outcomes) + 1} grid points)",
        f"  established setting: AUC-PR {baseline.ensemble_auc_pr:.4f}, "
        f"ensemble recall {baseline.ensemble_recall:.4f}, "
        f"rules-invisible recall {baseline.rules_invisible_recall:.4f}",
        f"  AUC-PR across the grid: {low:.4f} to {high:.4f} (spread {high - low:.4f})",
        f"  ensemble beat the baseline at every grid point: {report.holds_everywhere}",
        "",
        "  grid point                     AUC-PR   delta   ens_recall  invis_recall  beats",
    ]
    for outcome in report.outcomes:
        lines.append(
            f"  {outcome.point.name:<28} {outcome.ensemble_auc_pr:>7.4f} "
            f"{report.delta_auc_pr(outcome):>+7.4f} {outcome.ensemble_recall:>11.4f} "
            f"{outcome.rules_invisible_recall:>13.4f}  {str(outcome.beats_baseline):<5}"
        )

    worst = report.worst_case
    lines.extend(
        [
            "",
            f"  Worst case: {worst.point.name} "
            f"({worst.point.description})",
            f"    AUC-PR {worst.ensemble_auc_pr:.4f} "
            f"({report.delta_auc_pr(worst):+.4f} vs the established setting), "
            f"rules-invisible recall {worst.rules_invisible_recall:.4f}",
        ]
    )
    return "\n".join(lines)


def summarize_variant_counts(
    caught: np.ndarray, variants: list[str]
) -> dict[str, tuple[int, int]]:
    """Counts caught and total attacks per sub-variant.

    Args:
        caught: Per-row block/allow array.
        variants: Sub-variant name per row, aligned with `caught`.

    Returns:
        Variant name to a (caught, total) pair.

    Raises:
        ValueError: If `caught` and `variants` have different lengths, which
            would silently misattribute catches to the wrong variant.
    """
    if len(caught) != len(variants):
        raise ValueError(f"caught has {len(caught)} rows but variants has {len(variants)}")
    counts: dict[str, tuple[int, int]] = {}
    for blocked, variant in zip(caught, variants, strict=True):
        hit, total = counts.get(variant, (0, 0))
        counts[variant] = (hit + int(bool(blocked)), total + 1)
    return counts
