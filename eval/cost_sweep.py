"""Full-range threshold sweep of the operational cost of the Layer 3 score.

`detect/calibration.py` answers one question -- which threshold minimises
expected cost -- and reports the answer at a handful of cost ratios. That is
the right output for choosing an operating point, and the wrong output for
understanding one: a single minimising threshold hides whether the cost curve
is a sharp valley (where being slightly wrong about the cost ratio is
expensive) or a broad basin (where it barely matters).

This module sweeps the entire threshold range instead, reporting at every step
the quantities a payments team would actually be handed:

- **Blocked legitimate sessions per 10,000 sessions.** A raw operational rate,
  not a modelled cost. It needs no assumption to compute and is the number a
  merchant-facing team feels directly.
- **Missed attacks per 10,000 sessions**, the same quantity for the other
  error.
- **Expected cost in false-positive-cost units**, carried over unchanged from
  `detect/calibration.py`: false positives count 1.0 each, false negatives
  count `cost_ratio` each.

The cost figure is deliberately left in false-positive-cost units rather than
converted to rupees. Converting would require an assumed cost per manual
review and an assumed loss per wrongly blocked basket, and this project has
measured neither. Reporting a rupee figure built on two unmeasured constants
would look more precise than the underlying evidence supports, while the
unit-free form carries exactly one assumption -- the false-negative-to-
false-positive cost ratio -- which `detect/calibration.py` already names as an
assumption and which the sweep varies rather than fixes. The per-10,000-session
error rates are reported alongside so a reader with real figures for their own
business can do the conversion themselves, with their numbers rather than
invented ones.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

from detect.calibration import (
    DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    DEFAULT_SENSITIVITY_COST_RATIOS,
)

logger = logging.getLogger(__name__)

# Denominator the error rates are normalised to. Chosen because a payments
# team reasons in blocks per ten thousand transactions, not in per-unit rates.
SESSIONS_PER_RATE_UNIT = 10_000

# Number of thresholds swept across the closed interval [0, 1]. Finer than
# `detect.calibration.DEFAULT_THRESHOLD_GRID_SIZE` because this sweep is
# reported as a curve rather than reduced to one minimum, and a coarse grid
# would make a sharp valley look like a plateau.
DEFAULT_SWEEP_POINTS = 501


@dataclass(frozen=True)
class CostSweepPoint:
    """Operational outcome at one threshold.

    Attributes:
        threshold: Score cutoff at or above which a session is blocked.
        true_positives: Attacks blocked at this threshold.
        false_positives: Legitimate sessions blocked at this threshold.
        false_negatives: Attacks allowed through at this threshold.
        true_negatives: Legitimate sessions correctly allowed.
        precision: Of everything blocked, the fraction that was an attack.
        recall: Of every attack, the fraction blocked.
        blocked_legitimate_per_10k: False positives scaled to a per-10,000
            session rate. A raw rate, carrying no cost assumption.
        missed_attacks_per_10k: False negatives on the same scale.
        expected_cost: Total cost in false-positive-cost units at the sweep's
            cost ratio.
    """

    threshold: float
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    blocked_legitimate_per_10k: float
    missed_attacks_per_10k: float
    expected_cost: float


@dataclass(frozen=True)
class CostSweep:
    """A full-range threshold sweep at one cost ratio.

    Attributes:
        cost_ratio: The false-negative-to-false-positive cost ratio the
            `expected_cost` column was computed under. An assumption, not a
            measurement; see `detect/calibration.py`.
        n_sessions: Rows the sweep was computed over.
        n_attacks: Attack rows among them.
        points: One entry per swept threshold, in ascending threshold order.
    """

    cost_ratio: float
    n_sessions: int
    n_attacks: int
    points: tuple[CostSweepPoint, ...]

    @property
    def minimum_cost_point(self) -> CostSweepPoint:
        """The swept threshold with the lowest expected cost.

        Returns:
            The cost-minimising point. Ties resolve to the lowest threshold,
            which is the conservative choice: it blocks more, so it errs
            toward catching attacks rather than toward letting them through.
        """
        return min(self.points, key=lambda point: (point.expected_cost, point.threshold))

    def at_recall(self, target_recall: float) -> CostSweepPoint | None:
        """Finds the highest-precision point meeting a recall floor.

        Exists because "precision at fixed recall" is the comparison the
        project's gate policy is written in terms of, and reading it off a
        sweep beats recomputing it separately and risking a different
        convention.

        Args:
            target_recall: The recall floor to meet.

        Returns:
            The best-precision point achieving at least `target_recall`, or
            None if no swept threshold reaches it.
        """
        qualifying = [point for point in self.points if point.recall >= target_recall]
        if not qualifying:
            return None
        return max(qualifying, key=lambda point: (point.precision, point.threshold))


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 on an empty denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 when the denominator is zero.
    """
    return numerator / denominator if denominator else 0.0


def sweep_thresholds(
    y_true: np.ndarray,
    y_score: np.ndarray,
    cost_ratio: float = DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    n_points: int = DEFAULT_SWEEP_POINTS,
) -> CostSweep:
    """Evaluates every threshold across [0, 1] at one cost ratio.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Model scores in [0, 1].
        cost_ratio: False-negative cost divided by false-positive cost.
        n_points: Number of thresholds to evaluate, evenly spaced over [0, 1].

    Returns:
        The sweep.

    Raises:
        ValueError: If the arrays are mismatched or empty, if `cost_ratio` is
            not positive, if `n_points` is less than two, or if the rows
            contain no attacks. A sweep with no positive class reports a
            precision of zero at every threshold, which reads as a broken
            detector rather than as an unusable evaluation set.
    """
    labels = np.asarray(y_true, dtype=bool)
    scores = np.asarray(y_score, dtype=np.float64)
    if labels.shape != scores.shape:
        raise ValueError(f"y_true has shape {labels.shape} but y_score has {scores.shape}")
    if labels.size == 0:
        raise ValueError("cannot sweep thresholds over zero rows")
    if cost_ratio <= 0:
        raise ValueError(f"cost_ratio must be positive, got {cost_ratio}")
    if n_points < 2:
        raise ValueError(f"n_points must be at least 2, got {n_points}")
    n_attacks = int(labels.sum())
    if n_attacks == 0:
        raise ValueError("cannot sweep thresholds over rows containing no attacks")

    scale = SESSIONS_PER_RATE_UNIT / labels.size
    points: list[CostSweepPoint] = []
    for threshold in np.linspace(0.0, 1.0, n_points):
        blocked = scores >= threshold
        true_positives = int(np.sum(blocked & labels))
        false_positives = int(np.sum(blocked & ~labels))
        false_negatives = int(np.sum(~blocked & labels))
        true_negatives = int(labels.size - true_positives - false_positives - false_negatives)

        points.append(
            CostSweepPoint(
                threshold=float(threshold),
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                true_negatives=true_negatives,
                precision=_safe_ratio(true_positives, true_positives + false_positives),
                recall=_safe_ratio(true_positives, true_positives + false_negatives),
                blocked_legitimate_per_10k=false_positives * scale,
                missed_attacks_per_10k=false_negatives * scale,
                expected_cost=false_positives * 1.0 + false_negatives * cost_ratio,
            )
        )

    sweep = CostSweep(
        cost_ratio=cost_ratio,
        n_sessions=int(labels.size),
        n_attacks=n_attacks,
        points=tuple(points),
    )
    best = sweep.minimum_cost_point
    logger.info(
        "cost sweep at ratio %.1f: minimum cost %.1f at threshold %.4f "
        "(%.1f blocked legitimate per 10k)",
        cost_ratio,
        best.expected_cost,
        best.threshold,
        best.blocked_legitimate_per_10k,
    )
    return sweep


def sweep_across_cost_ratios(
    y_true: np.ndarray,
    y_score: np.ndarray,
    cost_ratios: tuple[float, ...] = DEFAULT_SENSITIVITY_COST_RATIOS,
    n_points: int = DEFAULT_SWEEP_POINTS,
) -> tuple[CostSweep, ...]:
    """Runs the full threshold sweep at each of several cost ratios.

    The error counts do not depend on the cost ratio, only the cost column
    does, so this shows exactly how much of the recommended operating point is
    driven by the cost assumption rather than by the model.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Model scores in [0, 1].
        cost_ratios: Ratios to sweep. Must be non-empty.
        n_points: Number of thresholds per sweep.

    Returns:
        One sweep per ratio, in the given order.

    Raises:
        ValueError: If `cost_ratios` is empty, or as propagated from
            `sweep_thresholds`.
    """
    if not cost_ratios:
        raise ValueError("cost_ratios must be non-empty")
    return tuple(
        sweep_thresholds(y_true, y_score, cost_ratio=ratio, n_points=n_points)
        for ratio in cost_ratios
    )


def format_cost_sweep(sweep: CostSweep, every_n: int = 25) -> str:
    """Renders a sweep as a plain-text table, thinned for readability.

    Args:
        sweep: The sweep to render.
        every_n: Print every nth swept point. The cost-minimising point is
            always included regardless of where it falls.

    Returns:
        A human-readable multi-line table.

    Raises:
        ValueError: If `every_n` is not positive.
    """
    if every_n <= 0:
        raise ValueError(f"every_n must be positive, got {every_n}")

    best = sweep.minimum_cost_point
    selected = {
        index
        for index, point in enumerate(sweep.points)
        if index % every_n == 0 or point is best or index == len(sweep.points) - 1
    }

    lines = [
        f"Cost sweep across the full threshold range (cost_ratio={sweep.cost_ratio:.1f}, "
        f"{sweep.n_sessions} sessions, {sweep.n_attacks} attacks)",
        "  threshold  precision  recall   blocked_legit/10k  missed_attacks/10k  cost  ",
    ]
    for index in sorted(selected):
        point = sweep.points[index]
        marker = "  <- min cost" if point is best else ""
        lines.append(
            f"  {point.threshold:>9.3f}  {point.precision:>9.4f}  {point.recall:>6.4f}  "
            f"{point.blocked_legitimate_per_10k:>17.1f}  {point.missed_attacks_per_10k:>18.1f}  "
            f"{point.expected_cost:>6.1f}{marker}"
        )
    return "\n".join(lines)
