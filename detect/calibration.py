"""Threshold calibration for the Layer 3 score, driven by an explicit cost model.

A classifier score is not a decision. Turning it into one requires a
threshold, and the threshold that minimizes total harm depends on how a
false block (a legitimate session denied) compares in cost to a false allow
(an attack that gets through). This project has no measured figures for
either cost — no real fraud-loss data, no real support-cost data — so the
ratio below is a stated assumption, not a fact, and it is named as one.

`DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO` should be replaced the
moment real figures exist: divide an average fraud loss per undetected
attack by an average friction/support cost per wrongly blocked transaction.
Until then, `10.0` reflects the ordinary assumption in payment fraud that
letting money out the door costs more than annoying a legitimate user once,
without claiming a precise number. Because that assumption drives the
threshold, `sensitivity_sweep` reports the threshold across a range of
plausible ratios rather than committing to one silently.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

# Assumption, not measured data. See module docstring.
DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO = 10.0

# Ratios swept for the sensitivity report, spanning "barely worse than even"
# to "an order of magnitude worse than the default assumption."
DEFAULT_SENSITIVITY_COST_RATIOS: tuple[float, ...] = (1.0, 5.0, 10.0, 20.0, 30.0)

DEFAULT_THRESHOLD_GRID_SIZE = 200


@dataclass(frozen=True)
class CalibrationResult:
    """The threshold that minimizes expected cost at one cost ratio.

    Attributes:
        cost_ratio: False-negative cost divided by false-positive cost, used
            to produce this result.
        threshold: The score cutoff at or above which a session is blocked.
        expected_cost: Total cost at this threshold, in false-positive-cost
            units (false positives counted at 1.0 each, false negatives at
            `cost_ratio` each).
        precision: Precision on the calibration set at this threshold.
        recall: Recall on the calibration set at this threshold.
    """

    cost_ratio: float
    threshold: float
    expected_cost: float
    precision: float
    recall: float


def _cost_at_threshold(y_true: np.ndarray, y_score: np.ndarray, threshold: float, cost_ratio: float) -> float:
    """Computes expected cost for one threshold, in false-positive-cost units.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Model scores in [0, 1].
        threshold: The score cutoff at or above which a session is blocked.
        cost_ratio: False-negative cost divided by false-positive cost.

    Returns:
        The expected cost.
    """
    predicted_block = y_score >= threshold
    false_positives = int(np.sum(predicted_block & ~y_true))
    false_negatives = int(np.sum(~predicted_block & y_true))
    return false_positives * 1.0 + false_negatives * cost_ratio


def calibrate_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    cost_ratio: float = DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    grid_size: int = DEFAULT_THRESHOLD_GRID_SIZE,
) -> CalibrationResult:
    """Selects the threshold minimizing expected cost on a held-out set.

    Args:
        y_true: Ground-truth `is_attack` labels for the calibration set.
        y_score: Model scores in [0, 1] for the same rows.
        cost_ratio: False-negative cost divided by false-positive cost.
        grid_size: Number of threshold values to evaluate, evenly spaced
            over [0, 1].

    Returns:
        The cost-minimizing calibration result.

    Raises:
        ValueError: If `y_true` and `y_score` have mismatched lengths, if
            the calibration set contains no attacks or no legitimate
            sessions (the ratio between the two error types is then
            undefined), or if `cost_ratio` is not positive.
    """
    if len(y_true) != len(y_score):
        raise ValueError(f"y_true has {len(y_true)} rows but y_score has {len(y_score)}")
    if cost_ratio <= 0:
        raise ValueError(f"cost_ratio must be positive, got {cost_ratio}")
    y_true = np.asarray(y_true, dtype=bool)
    if not y_true.any():
        raise ValueError("calibration set contains no attack sessions; cannot calibrate a threshold")
    if y_true.all():
        raise ValueError("calibration set contains no legitimate sessions; cannot calibrate a threshold")

    grid = np.linspace(0.0, 1.0, grid_size)
    costs = np.array([_cost_at_threshold(y_true, y_score, t, cost_ratio) for t in grid])
    best_index = int(np.argmin(costs))
    best_threshold = float(grid[best_index])

    predicted_block = y_score >= best_threshold
    true_positives = int(np.sum(predicted_block & y_true))
    false_positives = int(np.sum(predicted_block & ~y_true))
    false_negatives = int(np.sum(~predicted_block & y_true))
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0

    result = CalibrationResult(
        cost_ratio=cost_ratio,
        threshold=best_threshold,
        expected_cost=float(costs[best_index]),
        precision=precision,
        recall=recall,
    )
    logger.info(
        "calibration: cost_ratio=%.1f threshold=%.4f precision=%.4f recall=%.4f",
        cost_ratio,
        result.threshold,
        precision,
        recall,
    )
    return result


def sensitivity_sweep(
    y_true: np.ndarray,
    y_score: np.ndarray,
    cost_ratios: tuple[float, ...] = DEFAULT_SENSITIVITY_COST_RATIOS,
) -> tuple[CalibrationResult, ...]:
    """Calibrates a threshold at each of several cost ratios.

    Exists so a threshold choice can be reported alongside how much it would
    change if the underlying cost assumption were wrong, rather than as a
    single unqualified number.

    Args:
        y_true: Ground-truth `is_attack` labels for the calibration set.
        y_score: Model scores in [0, 1] for the same rows.
        cost_ratios: The cost ratios to sweep over.

    Returns:
        One calibration result per ratio, in the given order.

    Raises:
        ValueError: If `cost_ratios` is empty.
    """
    if not cost_ratios:
        raise ValueError("cost_ratios must be non-empty")
    return tuple(calibrate_threshold(y_true, y_score, cost_ratio=ratio) for ratio in cost_ratios)