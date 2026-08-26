"""Threshold-free ranking metrics and probability calibration diagnostics.

AUC-PR is the primary metric here rather than AUC-ROC, and the reason is the
class balance. Attack traffic sits at a low single-digit base rate, and ROC's
false-positive rate divides by a legitimate-session count large enough to keep
the denominator almost constant: a detector can add hundreds of false blocks
and barely move the curve. Precision divides by the number of sessions the
detector actually blocked, so it degrades visibly at exactly the operating
points a payments team would care about. AUC-ROC is still reported, as the
secondary metric, because it is the quantity DeLong's test is defined over and
because it is the number most readers will look for first.

Everything here is computed directly from numpy rather than pulled from
scikit-learn, for two reasons: the bootstrap resamples these functions a
thousand times over and the per-call overhead matters, and a hand-rolled
implementation is only trustworthy if it is checked, so the tests assert exact
agreement with scikit-learn's reference implementations on random data
including tied scores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_CALIBRATION_BINS = 10


def _validate_pair(y_true: np.ndarray, y_score: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Coerces and checks a (labels, scores) pair shared by every metric here.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Per-row scores, higher meaning more attack-like.

    Returns:
        The pair as (bool array, float array).

    Raises:
        ValueError: If the arrays have mismatched lengths, are empty, or
            contain non-finite scores. A NaN score silently sorts to one end
            of the ranking and would corrupt every metric downstream of it.
    """
    labels = np.asarray(y_true, dtype=bool)
    scores = np.asarray(y_score, dtype=np.float64)
    if labels.shape != scores.shape:
        raise ValueError(f"y_true has shape {labels.shape} but y_score has {scores.shape}")
    if labels.size == 0:
        raise ValueError("cannot compute a metric over zero rows")
    if not np.isfinite(scores).all():
        raise ValueError("y_score contains non-finite values")
    return labels, scores


def average_precision(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Computes AUC-PR as the step-wise average precision.

    Uses the step-wise definition (the sum of precision at each threshold,
    weighted by the recall gained at that threshold) rather than trapezoidal
    interpolation of the precision-recall curve. Interpolation is optimistic
    on a curve this sparse in the high-precision region, and the step-wise form
    is what scikit-learn's `average_precision_score` reports, so the number is
    comparable with anything else a reader computes.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Per-row scores, higher meaning more attack-like.

    Returns:
        Average precision in [0, 1].

    Raises:
        ValueError: If the inputs are mismatched, empty, non-finite, or
            contain no positive rows. Average precision is undefined without
            a positive class, and returning 0.0 there would read as a real
            measurement of a very poor detector.
    """
    labels, scores = _validate_pair(y_true, y_score)
    n_positive = int(labels.sum())
    if n_positive == 0:
        raise ValueError("average precision is undefined with no positive rows")

    order = np.argsort(-scores, kind="stable")
    ranked = labels[order]
    sorted_scores = scores[order]

    true_positives = np.cumsum(ranked)
    predicted_positives = np.arange(1, ranked.size + 1, dtype=np.float64)

    # Rows sharing a score cannot be separated by any threshold, so the curve
    # only has a vertex at the last row of each tied block.
    last_of_tie = np.append(np.flatnonzero(np.diff(sorted_scores)), ranked.size - 1)
    precision = true_positives[last_of_tie] / predicted_positives[last_of_tie]
    recall = true_positives[last_of_tie] / n_positive

    recall_gain = np.diff(np.concatenate(([0.0], recall)))
    return float(np.sum(recall_gain * precision))


def roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Computes AUC-ROC via the midrank Mann-Whitney statistic.

    The midrank form is what makes this well defined on a score with ties,
    including the fully binary block/allow score the rules-only baseline emits:
    a tied pair contributes 0.5 rather than being dropped. On a binary score
    the result collapses to balanced accuracy, which is correct but carries far
    less information than an AUC over a genuinely ranked score -- see
    `eval/delong.py`, which relies on the same convention.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Per-row scores, higher meaning more attack-like.

    Returns:
        Area under the ROC curve, in [0, 1].

    Raises:
        ValueError: If the inputs are mismatched, empty, non-finite, or
            contain only one class. AUC is undefined without both a positive
            and a negative row to rank against each other.
    """
    labels, scores = _validate_pair(y_true, y_score)
    n_positive = int(labels.sum())
    n_negative = int(labels.size - n_positive)
    if n_positive == 0 or n_negative == 0:
        raise ValueError(
            f"AUC-ROC is undefined with a single class present "
            f"({n_positive} positive, {n_negative} negative rows)"
        )

    ranks = _midranks(scores)
    positive_rank_sum = float(ranks[labels].sum())
    # Mann-Whitney U for the positive class, normalised to an area.
    u_statistic = positive_rank_sum - n_positive * (n_positive + 1) / 2.0
    return float(u_statistic / (n_positive * n_negative))


def _midranks(values: np.ndarray) -> np.ndarray:
    """Ranks values from 1, assigning tied values their shared average rank.

    Args:
        values: The values to rank.

    Returns:
        Midranks, in the input order.
    """
    order = np.argsort(values, kind="stable")
    sorted_values = values[order]
    ranks = np.empty(values.size, dtype=np.float64)

    start = 0
    while start < sorted_values.size:
        stop = start
        while stop + 1 < sorted_values.size and sorted_values[stop + 1] == sorted_values[start]:
            stop += 1
        # Ranks are 1-based, so a block spanning positions [start, stop] shares
        # the average of start+1 .. stop+1.
        ranks[order[start : stop + 1]] = (start + stop) / 2.0 + 1.0
        start = stop + 1
    return ranks


def brier_score(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Computes the Brier score: mean squared error of a probability forecast.

    Lower is better. Unlike AUC, this is sensitive to whether the scores are
    calibrated probabilities rather than merely well ordered, which is what
    makes it worth reporting next to a ranking metric: a model can rank
    perfectly and still be systematically overconfident.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Predicted probabilities in [0, 1].

    Returns:
        The Brier score, in [0, 1].

    Raises:
        ValueError: If the inputs are mismatched, empty, non-finite, or if any
            score falls outside [0, 1]. A score outside that range is not a
            probability, and scoring it as one would understate the error.
    """
    labels, scores = _validate_pair(y_true, y_score)
    if scores.min() < 0.0 or scores.max() > 1.0:
        raise ValueError(
            f"Brier score requires probabilities in [0, 1], got range "
            f"[{scores.min():.4f}, {scores.max():.4f}]"
        )
    return float(np.mean((scores - labels.astype(np.float64)) ** 2))


@dataclass(frozen=True)
class CalibrationBin:
    """One bin of a reliability diagram.

    Attributes:
        lower: Inclusive lower edge of the predicted-probability bin.
        upper: Upper edge of the bin, inclusive only for the final bin.
        count: Rows falling in this bin.
        mean_predicted: Mean predicted probability among those rows.
        observed_rate: Fraction of those rows that were genuinely attacks.
    """

    lower: float
    upper: float
    count: int
    mean_predicted: float
    observed_rate: float

    @property
    def gap(self) -> float:
        """Signed miscalibration in this bin.

        Returns:
            `mean_predicted - observed_rate`. Positive means the model was
            overconfident here, negative means underconfident.
        """
        return self.mean_predicted - self.observed_rate


@dataclass(frozen=True)
class CalibrationCurve:
    """A reliability diagram plus its scalar summaries.

    Attributes:
        bins: Populated bins only. Empty bins are dropped rather than
            reported with a zero observed rate, which would read as a
            confident, wrong prediction rather than as an absence of data.
        brier: Brier score over all rows.
        expected_calibration_error: Count-weighted mean absolute bin gap. A
            single number for comparing calibration across runs, where the
            full curve is the thing to actually look at.
    """

    bins: tuple[CalibrationBin, ...]
    brier: float
    expected_calibration_error: float


def calibration_curve(
    y_true: np.ndarray, y_score: np.ndarray, n_bins: int = DEFAULT_CALIBRATION_BINS
) -> CalibrationCurve:
    """Builds a reliability diagram over equal-width probability bins.

    Equal-width rather than equal-frequency bins, because the question being
    asked is "when this model says 0.9, is it right 90% of the time" -- which
    is a question about fixed probability regions, not about however many rows
    happen to land in each quantile.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Predicted probabilities in [0, 1].
        n_bins: Number of equal-width bins spanning [0, 1].

    Returns:
        The curve, its Brier score, and its expected calibration error.

    Raises:
        ValueError: If the inputs are mismatched, empty, non-finite, outside
            [0, 1], or if `n_bins` is not positive.
    """
    if n_bins <= 0:
        raise ValueError(f"n_bins must be positive, got {n_bins}")
    labels, scores = _validate_pair(y_true, y_score)
    brier = brier_score(labels, scores)

    edges = np.linspace(0.0, 1.0, n_bins + 1)
    # `right=False` puts a score exactly on an edge in the upper bin; clipping
    # the top index keeps a score of exactly 1.0 in the final bin rather than
    # in a nonexistent one past the end.
    assignments = np.clip(np.digitize(scores, edges[1:-1], right=False), 0, n_bins - 1)

    bins: list[CalibrationBin] = []
    absolute_gap_total = 0.0
    for index in range(n_bins):
        member = assignments == index
        count = int(member.sum())
        if count == 0:
            continue
        mean_predicted = float(scores[member].mean())
        observed_rate = float(labels[member].mean())
        absolute_gap_total += count * abs(mean_predicted - observed_rate)
        bins.append(
            CalibrationBin(
                lower=float(edges[index]),
                upper=float(edges[index + 1]),
                count=count,
                mean_predicted=mean_predicted,
                observed_rate=observed_rate,
            )
        )

    curve = CalibrationCurve(
        bins=tuple(bins),
        brier=brier,
        expected_calibration_error=absolute_gap_total / labels.size,
    )
    logger.info(
        "calibration: %d populated bins, brier=%.5f, ece=%.5f",
        len(curve.bins),
        curve.brier,
        curve.expected_calibration_error,
    )
    return curve
