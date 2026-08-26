"""DeLong's test for the difference between two correlated ROC curves.

Two classifiers scored on the same sessions produce correlated AUCs, so the
variance of their difference is not the sum of their individual variances --
treating it as such would overstate the evidence for whichever one came out
ahead. DeLong, DeLong and Clarke-Pearson (1988) give a closed-form estimator
that accounts for the correlation, built out of the placement values (also
called structural components) of each score set. That estimator is implemented
here directly; there is no dependency in this project that provides it, and
adding one for a page of arithmetic would be worse than writing it down.

What the test needs from the caller, and what it cannot supply
--------------------------------------------------------------
DeLong compares rankings. The Layer 3 ensemble emits a continuous score and
ranks well. The rules-only baseline emits a hard block/allow verdict and does
not rank at all: every blocked session ties with every other blocked session.
Passing that in is legitimate -- the midrank Mann-Whitney kernel used here
handles ties by construction, scoring a tied pair 0.5 -- but the resulting AUC
collapses to balanced accuracy, `(sensitivity + specificity) / 2`, and carries
no information about ordering within either group because there is none to
carry. That is a real property of the comparison, not a defect in the
estimator, and `eval/milestone_b.py` reports it as such rather than presenting
a binary-score AUC as if it were comparable to a ranked one. The paired
McNemar test at the operating point, and the baseline plotted as a single
point against the ensemble's precision-recall curve, are the comparisons that
carry the actual weight.

Correctness
-----------
`tests/test_delong.py` checks this implementation three ways rather than
asserting that it runs: the structural components are verified element by
element against a hand-computed four-row case, the AUC it derives is checked
against the independent midrank implementation in `eval/metrics.py` and
against scikit-learn, and the closed-form standard error of the difference is
checked against a bootstrap estimate of the same quantity, which agrees to
within sampling error on a dataset of realistic size.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
from scipy.stats import norm  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

DEFAULT_ALPHA = 0.05


@dataclass(frozen=True)
class DeLongResult:
    """Outcome of a paired DeLong test between two scores on the same rows.

    Attributes:
        baseline_auc: AUC-ROC of the baseline score.
        challenger_auc: AUC-ROC of the challenger score.
        auc_difference: `challenger_auc - baseline_auc`.
        standard_error: Closed-form standard error of that difference,
            accounting for the correlation between the two scores.
        z_statistic: `auc_difference / standard_error`.
        p_value: Two-sided normal p-value.
        significant: Whether `p_value` is below `alpha`.
        favors_challenger: True only if the result is significant *and* the
            challenger's AUC is the larger of the two.
        baseline_is_degenerate: True when the baseline score takes at most two
            distinct values, meaning its AUC is balanced accuracy and the
            comparison is against a non-ranking classifier. Carried on the
            result so a report cannot quote the p-value without the caveat.
    """

    baseline_auc: float
    challenger_auc: float
    auc_difference: float
    standard_error: float
    z_statistic: float
    p_value: float
    significant: bool
    favors_challenger: bool
    baseline_is_degenerate: bool


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
        ranks[order[start : stop + 1]] = (start + stop) / 2.0 + 1.0
        start = stop + 1
    return ranks


def structural_components(
    positive_scores: np.ndarray, negative_scores: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """Computes DeLong's placement values for one score set.

    For each positive row, its component is the fraction of negative rows it
    outranks, counting a tie as half. For each negative row, its component is
    the fraction of positive rows that outrank it, on the same convention. The
    mean of either set equals the AUC; their variances and covariances are what
    the closed-form standard error is assembled from.

    Computed via midranks rather than an explicit O(n_pos * n_neg) comparison,
    which is what makes the bootstrap and the sensitivity grid affordable, but
    the two are algebraically identical -- the tests assert that directly on a
    small case.

    Args:
        positive_scores: Scores of the rows labelled attack.
        negative_scores: Scores of the rows labelled legitimate.

    Returns:
        A tuple of (positive components, negative components).

    Raises:
        ValueError: If either array is empty. A placement value is a fraction
            of the other class, which does not exist if that class is absent.
    """
    if positive_scores.size == 0 or negative_scores.size == 0:
        raise ValueError(
            f"structural components need both classes, got {positive_scores.size} positive "
            f"and {negative_scores.size} negative rows"
        )

    n_positive = positive_scores.size
    n_negative = negative_scores.size
    combined = np.concatenate([positive_scores, negative_scores])

    combined_ranks = _midranks(combined)
    positive_only_ranks = _midranks(positive_scores)
    negative_only_ranks = _midranks(negative_scores)

    # A positive row's rank among everything, minus its rank among positives
    # alone, is the number of negatives it outranks (ties counted as halves).
    positive_components = (
        combined_ranks[:n_positive] - positive_only_ranks
    ) / n_negative
    negative_components = 1.0 - (
        combined_ranks[n_positive:] - negative_only_ranks
    ) / n_positive
    return positive_components, negative_components


def _auc_and_components(
    labels: np.ndarray, scores: np.ndarray
) -> tuple[float, np.ndarray, np.ndarray]:
    """Splits scores by label and derives the AUC from their components.

    Args:
        labels: Ground-truth `is_attack` labels.
        scores: Per-row scores, higher meaning more attack-like.

    Returns:
        A tuple of (AUC, positive components, negative components).
    """
    positive_components, negative_components = structural_components(
        scores[labels], scores[~labels]
    )
    return float(positive_components.mean()), positive_components, negative_components


def delong_test(
    y_true: np.ndarray,
    baseline_score: np.ndarray,
    challenger_score: np.ndarray,
    alpha: float = DEFAULT_ALPHA,
) -> DeLongResult:
    """Tests whether two AUCs measured on the same rows differ significantly.

    Args:
        y_true: Ground-truth `is_attack` labels.
        baseline_score: Baseline score per row, higher meaning more
            attack-like. May be binary; see the module docstring for what that
            costs in interpretability.
        challenger_score: Challenger score over the same rows in the same
            order.
        alpha: Significance threshold.

    Returns:
        The test result.

    Raises:
        ValueError: If the three arrays have mismatched lengths, if any score
            is non-finite, if only one class is present, or if the estimated
            variance of the difference is zero. A zero variance means the two
            scores induce identical placement values on every row, so there is
            no sampling distribution to test against and a z-statistic would
            be a division by zero dressed up as infinite confidence.
    """
    labels = np.asarray(y_true, dtype=bool)
    baseline = np.asarray(baseline_score, dtype=np.float64)
    challenger = np.asarray(challenger_score, dtype=np.float64)

    if not labels.shape == baseline.shape == challenger.shape:
        raise ValueError(
            f"mismatched shapes: y_true {labels.shape}, baseline {baseline.shape}, "
            f"challenger {challenger.shape}"
        )
    if not (np.isfinite(baseline).all() and np.isfinite(challenger).all()):
        raise ValueError("scores contain non-finite values")

    n_positive = int(labels.sum())
    n_negative = int(labels.size - n_positive)
    if n_positive == 0 or n_negative == 0:
        raise ValueError(
            f"DeLong's test needs both classes, got {n_positive} positive and "
            f"{n_negative} negative rows"
        )

    baseline_auc, baseline_positive, baseline_negative = _auc_and_components(labels, baseline)
    challenger_auc, challenger_positive, challenger_negative = _auc_and_components(
        labels, challenger
    )

    # S10 and S01: the sample covariance matrices of the placement values,
    # over the positive rows and the negative rows respectively.
    positive_covariance = np.cov(np.vstack([baseline_positive, challenger_positive]), ddof=1)
    negative_covariance = np.cov(np.vstack([baseline_negative, challenger_negative]), ddof=1)
    covariance = positive_covariance / n_positive + negative_covariance / n_negative

    # Var(challenger - baseline) for the contrast vector (-1, +1).
    contrast = np.array([-1.0, 1.0])
    variance = float(contrast @ covariance @ contrast)
    if variance <= 0.0:
        raise ValueError(
            "estimated variance of the AUC difference is zero; the two scores rank every "
            "row identically, so there is no sampling distribution to test against"
        )

    standard_error = float(np.sqrt(variance))
    difference = challenger_auc - baseline_auc
    z_statistic = difference / standard_error
    p_value = float(2.0 * norm.sf(abs(z_statistic)))
    significant = p_value < alpha

    result = DeLongResult(
        baseline_auc=baseline_auc,
        challenger_auc=challenger_auc,
        auc_difference=difference,
        standard_error=standard_error,
        z_statistic=float(z_statistic),
        p_value=p_value,
        significant=significant,
        favors_challenger=significant and difference > 0.0,
        baseline_is_degenerate=int(np.unique(baseline).size) <= 2,
    )
    logger.info(
        "delong: baseline auc=%.4f challenger auc=%.4f diff=%.4f se=%.5f p=%.4g degenerate=%s",
        result.baseline_auc,
        result.challenger_auc,
        result.auc_difference,
        result.standard_error,
        result.p_value,
        result.baseline_is_degenerate,
    )
    return result
