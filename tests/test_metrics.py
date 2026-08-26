"""Tests for the hand-rolled ranking metrics and calibration diagnostics.

These implementations exist for speed inside the bootstrap loop, which only
justifies them if they agree exactly with an established reference. Every
metric here is therefore checked against scikit-learn on random data that
includes tied scores, not merely exercised for absence of exceptions.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.metrics import (  # type: ignore[import-untyped]
    average_precision_score,
    brier_score_loss,
    roc_auc_score,
)

from eval.metrics import (
    average_precision,
    brier_score,
    calibration_curve,
    roc_auc,
)

_AGREEMENT_TOLERANCE = 1e-12


def _random_case(rng: np.random.Generator, n: int, prevalence: float) -> tuple[np.ndarray, np.ndarray]:
    """Builds a random (labels, scores) pair with a signal the metrics can see.

    Args:
        rng: Seeded random generator.
        n: Number of rows.
        prevalence: Fraction of rows labelled positive.

    Returns:
        A (labels, scores) tuple.
    """
    labels = rng.random(n) < prevalence
    scores = np.clip(rng.normal(loc=labels * 0.8, scale=0.5), 0.0, 1.0)
    return labels, scores


@pytest.mark.parametrize("prevalence", [0.02, 0.15, 0.5])
def test_average_precision_matches_sklearn(prevalence: float) -> None:
    """AUC-PR must equal scikit-learn's step-wise average precision."""
    rng = np.random.default_rng(7)
    labels, scores = _random_case(rng, 2000, prevalence)
    assert average_precision(labels, scores) == pytest.approx(
        float(average_precision_score(labels, scores)), abs=_AGREEMENT_TOLERANCE
    )


def test_average_precision_matches_sklearn_with_heavy_ties() -> None:
    """Tied scores must be handled the same way scikit-learn handles them.

    Ties are the case a naive implementation gets wrong, and they are not
    hypothetical here: the rules-only baseline's score is entirely ties.
    """
    rng = np.random.default_rng(11)
    labels = rng.random(600) < 0.2
    scores = rng.integers(0, 4, size=600).astype(np.float64) / 3.0
    assert average_precision(labels, scores) == pytest.approx(
        float(average_precision_score(labels, scores)), abs=_AGREEMENT_TOLERANCE
    )


@pytest.mark.parametrize("prevalence", [0.02, 0.15, 0.5])
def test_roc_auc_matches_sklearn(prevalence: float) -> None:
    """AUC-ROC must equal scikit-learn's implementation."""
    rng = np.random.default_rng(13)
    labels, scores = _random_case(rng, 2000, prevalence)
    assert roc_auc(labels, scores) == pytest.approx(
        float(roc_auc_score(labels, scores)), abs=_AGREEMENT_TOLERANCE
    )


def test_roc_auc_matches_sklearn_on_a_binary_score() -> None:
    """The degenerate binary case must still agree with the reference."""
    rng = np.random.default_rng(17)
    labels = rng.random(800) < 0.1
    predictions = (rng.random(800) < np.where(labels, 0.8, 0.05)).astype(np.float64)
    assert roc_auc(labels, predictions) == pytest.approx(
        float(roc_auc_score(labels, predictions)), abs=_AGREEMENT_TOLERANCE
    )


def test_binary_score_auc_equals_balanced_accuracy() -> None:
    """A binary score's AUC is balanced accuracy, the caveat the report states.

    Pinning this makes the claim in `eval/delong.py`'s docstring a tested fact
    rather than an assertion in prose.
    """
    labels = np.array([True, True, True, True, False, False, False, False])
    predictions = np.array([1.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0])
    sensitivity = 3 / 4
    specificity = 3 / 4
    assert roc_auc(labels, predictions) == pytest.approx((sensitivity + specificity) / 2)


def test_brier_score_matches_sklearn() -> None:
    """The Brier score must equal scikit-learn's."""
    rng = np.random.default_rng(19)
    labels, scores = _random_case(rng, 1500, 0.1)
    assert brier_score(labels, scores) == pytest.approx(
        float(brier_score_loss(labels, scores)), abs=_AGREEMENT_TOLERANCE
    )


def test_brier_score_is_zero_for_a_perfect_forecast() -> None:
    """A forecast that is right with full confidence has no squared error."""
    labels = np.array([True, False, True, False])
    assert brier_score(labels, labels.astype(np.float64)) == pytest.approx(0.0)


def test_calibration_curve_recovers_a_known_miscalibration() -> None:
    """A model that always says 0.9 but is right 50% of the time must show it."""
    labels = np.array([True] * 500 + [False] * 500)
    scores = np.full(1000, 0.9)
    curve = calibration_curve(labels, scores, n_bins=10)

    assert len(curve.bins) == 1
    only_bin = curve.bins[0]
    assert only_bin.count == 1000
    assert only_bin.mean_predicted == pytest.approx(0.9)
    assert only_bin.observed_rate == pytest.approx(0.5)
    assert only_bin.gap == pytest.approx(0.4)
    assert curve.expected_calibration_error == pytest.approx(0.4)


def test_calibration_curve_drops_empty_bins() -> None:
    """An unpopulated bin must be absent, not reported as a confident zero."""
    labels = np.array([True, False, True, False])
    scores = np.array([0.95, 0.92, 0.98, 0.91])
    curve = calibration_curve(labels, scores, n_bins=10)
    assert len(curve.bins) == 1
    assert curve.bins[0].lower == pytest.approx(0.9)


def test_calibration_curve_of_a_well_calibrated_model_has_small_error() -> None:
    """Labels drawn from the predicted probability must calibrate well."""
    rng = np.random.default_rng(23)
    scores = rng.random(20000)
    labels = rng.random(20000) < scores
    curve = calibration_curve(labels, scores, n_bins=10)
    assert curve.expected_calibration_error < 0.02
    assert all(abs(one_bin.gap) < 0.05 for one_bin in curve.bins)


def test_calibration_places_a_score_of_one_in_the_final_bin() -> None:
    """A probability of exactly 1.0 must not fall off the end of the bins."""
    labels = np.array([True, True, False])
    curve = calibration_curve(labels, np.array([1.0, 1.0, 1.0]), n_bins=10)
    assert len(curve.bins) == 1
    assert curve.bins[0].upper == pytest.approx(1.0)


def test_average_precision_rejects_a_single_class() -> None:
    """Average precision without positives must fail rather than return zero."""
    with pytest.raises(ValueError, match="undefined with no positive rows"):
        average_precision(np.array([False, False]), np.array([0.1, 0.9]))


def test_roc_auc_rejects_a_single_class() -> None:
    """AUC needs both classes to rank against each other."""
    with pytest.raises(ValueError, match="undefined with a single class"):
        roc_auc(np.array([True, True]), np.array([0.1, 0.9]))


def test_metrics_reject_non_finite_scores() -> None:
    """A NaN score would sort to one end and corrupt the ranking silently."""
    with pytest.raises(ValueError, match="non-finite"):
        roc_auc(np.array([True, False]), np.array([np.nan, 0.5]))


def test_brier_score_rejects_scores_outside_the_unit_interval() -> None:
    """A value outside [0, 1] is not a probability."""
    with pytest.raises(ValueError, match="probabilities in"):
        brier_score(np.array([True, False]), np.array([1.5, 0.5]))


def test_metrics_reject_mismatched_lengths() -> None:
    """Mismatched arrays are a caller bug, not something to broadcast around."""
    with pytest.raises(ValueError, match="shape"):
        average_precision(np.array([True, False]), np.array([0.5]))
