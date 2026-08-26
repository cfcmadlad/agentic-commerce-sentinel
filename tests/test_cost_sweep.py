"""Tests for the full-range threshold cost sweep.

The sweep is only useful if its counts are exactly right at every threshold,
so the arithmetic is checked against a hand-constructed case where every
confusion-matrix cell is known, rather than only against monotonicity
properties that a subtly wrong implementation would also satisfy.
"""

from __future__ import annotations

import numpy as np
import pytest

from detect.calibration import (
    DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    calibrate_threshold,
)
from eval.cost_sweep import (
    SESSIONS_PER_RATE_UNIT,
    format_cost_sweep,
    sweep_across_cost_ratios,
    sweep_thresholds,
)


def _separable_case(n: int = 4000, prevalence: float = 0.05) -> tuple[np.ndarray, np.ndarray]:
    """Builds a realistically imbalanced, partly separable scoring problem.

    Args:
        n: Number of rows.
        prevalence: Fraction of rows labelled attack.

    Returns:
        A (labels, scores) tuple with scores in [0, 1].
    """
    rng = np.random.default_rng(42)
    labels = rng.random(n) < prevalence
    scores = np.clip(rng.normal(loc=np.where(labels, 0.75, 0.15), scale=0.18), 0.0, 1.0)
    return labels, scores


def test_counts_are_exact_at_a_known_threshold() -> None:
    """Every confusion-matrix cell must be right on a hand-built case."""
    labels = np.array([True, True, True, False, False, False, False])
    scores = np.array([0.90, 0.60, 0.20, 0.80, 0.40, 0.10, 0.00])

    sweep = sweep_thresholds(labels, scores, cost_ratio=10.0, n_points=101)
    point = next(p for p in sweep.points if p.threshold == pytest.approx(0.50))

    # At 0.50: blocked are 0.90(A), 0.60(A), 0.80(L) -> TP=2, FP=1
    #          allowed are 0.20(A), 0.40(L), 0.10(L), 0.00(L) -> FN=1, TN=3
    assert (point.true_positives, point.false_positives) == (2, 1)
    assert (point.false_negatives, point.true_negatives) == (1, 3)
    assert point.precision == pytest.approx(2 / 3)
    assert point.recall == pytest.approx(2 / 3)
    assert point.expected_cost == pytest.approx(1 * 1.0 + 1 * 10.0)


def test_every_point_has_a_complete_confusion_matrix() -> None:
    """The four cells must always sum to the row count, at every threshold."""
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=101)
    for point in sweep.points:
        total = (
            point.true_positives
            + point.false_positives
            + point.false_negatives
            + point.true_negatives
        )
        assert total == sweep.n_sessions


def test_sweep_spans_the_full_range_and_reaches_both_extremes() -> None:
    """A threshold of 0 must block everything and a threshold above every score nothing."""
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=501)

    first, last = sweep.points[0], sweep.points[-1]
    assert first.threshold == pytest.approx(0.0)
    assert last.threshold == pytest.approx(1.0)
    assert first.recall == pytest.approx(1.0)
    assert first.true_negatives == 0
    assert last.false_positives == 0


def test_recall_is_non_increasing_across_the_sweep() -> None:
    """Raising the threshold can only ever block fewer sessions."""
    labels, scores = _separable_case()
    recalls = [point.recall for point in sweep_thresholds(labels, scores, n_points=201).points]
    assert all(later <= earlier + 1e-12 for earlier, later in zip(recalls, recalls[1:], strict=False))


def test_per_10k_rates_are_scaled_consistently_with_the_counts() -> None:
    """The reported rate must be the count rescaled, not an independent figure."""
    labels, scores = _separable_case(n=5000)
    sweep = sweep_thresholds(labels, scores, n_points=51)
    scale = SESSIONS_PER_RATE_UNIT / sweep.n_sessions
    for point in sweep.points:
        assert point.blocked_legitimate_per_10k == pytest.approx(point.false_positives * scale)
        assert point.missed_attacks_per_10k == pytest.approx(point.false_negatives * scale)


def test_minimum_cost_point_agrees_with_the_calibration_module() -> None:
    """The sweep and the calibrator must not disagree about the best threshold.

    Two cost models in one repository that pick different operating points
    would be a real defect, so this pins them to the same answer within the
    resolution of the coarser of the two grids.
    """
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=201)
    calibrated = calibrate_threshold(labels, scores, grid_size=201)

    assert sweep.minimum_cost_point.threshold == pytest.approx(calibrated.threshold, abs=0.01)
    assert sweep.minimum_cost_point.expected_cost == pytest.approx(calibrated.expected_cost)


def test_cost_ratio_moves_the_optimum_toward_recall() -> None:
    """A harsher false-negative penalty must lower the chosen threshold."""
    labels, scores = _separable_case()
    cheap = sweep_thresholds(labels, scores, cost_ratio=1.0, n_points=201)
    costly = sweep_thresholds(labels, scores, cost_ratio=30.0, n_points=201)

    assert costly.minimum_cost_point.threshold <= cheap.minimum_cost_point.threshold
    assert costly.minimum_cost_point.recall >= cheap.minimum_cost_point.recall


def test_error_counts_do_not_depend_on_the_cost_ratio() -> None:
    """Only the cost column may move when the assumption changes."""
    labels, scores = _separable_case()
    cheap = sweep_thresholds(labels, scores, cost_ratio=1.0, n_points=51)
    costly = sweep_thresholds(labels, scores, cost_ratio=30.0, n_points=51)

    for left, right in zip(cheap.points, costly.points, strict=True):
        assert left.false_positives == right.false_positives
        assert left.false_negatives == right.false_negatives
        assert left.expected_cost != right.expected_cost or left.false_negatives == 0


def test_at_recall_returns_the_best_precision_meeting_the_floor() -> None:
    """The gate's 'precision at fixed recall' reading must be exact."""
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=501)

    found = sweep.at_recall(0.80)
    assert found is not None
    assert found.recall >= 0.80
    qualifying = [point.precision for point in sweep.points if point.recall >= 0.80]
    assert found.precision == pytest.approx(max(qualifying))


def test_at_recall_returns_none_for_an_unreachable_floor() -> None:
    """An unreachable recall must return None, not the closest available point."""
    labels = np.array([True, True, False, False])
    scores = np.array([0.9, 0.1, 0.8, 0.2])
    sweep = sweep_thresholds(labels, scores, n_points=101)
    assert sweep.at_recall(1.01) is None


def test_sweep_across_cost_ratios_covers_every_requested_ratio() -> None:
    """Each requested ratio must produce its own sweep, in order."""
    labels, scores = _separable_case()
    ratios = (1.0, 10.0, 30.0)
    sweeps = sweep_across_cost_ratios(labels, scores, cost_ratios=ratios, n_points=51)
    assert tuple(sweep.cost_ratio for sweep in sweeps) == ratios


def test_default_cost_ratio_is_the_shared_named_assumption() -> None:
    """The sweep must not introduce a second, inconsistent default."""
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=11)
    assert sweep.cost_ratio == DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO


def test_formatting_always_includes_the_minimum_cost_point() -> None:
    """A thinned table that omitted the optimum would be actively misleading."""
    labels, scores = _separable_case()
    sweep = sweep_thresholds(labels, scores, n_points=501)
    rendered = format_cost_sweep(sweep, every_n=100)

    assert "<- min cost" in rendered
    assert f"{sweep.minimum_cost_point.threshold:.3f}" in rendered


def test_rejects_invalid_inputs() -> None:
    """Bad arguments must fail loudly rather than produce a plausible sweep."""
    labels, scores = _separable_case(n=200)

    with pytest.raises(ValueError, match="cost_ratio must be positive"):
        sweep_thresholds(labels, scores, cost_ratio=0.0)
    with pytest.raises(ValueError, match="n_points must be at least 2"):
        sweep_thresholds(labels, scores, n_points=1)
    with pytest.raises(ValueError, match="no attacks"):
        sweep_thresholds(np.zeros(10, dtype=bool), np.linspace(0, 1, 10))
    with pytest.raises(ValueError, match="shape"):
        sweep_thresholds(np.array([True, False]), np.array([0.5]))
    with pytest.raises(ValueError, match="cost_ratios must be non-empty"):
        sweep_across_cost_ratios(labels, scores, cost_ratios=())
    with pytest.raises(ValueError, match="every_n must be positive"):
        format_cost_sweep(sweep_thresholds(labels, scores, n_points=11), every_n=0)
