"""Tests for `detect.calibration`: cost-driven threshold selection."""

from __future__ import annotations

import numpy as np
import pytest

from detect.calibration import calibrate_threshold, sensitivity_sweep


def _perfectly_separable() -> tuple[np.ndarray, np.ndarray]:
    """Builds labels and scores with a clean separating gap at 0.5.

    Returns:
        A (y_true, y_score) pair.
    """
    y_true = np.array([False] * 50 + [True] * 10)
    y_score = np.array([0.1] * 50 + [0.9] * 10)
    return y_true, y_score


def test_calibrate_threshold_finds_the_separating_gap() -> None:
    """A clean separation should calibrate to a threshold inside the gap."""
    y_true, y_score = _perfectly_separable()
    result = calibrate_threshold(y_true, y_score, cost_ratio=10.0)
    assert 0.1 < result.threshold <= 0.9
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_higher_cost_ratio_never_raises_the_threshold() -> None:
    """Weighting false negatives more heavily should not push the threshold up.

    A higher relative cost for missing an attack should make the calibration
    at least as willing to block, never less.
    """
    rng = np.random.default_rng(3)
    y_true = rng.random(500) < 0.1
    y_score = np.clip(y_true * 0.6 + rng.normal(0, 0.25, size=500), 0, 1)
    low_ratio = calibrate_threshold(y_true, y_score, cost_ratio=1.0)
    high_ratio = calibrate_threshold(y_true, y_score, cost_ratio=50.0)
    assert high_ratio.threshold <= low_ratio.threshold


def test_rejects_mismatched_lengths() -> None:
    """y_true and y_score must describe the same rows."""
    with pytest.raises(ValueError, match="rows"):
        calibrate_threshold(np.array([True, False]), np.array([0.1]))


def test_rejects_non_positive_cost_ratio() -> None:
    """A zero or negative cost ratio is meaningless."""
    y_true, y_score = _perfectly_separable()
    with pytest.raises(ValueError, match="cost_ratio must be positive"):
        calibrate_threshold(y_true, y_score, cost_ratio=0.0)


def test_rejects_calibration_set_with_no_attacks() -> None:
    """A calibration set with only legitimate sessions cannot define a ratio."""
    y_true = np.array([False] * 20)
    y_score = np.zeros(20)
    with pytest.raises(ValueError, match="no attack sessions"):
        calibrate_threshold(y_true, y_score)


def test_rejects_calibration_set_with_no_legitimate_sessions() -> None:
    """A calibration set with only attacks cannot define a ratio either."""
    y_true = np.array([True] * 20)
    y_score = np.ones(20)
    with pytest.raises(ValueError, match="no legitimate sessions"):
        calibrate_threshold(y_true, y_score)


def test_sensitivity_sweep_returns_one_result_per_ratio() -> None:
    """The sweep must cover every requested ratio, in order."""
    y_true, y_score = _perfectly_separable()
    ratios = (1.0, 5.0, 25.0)
    results = sensitivity_sweep(y_true, y_score, cost_ratios=ratios)
    assert tuple(r.cost_ratio for r in results) == ratios


def test_sensitivity_sweep_rejects_empty_ratios() -> None:
    """An empty ratio list has nothing to sweep."""
    y_true, y_score = _perfectly_separable()
    with pytest.raises(ValueError, match="non-empty"):
        sensitivity_sweep(y_true, y_score, cost_ratios=())