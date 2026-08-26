"""Tests for the stratified bootstrap confidence intervals.

The properties worth pinning are that the interval is reproducible from a
seed, that it brackets the point estimate, that it narrows as the sample
grows, and -- the one that actually validates the method -- that its nominal
coverage is roughly its real coverage against a known true value.
"""

from __future__ import annotations

import numpy as np
import pytest
from scipy.stats import norm  # type: ignore[import-untyped]

from eval.bootstrap import DEFAULT_RESAMPLES, bootstrap_metric
from eval.metrics import average_precision, roc_auc


def _labelled_scores(
    rng: np.random.Generator, n: int, prevalence: float, separation: float
) -> tuple[np.ndarray, np.ndarray]:
    """Builds a (labels, scores) pair with a controllable amount of signal.

    Args:
        rng: Seeded random generator.
        n: Number of rows.
        prevalence: Fraction of rows labelled positive.
        separation: Mean shift applied to positive rows' scores.

    Returns:
        A (labels, scores) tuple.
    """
    labels = rng.random(n) < prevalence
    scores = np.clip(rng.normal(loc=labels * separation, scale=1.0), -6.0, 6.0)
    return labels, scores


def test_interval_brackets_the_point_estimate() -> None:
    """A percentile interval must contain the estimate it was built around."""
    rng = np.random.default_rng(3)
    labels, scores = _labelled_scores(rng, 3000, 0.05, 1.5)
    interval = bootstrap_metric(labels, scores, average_precision, n_resamples=400)

    assert interval.lower <= interval.point_estimate <= interval.upper
    assert interval.point_estimate == pytest.approx(average_precision(labels, scores))
    assert interval.width > 0.0


def test_interval_is_reproducible_from_its_seed() -> None:
    """Two runs at the same seed must produce identical bounds, not merely close ones."""
    rng = np.random.default_rng(4)
    labels, scores = _labelled_scores(rng, 1500, 0.08, 1.2)

    first = bootstrap_metric(labels, scores, roc_auc, n_resamples=300, seed=7)
    second = bootstrap_metric(labels, scores, roc_auc, n_resamples=300, seed=7)
    assert (first.lower, first.upper) == (second.lower, second.upper)


def test_different_seeds_move_the_interval_slightly() -> None:
    """The interval is a random quantity; identical bounds across seeds would be suspect."""
    rng = np.random.default_rng(5)
    labels, scores = _labelled_scores(rng, 1500, 0.08, 1.2)

    first = bootstrap_metric(labels, scores, roc_auc, n_resamples=300, seed=1)
    second = bootstrap_metric(labels, scores, roc_auc, n_resamples=300, seed=2)
    assert (first.lower, first.upper) != (second.lower, second.upper)
    assert first.lower == pytest.approx(second.lower, abs=0.05)


def test_interval_narrows_as_the_sample_grows() -> None:
    """More data must buy a tighter interval, or the resampling is not working."""
    rng = np.random.default_rng(6)
    small_labels, small_scores = _labelled_scores(rng, 600, 0.1, 1.5)
    large_labels, large_scores = _labelled_scores(rng, 12000, 0.1, 1.5)

    small = bootstrap_metric(small_labels, small_scores, roc_auc, n_resamples=400)
    large = bootstrap_metric(large_labels, large_scores, roc_auc, n_resamples=400)
    assert large.width < small.width


def test_stratification_preserves_the_class_counts() -> None:
    """Every resample must keep the original prevalence.

    Without this, a rare-positive corpus produces resamples with too few
    attacks to score, and the interval silently describes a different problem
    from the one being measured.
    """
    rng = np.random.default_rng(7)
    labels, scores = _labelled_scores(rng, 800, 0.02, 2.0)
    expected_positive = int(labels.sum())
    observed: list[int] = []

    def recording_metric(resampled_labels: np.ndarray, resampled_scores: np.ndarray) -> float:
        """Records the positive count of each resample, then scores it."""
        observed.append(int(resampled_labels.sum()))
        return roc_auc(resampled_labels, resampled_scores)

    bootstrap_metric(labels, scores, recording_metric, n_resamples=50)
    # The first call is on the original sample, the rest are resamples.
    assert set(observed) == {expected_positive}


def test_nominal_coverage_is_approximately_real_coverage() -> None:
    """A 95% interval must cover a known true AUC close to 95% of the time.

    This is the check that validates the method rather than the plumbing. The
    true AUC of two normals separated by `d` with unit variance is
    `Phi(d / sqrt(2))`, so there is an exact target to cover.
    """
    separation = 1.0
    true_auc = float(norm.cdf(separation / np.sqrt(2.0)))

    covered = 0
    trials = 40
    for trial in range(trials):
        rng = np.random.default_rng(1000 + trial)
        labels, scores = _labelled_scores(rng, 1200, 0.25, separation)
        interval = bootstrap_metric(labels, scores, roc_auc, n_resamples=150, seed=trial)
        if interval.lower <= true_auc <= interval.upper:
            covered += 1

    # Wide acceptance band on purpose: with 40 trials the binomial noise around
    # 0.95 coverage is itself several percentage points, and a tight assertion
    # here would be a flaky test rather than a stronger one.
    assert 0.80 <= covered / trials <= 1.0


def test_confidence_level_controls_the_width() -> None:
    """A 99% interval must be wider than a 90% one on the same data."""
    rng = np.random.default_rng(9)
    labels, scores = _labelled_scores(rng, 2000, 0.1, 1.2)

    narrow = bootstrap_metric(labels, scores, roc_auc, n_resamples=500, confidence_level=0.90)
    wide = bootstrap_metric(labels, scores, roc_auc, n_resamples=500, confidence_level=0.99)
    assert wide.width > narrow.width


def test_default_resample_count_is_the_documented_one() -> None:
    """The reported interval must be built from the resample count the report claims."""
    assert DEFAULT_RESAMPLES == 1000
    rng = np.random.default_rng(10)
    labels, scores = _labelled_scores(rng, 800, 0.1, 1.0)
    assert bootstrap_metric(labels, scores, roc_auc).n_resamples == DEFAULT_RESAMPLES


def test_rejects_a_single_class() -> None:
    """Stratified resampling needs both strata to exist."""
    with pytest.raises(ValueError, match="needs both classes"):
        bootstrap_metric(np.array([True, True]), np.array([0.1, 0.2]), roc_auc)


def test_rejects_invalid_arguments() -> None:
    """Invalid resample counts and confidence levels must fail loudly."""
    rng = np.random.default_rng(11)
    labels, scores = _labelled_scores(rng, 200, 0.2, 1.0)

    with pytest.raises(ValueError, match="n_resamples must be positive"):
        bootstrap_metric(labels, scores, roc_auc, n_resamples=0)
    with pytest.raises(ValueError, match="confidence_level must be in"):
        bootstrap_metric(labels, scores, roc_auc, confidence_level=1.0)


def test_rejects_mismatched_lengths() -> None:
    """Mismatched arrays are a caller bug."""
    with pytest.raises(ValueError, match="shape"):
        bootstrap_metric(np.array([True, False]), np.array([0.5]), roc_auc)


def test_surfaces_a_metric_that_is_undefined_too_often() -> None:
    """Silently dropping failed resamples would misreport the interval."""
    rng = np.random.default_rng(12)
    labels, scores = _labelled_scores(rng, 300, 0.2, 1.0)
    calls = {"n": 0}

    def undefined_after_the_first_call(
        resampled_labels: np.ndarray, resampled_scores: np.ndarray
    ) -> float:
        """Scores the original sample, then declares every resample undefined."""
        calls["n"] += 1
        if calls["n"] == 1:
            return roc_auc(resampled_labels, resampled_scores)
        raise ValueError("undefined for this resample")

    with pytest.raises(ValueError, match="undefined metric"):
        bootstrap_metric(labels, scores, undefined_after_the_first_call, n_resamples=20)


def test_a_metric_that_fails_on_the_original_sample_propagates() -> None:
    """A metric undefined on the real data is a caller error, not a resampling one."""
    rng = np.random.default_rng(13)
    labels, scores = _labelled_scores(rng, 300, 0.2, 1.0)

    def always_undefined(_labels: np.ndarray, _scores: np.ndarray) -> float:
        """Stands in for a metric that cannot score this data at all."""
        raise ValueError("cannot score this data")

    with pytest.raises(ValueError, match="cannot score this data"):
        bootstrap_metric(labels, scores, always_undefined, n_resamples=20)
