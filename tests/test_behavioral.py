"""Tests for `detect.behavioral`: chronological splitting and model fitting."""

from __future__ import annotations

import numpy as np
import pytest

from detect.behavioral import (
    MIN_POSITIVE_CLASS_ROWS,
    MIN_TRAINING_ROWS,
    chronological_split,
    train_behavioral_model,
)

FEATURE_NAMES = ("a", "b")


def _synthetic_dataset(n_rows: int, n_positive: int, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Builds a linearly separable synthetic dataset for fitting tests.

    Args:
        n_rows: Total rows.
        n_positive: Rows labeled positive (attack). Placed contiguously at
            the end so a chronological split still sees both classes.
        seed: RNG seed.

    Returns:
        A (features, labels) pair.
    """
    rng = np.random.default_rng(seed)
    negative = rng.normal(loc=0.0, scale=1.0, size=(n_rows - n_positive, 2))
    positive = rng.normal(loc=5.0, scale=1.0, size=(n_positive, 2))
    features = np.vstack([negative, positive])
    labels = np.array([0] * (n_rows - n_positive) + [1] * n_positive)
    order = rng.permutation(n_rows)
    return features[order], labels[order]


def test_chronological_split_sizes_sum_to_total() -> None:
    """The three masks must partition every row exactly once."""
    split = chronological_split(1000, train_fraction=0.6, validation_fraction=0.2)
    assert split.train.sum() + split.validation.sum() + split.test.sum() == 1000
    assert not (split.train & split.validation).any()
    assert not (split.validation & split.test).any()


def test_chronological_split_preserves_order() -> None:
    """Train rows must all precede validation rows, which precede test rows."""
    split = chronological_split(100, train_fraction=0.6, validation_fraction=0.2)
    train_end = np.flatnonzero(split.train).max()
    validation_start = np.flatnonzero(split.validation).min()
    validation_end = np.flatnonzero(split.validation).max()
    test_start = np.flatnonzero(split.test).min()
    assert train_end < validation_start
    assert validation_end < test_start


def test_chronological_split_rejects_fractions_leaving_no_test_split() -> None:
    """Fractions summing to >= 1 would leave an empty test block."""
    with pytest.raises(ValueError, match="non-empty test split"):
        chronological_split(100, train_fraction=0.7, validation_fraction=0.3)


def test_chronological_split_rejects_non_positive_rows() -> None:
    """Zero or negative row counts are a caller error."""
    with pytest.raises(ValueError, match="must be positive"):
        chronological_split(0, train_fraction=0.6, validation_fraction=0.2)


def test_train_behavioral_model_fits_a_separable_dataset() -> None:
    """A clearly separable dataset should fit without error and score sensibly."""
    features, labels = _synthetic_dataset(n_rows=400, n_positive=40)
    model = train_behavioral_model(features, labels, FEATURE_NAMES, random_state=1)
    scores = model.predict_proba(features)
    assert scores.shape == (400,)
    assert scores[labels == 1].mean() > scores[labels == 0].mean()


def test_train_behavioral_model_rejects_mismatched_lengths() -> None:
    """Features and labels must describe the same rows."""
    features, labels = _synthetic_dataset(n_rows=200, n_positive=20)
    with pytest.raises(ValueError, match="rows"):
        train_behavioral_model(features, labels[:-1], FEATURE_NAMES)


def test_train_behavioral_model_rejects_too_few_rows() -> None:
    """A dataset smaller than the minimum is a gate condition, not a fit attempt."""
    features, labels = _synthetic_dataset(n_rows=MIN_TRAINING_ROWS - 1, n_positive=5)
    with pytest.raises(ValueError, match="training rows"):
        train_behavioral_model(features, labels, FEATURE_NAMES)


def test_train_behavioral_model_rejects_sparse_positive_class() -> None:
    """Too few attack rows to fit against must fail loudly, not fit anyway."""
    features, labels = _synthetic_dataset(n_rows=200, n_positive=MIN_POSITIVE_CLASS_ROWS - 1)
    with pytest.raises(ValueError, match="positive"):
        train_behavioral_model(features, labels, FEATURE_NAMES)


def test_predict_proba_rejects_wrong_column_count() -> None:
    """Scoring with a mismatched design matrix must fail rather than misalign columns."""
    features, labels = _synthetic_dataset(n_rows=200, n_positive=20)
    model = train_behavioral_model(features, labels, FEATURE_NAMES)
    with pytest.raises(ValueError, match="columns"):
        model.predict_proba(np.zeros((5, 3)))


def test_same_random_state_is_reproducible() -> None:
    """Two fits with the same random_state on the same data must score identically."""
    features, labels = _synthetic_dataset(n_rows=300, n_positive=30)
    model_a = train_behavioral_model(features, labels, FEATURE_NAMES, random_state=7)
    model_b = train_behavioral_model(features, labels, FEATURE_NAMES, random_state=7)
    np.testing.assert_array_equal(model_a.predict_proba(features), model_b.predict_proba(features))