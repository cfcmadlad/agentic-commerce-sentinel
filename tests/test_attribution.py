"""Tests for `detect.attribution`: SHAP feature attribution."""

from __future__ import annotations

import numpy as np
import pytest

from detect.attribution import compute_attribution, explain_row, top_features
from detect.behavioral import BehavioralModel, train_behavioral_model

FEATURE_NAMES = ("informative", "noise")


def _fitted_model_and_data() -> tuple[BehavioralModel, np.ndarray]:
    """Fits a model where one feature is informative and one is pure noise.

    Returns:
        A (model, features) pair.
    """
    rng = np.random.default_rng(0)
    n = 400
    informative = rng.normal(size=n)
    noise = rng.normal(size=n)
    labels = (informative > 0.5).astype(int)
    features = np.column_stack([informative, noise])
    model = train_behavioral_model(features, labels, FEATURE_NAMES, random_state=0)
    return model, features


def test_informative_feature_ranks_above_noise() -> None:
    """The feature that actually drives the label must attribute higher than noise."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    ranked = top_features(attribution, top_n=2)
    assert ranked[0][0] == "informative"


def test_shap_values_shape_matches_input() -> None:
    """One attribution row per input row, one column per feature."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    assert attribution.shap_values.shape == features.shape


def test_top_features_respects_requested_count() -> None:
    """top_n caps the returned ranking length."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    assert len(top_features(attribution, top_n=1)) == 1


def test_top_features_rejects_non_positive_n() -> None:
    """A zero or negative top_n is a caller error."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    with pytest.raises(ValueError, match="top_n must be positive"):
        top_features(attribution, top_n=0)


def test_compute_attribution_rejects_wrong_column_count() -> None:
    """A design matrix with the wrong number of columns must fail loudly."""
    model, _ = _fitted_model_and_data()
    with pytest.raises(ValueError, match="columns"):
        compute_attribution(model, np.zeros((5, 3)))


def test_compute_attribution_rejects_zero_rows() -> None:
    """Attribution over zero rows has nothing to explain."""
    model, _ = _fitted_model_and_data()
    with pytest.raises(ValueError, match="zero rows"):
        compute_attribution(model, np.zeros((0, 2)))


def test_explain_row_returns_signed_contributions() -> None:
    """A row driven toward the positive class should show a positive contribution."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    strongly_positive_index = int(np.argmax(features[:, 0]))
    explanation = explain_row(attribution, strongly_positive_index, top_n=1)
    assert explanation[0][0] == "informative"


def test_explain_row_rejects_out_of_range_index() -> None:
    """An index outside the attributed rows is a caller error."""
    model, features = _fitted_model_and_data()
    attribution = compute_attribution(model, features)
    with pytest.raises(ValueError, match="out of range"):
        explain_row(attribution, row_index=len(features))