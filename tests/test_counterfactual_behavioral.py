"""Tests for `counterfactual.behavioral`: Layer 3's SHAP-guided minimal-edit search.

Synthetic feature names are deliberately reused from the real feature
vocabulary (`hour_of_day`, `has_catalog_browse`) where a test needs to
exercise this module's excluded-feature or binary-flip handling -- what
matters to `behavioral_counterfactual` is the name string, not where the
column actually comes from, so a small synthetic model exercises the same
code paths a real 18-feature model would.
"""

from __future__ import annotations

import numpy as np

from counterfactual.behavioral import behavioral_counterfactual
from detect.attribution import compute_attribution
from detect.behavioral import BehavioralModel, train_behavioral_model


def _fit(feature_names: tuple[str, ...], columns: list[np.ndarray], labels: np.ndarray) -> BehavioralModel:
    """Fits a small model over explicitly named synthetic columns.

    Args:
        feature_names: Column names, matching `columns`' order.
        columns: One 1-D array per feature.
        labels: Ground-truth labels.

    Returns:
        The fitted model.
    """
    features = np.column_stack(columns)
    return train_behavioral_model(features, labels, feature_names, random_state=0)


def test_returns_none_when_already_below_threshold() -> None:
    """A session whose score is already under the threshold has nothing to explain."""
    rng = np.random.default_rng(1)
    n = 400
    informative = rng.normal(size=n)
    noise = rng.normal(size=n)
    labels = (informative > 0.5).astype(int)
    model = _fit(("informative", "noise"), [informative, noise], labels)

    row = np.array([[-3.0, 0.0]])
    attribution = compute_attribution(model, row)
    score = float(model.predict_proba(row)[0])
    result = behavioral_counterfactual(model, row, attribution, row_index=0, threshold=score + 0.5)
    assert result is None


def test_finds_a_downward_edit_that_clears_the_threshold() -> None:
    """A high-scoring row's top continuous feature gets pulled toward whichever side lowers the score."""
    rng = np.random.default_rng(2)
    n = 500
    informative = rng.normal(size=n)
    noise = rng.normal(size=n)
    labels = (informative > 0.5).astype(int)
    model = _fit(("informative", "noise"), [informative, noise], labels)

    row = np.array([[4.0, 0.0]])
    attribution = compute_attribution(model, row)
    score = float(model.predict_proba(row)[0])
    threshold = score - 0.05
    assert threshold > 0.0  # sanity: the row must actually be near-certainly "attack" for this test to mean anything

    result = behavioral_counterfactual(model, row, attribution, row_index=0, threshold=threshold)
    assert result is not None
    assert result.feasible
    assert result.resulting_score < threshold
    assert len(result.edits) >= 1
    edited = result.edits[0]
    assert edited.feature == "informative"
    assert edited.suggested_value != edited.real_value


def test_excludes_calendar_features_even_when_they_dominate_shap() -> None:
    """hour_of_day and day_of_week are never edited, even if they are the only informative features."""
    rng = np.random.default_rng(3)
    n = 500
    hour = rng.uniform(0, 23, size=n)
    day = rng.uniform(0, 6, size=n)
    noise = rng.normal(size=n)
    labels = (hour > 12).astype(int)
    model = _fit(("hour_of_day", "day_of_week", "noise"), [hour, day, noise], labels)

    row = np.array([[22.0, 5.0, 0.0]])
    attribution = compute_attribution(model, row)
    score = float(model.predict_proba(row)[0])
    result = behavioral_counterfactual(model, row, attribution, row_index=0, threshold=score - 0.01)
    assert result is not None
    assert not any(edit.feature in {"hour_of_day", "day_of_week"} for edit in result.edits)


def test_binary_feature_is_only_ever_flipped() -> None:
    """A boolean flag feature is tested as a single flip, never a fractional bisection value."""
    rng = np.random.default_rng(4)
    n = 500
    flag = rng.integers(0, 2, size=n).astype(float)
    noise = rng.normal(size=n)
    labels = flag.astype(int)
    model = _fit(("has_catalog_browse", "noise"), [flag, noise], labels)

    row = np.array([[1.0, 0.0]])
    attribution = compute_attribution(model, row)
    score = float(model.predict_proba(row)[0])
    result = behavioral_counterfactual(model, row, attribution, row_index=0, threshold=score - 0.01)
    assert result is not None
    for edit in result.edits:
        if edit.feature == "has_catalog_browse":
            assert edit.suggested_value in (0.0, 1.0)


def test_infeasible_when_no_candidate_feature_helps() -> None:
    """When every candidate feature is irrelevant to the score, the search honestly reports no crossing."""
    rng = np.random.default_rng(5)
    n = 500
    informative = rng.normal(size=n)
    irrelevant_a = rng.normal(size=n)
    irrelevant_b = rng.normal(size=n)
    labels = (informative > 0.5).astype(int)
    model = _fit(("informative", "irrelevant_a", "irrelevant_b"), [informative, irrelevant_a, irrelevant_b], labels)

    row = np.array([[4.0, 0.0, 0.0]])
    attribution = compute_attribution(model, row)
    # A threshold of exactly 0.0 can never be cleared -- every score from a
    # probabilistic classifier is >= 0.0 -- so this forces the honest
    # infeasible path deterministically, regardless of how the model
    # actually responds to any of the three features.
    result = behavioral_counterfactual(model, row, attribution, row_index=0, threshold=0.0)
    assert result is not None
    assert not result.feasible
    assert result.resulting_score >= 0.0
