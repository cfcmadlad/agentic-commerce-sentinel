"""Tests for the shared detection-stack fit.

The load-bearing test here is the drift check against `run_milestone_a`: two
evaluation paths over the same corpus that disagreed would mean one of the
project's reported results was wrong, and nothing else in the suite would
catch it.
"""

from __future__ import annotations

import numpy as np
import pytest

from eval.milestone_a import run_milestone_a
from eval.pipeline import (
    RULES_ALLOWED_SCORE,
    RULES_BLOCKED_SCORE,
    extract_features_causally,
    fit_pipeline,
    precision_recall,
)
from features.session import feature_names
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus

_CORPUS_SESSIONS = 3000
_CORPUS_SEED = 42


@pytest.fixture(scope="module")
def corpus() -> EvaluationCorpus:
    """Builds one corpus shared across the tests in this module.

    Returns:
        The corpus.
    """
    return build_evaluation_corpus(_CORPUS_SESSIONS, seed=_CORPUS_SEED)


def test_matches_milestone_a_headline_numbers(corpus: EvaluationCorpus) -> None:
    """The shared fit must reproduce Milestone A's reported comparison exactly.

    Not approximately: both paths run the same layers on the same corpus with
    the same seeds, so any difference is a defect in one of them rather than
    tolerable numerical noise.
    """
    milestone_a = run_milestone_a(corpus)
    fit = fit_pipeline(corpus)
    labels, baseline_score, ensemble_score = fit.test_slice()

    baseline_precision, baseline_recall = precision_recall(
        baseline_score >= RULES_BLOCKED_SCORE, labels
    )
    ensemble_precision, ensemble_recall = precision_recall(
        ensemble_score >= fit.threshold, labels
    )

    assert fit.threshold == pytest.approx(milestone_a.chosen_calibration.threshold)
    assert baseline_precision == pytest.approx(milestone_a.baseline_precision)
    assert baseline_recall == pytest.approx(milestone_a.baseline_recall)
    assert ensemble_precision == pytest.approx(milestone_a.ensemble_precision)
    assert ensemble_recall == pytest.approx(milestone_a.ensemble_recall)


def test_ensemble_score_reproduces_the_ensemble_verdict(corpus: EvaluationCorpus) -> None:
    """Thresholding the scalar score must equal the ensemble's own rule.

    Every threshold-free metric is computed over this score, so if it did not
    reproduce the ensemble's verdict at the operating point, the AUC would
    describe a system that is not the one being deployed.
    """
    fit = fit_pipeline(corpus)
    expected = fit.baseline_blocked | (fit.behavioral_score >= fit.threshold)
    np.testing.assert_array_equal(fit.ensemble_blocked, expected)


def test_layer3_never_unblocks_a_rules_block(corpus: EvaluationCorpus) -> None:
    """A session the deterministic layers blocked must stay blocked at any threshold."""
    fit = fit_pipeline(corpus)
    for threshold in (0.0, 0.25, 0.5, 0.9, 1.0):
        blocked = fit.ensemble_score >= threshold
        assert np.all(blocked[fit.baseline_blocked])


def test_baseline_score_is_exactly_binary(corpus: EvaluationCorpus) -> None:
    """The rules baseline emits a verdict, and its score must say so."""
    fit = fit_pipeline(corpus)
    assert set(np.unique(fit.baseline_score)) <= {RULES_ALLOWED_SCORE, RULES_BLOCKED_SCORE}
    np.testing.assert_array_equal(fit.baseline_score >= RULES_BLOCKED_SCORE, fit.baseline_blocked)


def test_splits_are_disjoint_and_cover_the_corpus(corpus: EvaluationCorpus) -> None:
    """Train, validation and test must partition the corpus exactly once."""
    fit = fit_pipeline(corpus)
    stacked = np.vstack([fit.split.train, fit.split.validation, fit.split.test])
    np.testing.assert_array_equal(stacked.sum(axis=0), np.ones(len(fit.labels), dtype=int))


def test_model_never_sees_the_test_block(corpus: EvaluationCorpus) -> None:
    """Training rows must fall strictly inside the training block's residual."""
    fit = fit_pipeline(corpus)
    train_residual = fit.split.train & fit.residual
    assert not np.any(train_residual & fit.split.test)
    assert not np.any(train_residual & fit.split.validation)
    assert not np.any(train_residual & fit.baseline_blocked)


def test_test_slice_covers_the_whole_test_block(corpus: EvaluationCorpus) -> None:
    """The reported comparison must be over all test traffic, not the residual."""
    fit = fit_pipeline(corpus)
    labels, baseline_score, ensemble_score = fit.test_slice()
    expected = int(fit.split.test.sum())
    assert labels.size == baseline_score.size == ensemble_score.size == expected
    # The residual alone would be strictly smaller, which is the mistake this guards.
    assert expected > int((fit.split.test & fit.residual).sum())


def test_features_have_the_declared_shape(corpus: EvaluationCorpus) -> None:
    """The design matrix must match the feature contract the model was fitted on."""
    fit = fit_pipeline(corpus)
    assert fit.features.shape == (len(corpus.labeled_sessions), len(feature_names()))
    assert fit.model.feature_names == feature_names()


def test_feature_extraction_is_deterministic(corpus: EvaluationCorpus) -> None:
    """The same sessions must produce the same matrix on every run."""
    first = extract_features_causally(corpus.labeled_sessions)
    second = extract_features_causally(corpus.labeled_sessions)
    np.testing.assert_array_equal(first, second)


def test_fit_is_reproducible(corpus: EvaluationCorpus) -> None:
    """Two fits of the same corpus must agree on every score."""
    first = fit_pipeline(corpus)
    second = fit_pipeline(corpus)
    np.testing.assert_array_equal(first.ensemble_score, second.ensemble_score)
    assert first.threshold == second.threshold


def test_precision_recall_matches_a_hand_computed_case() -> None:
    """The shared precision/recall helper must be arithmetically right."""
    predicted = np.array([True, True, True, False, False])
    truth = np.array([True, False, True, True, False])
    precision, recall = precision_recall(predicted, truth)
    assert precision == pytest.approx(2 / 3)
    assert recall == pytest.approx(2 / 3)


def test_precision_recall_handles_empty_denominators() -> None:
    """No blocks and no attacks must give 0.0, not a division error."""
    assert precision_recall(np.zeros(4, dtype=bool), np.zeros(4, dtype=bool)) == (0.0, 0.0)


def test_rejects_an_empty_corpus() -> None:
    """An empty corpus has nothing to fit."""
    from detect.resolution import InMemoryMandateResolver
    from generator.attack_config import DEFAULT_ATTACK_CONFIG
    from generator.config import DEFAULT_GENERATOR_CONFIG
    from mandate.verification import AgentKeyRegistry

    empty = EvaluationCorpus(
        labeled_sessions=(),
        resolver=InMemoryMandateResolver({}),
        registry=AgentKeyRegistry(),
        variant_by_session={},
        attack_base_rate=0.0,
        seed=0,
        generator_config=DEFAULT_GENERATOR_CONFIG,
        attack_config=DEFAULT_ATTACK_CONFIG,
        params_digest="",
    )
    with pytest.raises(ValueError, match="empty corpus"):
        fit_pipeline(empty)


def test_rejects_extracting_features_from_nothing() -> None:
    """Zero sessions must fail loudly rather than produce an empty matrix."""
    with pytest.raises(ValueError, match="zero sessions"):
        extract_features_causally(())
