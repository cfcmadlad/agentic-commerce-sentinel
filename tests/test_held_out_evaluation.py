"""Tests for the one-shot held-out evaluation.

The property that matters most is that this module never retrains or
recalibrates anything -- it must apply the `PipelineFit` it is handed
byte-for-byte. Everything else here checks that the reported numbers are
arithmetically consistent with what a hand count over the same corpus would
give.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from detect.baseline import RulesOnlyBaseline
from detect.ensemble import ensemble_decide
from eval.held_out_evaluation import (
    BUCKET_BEHAVIORALLY_ORDINARY,
    BUCKET_ELEVATED_BUT_INSUFFICIENT,
    _bucket_for_score,
    _safe_ratio,
    format_held_out_report,
    run_held_out_evaluation,
)
from eval.pipeline import PipelineFit, extract_features_causally, fit_pipeline
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus
from generator.attacks.held_out import build_held_out_corpus

_TRAIN_CORPUS_SESSIONS = 3000
_TRAIN_SEED = 42
_HELD_OUT_SESSIONS = 1500
_HELD_OUT_SEED = 90201


@pytest.fixture(scope="module")
def fit() -> PipelineFit:
    """Fits the ordinary three-class pipeline once, shared read-only.

    Returns:
        The fit.
    """
    corpus = build_evaluation_corpus(_TRAIN_CORPUS_SESSIONS, seed=_TRAIN_SEED)
    return fit_pipeline(corpus)


@pytest.fixture(scope="module")
def held_out_corpus() -> EvaluationCorpus:
    """Builds one held-out corpus shared read-only across this module's tests.

    Returns:
        The corpus.
    """
    return build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)


def test_uses_the_frozen_threshold_verbatim(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """The report's threshold must be exactly the fit's, never recomputed."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    assert report.threshold == fit.threshold


def test_recall_values_are_valid_fractions(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Every reported recall must be a genuine fraction."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    for value in (
        report.baseline_recall,
        report.ensemble_recall,
        report.in_distribution_ensemble_recall,
    ):
        assert 0.0 <= value <= 1.0


def test_ensemble_recall_is_never_below_rules_only(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Layer 3 only ever adds blocks, so the ensemble can't recall less than the baseline."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    assert report.ensemble_recall >= report.baseline_recall - 1e-12


def test_variant_totals_sum_to_n_attacks(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Per-variant totals must partition every attack session exactly once."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    assert sum(v.total for v in report.variant_results) == report.n_attacks


def test_failure_buckets_account_for_every_missed_session(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Caught + bucketed-missed must equal the total attack count."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    caught = sum(v.ensemble_caught for v in report.variant_results)
    missed_and_bucketed = sum(report.failure_buckets.values())
    assert caught + missed_and_bucketed == report.n_attacks


def test_failure_buckets_use_only_known_names(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """No stray bucket name should appear."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    assert set(report.failure_buckets) <= {
        BUCKET_BEHAVIORALLY_ORDINARY,
        BUCKET_ELEVATED_BUT_INSUFFICIENT,
    }


def test_degradation_matches_the_two_recall_figures(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """The convenience property must equal the difference it claims to be."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    expected = report.in_distribution_ensemble_recall - report.ensemble_recall
    assert report.recall_degradation == pytest.approx(expected)


def test_result_is_reproducible(fit: PipelineFit) -> None:
    """The same fit and held-out corpus must produce the same report twice."""
    corpus = build_held_out_corpus(800, seed=90202)
    first = run_held_out_evaluation(fit, corpus)
    second = run_held_out_evaluation(fit, corpus)
    assert first.ensemble_recall == second.ensemble_recall
    assert first.baseline_recall == second.baseline_recall


def test_rejects_a_held_out_corpus_with_no_attacks(fit: PipelineFit) -> None:
    """An all-legitimate corpus has nothing to evaluate recall over."""
    corpus = build_held_out_corpus(300, seed=90203)
    all_legitimate = replace(
        corpus, labeled_sessions=tuple(s for s in corpus.labeled_sessions if not s.is_attack)
    )
    with pytest.raises(ValueError, match="no attack sessions"):
        run_held_out_evaluation(fit, all_legitimate)


def test_formatted_report_states_the_one_shot_framing(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """The report must be legible about what it is and isn't, without external context."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    rendered = format_held_out_report(report)
    assert "held-out" in rendered.lower()
    assert "evaluated once" in rendered.lower()
    assert "in-distribution" in rendered.lower()


def test_model_object_identity_is_unchanged(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Running the evaluation must not mutate or replace the frozen model."""
    model_before = fit.model
    run_held_out_evaluation(fit, held_out_corpus)
    assert fit.model is model_before


def test_hand_counted_recall_matches_for_one_variant(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """Spot-check one variant's ensemble recall against an independent hand count."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    target_variant = report.variant_results[0].variant

    sessions = held_out_corpus.labeled_sessions
    baseline = RulesOnlyBaseline(held_out_corpus.registry, held_out_corpus.resolver)
    decisions = baseline.decide_all(s.trace for s in sessions)
    scores = fit.model.predict_proba(extract_features_causally(sessions))

    caught = 0
    total = 0
    for session, decision, score in zip(sessions, decisions, scores, strict=True):
        if not session.is_attack:
            continue
        if held_out_corpus.variant_by_session.get(session.trace.session_id) != target_variant:
            continue
        total += 1
        behavioral = None if decision.blocked else float(score)
        if ensemble_decide(decision, behavioral, fit.threshold).blocked:
            caught += 1

    hand_recall = caught / total if total else 0.0
    assert hand_recall == pytest.approx(report.variant_results[0].ensemble_recall)


def test_bucket_boundary_fires_at_exactly_half_the_threshold() -> None:
    """The near-miss split must fire exactly at half the threshold, not some other cutoff."""
    assert _bucket_for_score(0.05, threshold=0.10) == BUCKET_ELEVATED_BUT_INSUFFICIENT
    assert _bucket_for_score(0.0499, threshold=0.10) == BUCKET_BEHAVIORALLY_ORDINARY
    assert _bucket_for_score(0.0, threshold=0.10) == BUCKET_BEHAVIORALLY_ORDINARY


def test_reproducible_across_two_independent_fits() -> None:
    """Refitting from scratch with the same seed must reproduce the same held-out result."""
    fit_a = fit_pipeline(build_evaluation_corpus(_TRAIN_CORPUS_SESSIONS, seed=_TRAIN_SEED))
    fit_b = fit_pipeline(build_evaluation_corpus(_TRAIN_CORPUS_SESSIONS, seed=_TRAIN_SEED))
    held_out = build_held_out_corpus(800, seed=90204)

    report_a = run_held_out_evaluation(fit_a, held_out)
    report_b = run_held_out_evaluation(fit_b, held_out)
    assert report_a.ensemble_recall == report_b.ensemble_recall
    assert report_a.threshold == report_b.threshold


def test_variant_results_are_sorted_by_name(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> None:
    """A stable, alphabetic order makes the report diffable across runs."""
    report = run_held_out_evaluation(fit, held_out_corpus)
    names = [v.variant for v in report.variant_results]
    assert names == sorted(names)


def test_safe_ratio_handles_zero_denominator() -> None:
    """The shared ratio helper must not raise on an empty denominator."""
    assert _safe_ratio(0, 0) == 0.0
    assert _safe_ratio(3, 0) == 0.0


def test_all_scores_are_finite(fit: PipelineFit, held_out_corpus: EvaluationCorpus) -> None:
    """A NaN or inf score slipping through would corrupt every downstream ratio."""
    features = extract_features_causally(held_out_corpus.labeled_sessions)
    scores = fit.model.predict_proba(features)
    assert np.all(np.isfinite(scores))
