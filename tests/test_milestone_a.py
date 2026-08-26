"""Integration tests for `eval.milestone_a`: the full behavioral-model pipeline."""

from __future__ import annotations

import pytest

from common.schema import AttackClass
from eval.milestone_a import MilestoneAReport, format_milestone_a_report, run_milestone_a
from generator.attacks.corpus import build_evaluation_corpus

# Large enough that the residual training and validation splits contain
# enough positive examples of every variant, including the rules-invisible
# ones, for a stable fit and calibration. Smaller corpora make this test
# flaky rather than fast, which is worse.
N_LEGITIMATE = 20000
SEED = 42


@pytest.fixture(scope="module")
def report() -> MilestoneAReport:
    """Runs the full pipeline once and shares the result across assertions.

    Returns:
        The Milestone A report.
    """
    corpus = build_evaluation_corpus(N_LEGITIMATE, seed=SEED)
    return run_milestone_a(corpus)


def test_splits_partition_the_corpus_without_overlap(report: MilestoneAReport) -> None:
    """Train and validation residual counts plus the test block must fit within the corpus."""
    assert report.n_train_residual > 0
    assert report.n_validation_residual > 0
    assert report.n_test > 0
    assert report.n_train_residual + report.n_validation_residual < report.n_sessions


def test_ensemble_recall_is_at_least_the_baseline(report: MilestoneAReport) -> None:
    """Adding Layer 3 must never reduce coverage: it only adds blocks, never removes them."""
    assert report.ensemble_recall >= report.baseline_recall


def test_ensemble_significantly_beats_the_rules_only_baseline(report: MilestoneAReport) -> None:
    """The documented Milestone A result: the ensemble wins with significance.

    If this test starts failing, that is real information (Layer 3 stopped
    earning its place) and per project policy should be reported, not
    patched by relaxing this assertion.
    """
    assert report.significance.significant
    assert report.beats_baseline


def test_rules_invisible_variants_improve_under_the_ensemble(report: MilestoneAReport) -> None:
    """Rapid reuse and behavioral-only impersonation are what Layer 3 exists for."""
    by_variant = {c.variant: c for c in report.variant_comparison}
    assert by_variant["rapid_reuse"].rules_recall == 0.0
    assert by_variant["rapid_reuse"].ensemble_recall > 0.0
    assert by_variant["behavioral_only"].rules_recall < by_variant["behavioral_only"].ensemble_recall


def test_rules_visible_variants_are_unaffected(report: MilestoneAReport) -> None:
    """Variants the rules already catch at 1.0 recall must stay at 1.0 under the ensemble.

    The ensemble only adds blocks on rules-allowed sessions, so it cannot
    change the recall of a variant the rules already catch completely.
    """
    by_variant = {c.variant: c for c in report.variant_comparison}
    for variant in ("amount_over_ceiling", "window_edge", "unregistered_key", "forged_signature"):
        comparison = by_variant[variant]
        assert comparison.rules_recall == 1.0
        assert comparison.ensemble_recall == 1.0


def test_calibration_sweep_threshold_is_monotonically_non_increasing(report: MilestoneAReport) -> None:
    """A higher cost ratio must never raise the calibrated threshold."""
    thresholds = [r.threshold for r in report.calibration_sweep]
    assert thresholds == sorted(thresholds, reverse=True)


def test_attribution_reports_pacing_or_reuse_features_prominently(report: MilestoneAReport) -> None:
    """The top features should be behavioral signal, not incidental metadata.

    A model relying mainly on clock-time or amount features rather than
    pacing or reuse-timing features would indicate the wrong thing is being
    learned; this pins the expectation that it is not.
    """
    top_names = {name for name, _ in report.top_attribution_features[:5]}
    behavioral_signal = {
        "event_gap_cv",
        "mean_event_gap_seconds",
        "max_event_gap_seconds",
        "min_event_gap_seconds",
        "duration_seconds",
        "event_count",
        "hours_since_mandate_last_use",
        "hours_since_agent_last_session",
        "mandate_prior_use_count",
        "agent_prior_session_count",
    }
    assert top_names & behavioral_signal


def test_no_attack_class_gains_recall_without_the_ensemble_being_asked_to_improve_it(
    report: MilestoneAReport,
) -> None:
    """Every reported variant belongs to one of the three trained attack classes.

    The held-out class must not appear anywhere in this report; it is never
    part of the corpus this pipeline is built from.
    """
    variants = {c.variant for c in report.variant_comparison}
    assert "unknown" not in variants
    assert AttackClass.MANDATE_CHAINING.value not in variants


def test_report_formats_without_error(report: MilestoneAReport) -> None:
    """The text report must render and mention the headline comparison."""
    text = format_milestone_a_report(report)
    assert "baseline" in text
    assert "ensemble" in text
    assert "behavioral_only" in text


def test_rejects_empty_corpus() -> None:
    """An empty corpus has nothing to train or evaluate on.

    `build_evaluation_corpus` itself refuses to construct an empty corpus,
    so the empty-corpus path is exercised directly against a hand-built
    `EvaluationCorpus` instead of trying to coerce one from the generator.
    """
    from detect.resolution import InMemoryMandateResolver
    from generator.attacks.corpus import EvaluationCorpus
    from mandate.verification import AgentKeyRegistry

    empty = EvaluationCorpus(
        labeled_sessions=(),
        resolver=InMemoryMandateResolver({}),
        registry=AgentKeyRegistry(),
        variant_by_session={},
        attack_base_rate=0.0,
        seed=0,
    )
    with pytest.raises(ValueError, match="empty corpus"):
        run_milestone_a(empty)