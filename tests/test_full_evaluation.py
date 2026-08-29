"""Tests for the full evaluation orchestration and its gate assessment.

The gate logic gets the most attention here, because it is the part that
produces a recommendation rather than a number, and because it has to behave
correctly in the case that actually arises on this corpus: a comparator whose
precision is saturated at 1.0 and therefore cannot be beaten on precision at
any recall. A gate that silently read False in that situation, or silently read
True, would both be wrong in ways a passing test suite should not permit.
"""

from __future__ import annotations

import numpy as np
import pytest

from detect.calibration import DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO
from eval.cost_sweep import sweep_thresholds
from eval.full_evaluation import (
    FullEvaluationReport,
    GateAssessment,
    _assess_gate,
    format_full_evaluation_report,
    run_full_evaluation,
)
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus

_CORPUS_SESSIONS = 3000
_CORPUS_SEED = 42


@pytest.fixture(scope="module")
def report() -> FullEvaluationReport:
    """Runs the evaluation once and shares it across the module's tests.

    The sensitivity grid is skipped here and covered by `test_sensitivity.py`;
    running thirteen full regenerate-retrain cycles inside the unit suite
    would dominate its runtime without testing anything the grid tests do not.

    Returns:
        The report.
    """
    corpus = build_evaluation_corpus(_CORPUS_SESSIONS, seed=_CORPUS_SEED)
    return run_full_evaluation(
        corpus,
        n_resamples=120,
        latency_sessions=400,
        sensitivity_sessions=800,
        run_sensitivity=False,
    )


def _gate_case(
    baseline_blocked: np.ndarray, ensemble_score: np.ndarray, labels: np.ndarray
) -> GateAssessment:
    """Assembles a gate assessment from hand-built arrays.

    Args:
        baseline_blocked: Rules-only verdicts.
        ensemble_score: Ensemble scores over the same rows.
        labels: Ground-truth labels.

    Returns:
        The assessment.
    """
    baseline_score = np.where(baseline_blocked, 1.0, 0.0)
    threshold = 0.5
    ensemble_blocked = ensemble_score >= threshold
    sweep = sweep_thresholds(labels, ensemble_score, n_points=101)
    return _assess_gate(
        labels, baseline_score, ensemble_score, baseline_blocked, ensemble_blocked, sweep
    )


def test_report_covers_every_committed_metric(report: FullEvaluationReport) -> None:
    """Each deliverable the project committed to must be present in the report."""
    assert report.ensemble_scores.auc_pr.n_resamples == 120
    assert report.ensemble_scores.auc_roc.point_estimate > 0.0
    assert report.calibration.brier >= 0.0
    assert len(report.calibration.bins) > 0
    assert len(report.baseline_class_breakdown) == 3
    assert len(report.ensemble_class_breakdown) == 3
    assert len(report.variant_comparison) > 0
    assert len(report.cost_sweeps) == 5
    # The detailed table must be the sweep at the assumption that set the
    # threshold, not whichever ratio happens to be first in the list.
    assert report.cost_ratio == DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO
    assert report.cost_ratio in {sweep.cost_ratio for sweep in report.cost_sweeps}
    assert set(report.latency.percentiles) == {50.0, 95.0, 99.0}
    assert report.gate.mcnemar is not None
    assert report.gate.delong is not None
    assert len(report.top_attribution_features) > 0
    assert report.layer3_scores.auc_pr.point_estimate > 0.0


def test_auc_pr_is_the_headline_and_beats_the_baseline(report: FullEvaluationReport) -> None:
    """The ensemble's ranking must be clearly better than a block/allow verdict."""
    assert report.ensemble_scores.auc_pr.point_estimate > report.baseline_scores.auc_pr.point_estimate
    assert report.ensemble_scores.is_binary_score is False
    assert report.baseline_scores.is_binary_score is True


def test_layer3_is_scored_on_the_residual_not_the_full_block(
    report: FullEvaluationReport,
) -> None:
    """Layer 3's own figure must describe the rows the rules could not resolve.

    The ensemble's AUC is inflated by the deterministic layers resolving most
    of the population perfectly. Reporting only that number would credit the
    model with separation it did not perform, so the residual-only figure is
    computed separately and must be the stricter of the two.
    """
    assert report.layer3_scores.name.startswith("Layer 3 alone")
    assert (
        report.layer3_scores.auc_pr.point_estimate
        < report.ensemble_scores.auc_pr.point_estimate
    )


def test_intervals_bracket_their_point_estimates(report: FullEvaluationReport) -> None:
    """Every reported interval must contain the number it qualifies."""
    for summary in (report.baseline_scores, report.ensemble_scores):
        for interval in (summary.auc_pr, summary.auc_roc):
            assert interval.lower <= interval.point_estimate <= interval.upper


def test_delong_flags_the_binary_baseline(report: FullEvaluationReport) -> None:
    """The degeneracy caveat must be carried on the result, not left to prose."""
    assert report.gate.delong is not None
    assert report.gate.delong.baseline_is_degenerate is True


def test_rules_invisible_variants_are_marked(report: FullEvaluationReport) -> None:
    """The two variants Layer 3 exists for must be identifiable in the table."""
    marked = {c.variant for c in report.variant_comparison if c.is_rules_invisible}
    assert marked <= {"rapid_reuse", "behavioral_only"}
    for comparison in report.variant_comparison:
        if comparison.is_rules_invisible:
            assert comparison.rules_recall == pytest.approx(0.0)


def test_ensemble_never_loses_recall_on_any_variant(report: FullEvaluationReport) -> None:
    """Layer 3 only adds blocks, so per-variant recall can never fall."""
    for comparison in report.variant_comparison:
        assert comparison.ensemble_recall >= comparison.rules_recall - 1e-12


def test_class_breakdown_totals_agree_between_systems(report: FullEvaluationReport) -> None:
    """Both systems must be scored over the same test-block population."""
    baseline_totals = {b.attack_class: b.total for b in report.baseline_class_breakdown}
    ensemble_totals = {b.attack_class: b.total for b in report.ensemble_class_breakdown}
    assert baseline_totals == ensemble_totals


def test_gate_reports_saturation_when_the_baseline_is_perfect() -> None:
    """A precision-1.0 comparator must be diagnosed, not just scored False.

    This is the case the corpus actually produces, and the one where a bare
    `precision_gate_passed = False` would be read as Layer 3 failing when it
    reflects a property of the comparator instead.
    """
    n_attacks, n_legitimate = 100, 900
    labels = np.array([True] * n_attacks + [False] * n_legitimate)
    # Baseline catches 60 of 100 attacks and never fires on a legitimate session.
    baseline_blocked = np.zeros(n_attacks + n_legitimate, dtype=bool)
    baseline_blocked[:60] = True
    # Ensemble keeps those and adds 30 more attacks, still with no false positives.
    ensemble_score = np.zeros(n_attacks + n_legitimate)
    ensemble_score[:90] = 0.9

    gate = _gate_case(baseline_blocked, ensemble_score, labels)

    assert gate.baseline_precision == pytest.approx(1.0)
    assert gate.baseline_precision_is_saturated is True
    assert gate.precision_gate_passed is False
    assert gate.recall_gain_at_baseline_precision > 0.0
    assert gate.layer3_earns_its_place is True
    assert "saturated" in gate.rationale


def test_gate_fails_when_layer3_adds_no_recall() -> None:
    """A Layer 3 that adds nothing must be recommended for removal, plainly."""
    labels = np.array([True] * 10 + [False] * 90)
    baseline_blocked = np.array([True] * 6 + [False] * 4 + [False] * 90)
    # Scores that reproduce the baseline exactly and never add a catch.
    ensemble_score = np.where(baseline_blocked, 1.0, 0.0)

    gate = _gate_case(baseline_blocked, ensemble_score, labels)

    assert gate.is_degenerate is True
    assert gate.mcnemar is None
    assert gate.delong is None
    assert gate.recall_gain_at_baseline_precision <= 0.0
    assert gate.layer3_earns_its_place is False
    assert "changes no decision" in gate.rationale
    assert "does not earn its place" in gate.rationale


def test_gate_fails_when_the_gain_is_not_significant() -> None:
    """A real but statistically unsupported gain must not pass the gate."""
    labels = np.array([True] * 10 + [False] * 990)
    baseline_blocked = np.zeros(1000, dtype=bool)
    baseline_blocked[:6] = True
    # One extra catch: a real gain, but a single discordant pair is not evidence.
    ensemble_score = np.zeros(1000)
    ensemble_score[:7] = 0.9

    gate = _gate_case(baseline_blocked, ensemble_score, labels)

    assert gate.recall_gain_at_baseline_precision > 0.0
    assert gate.mcnemar is not None
    assert not gate.mcnemar.favors_challenger
    assert gate.layer3_earns_its_place is False
    assert "does not favour it" in gate.rationale


def test_gate_passes_on_an_unsaturated_baseline() -> None:
    """The non-saturated branch must also work, with its own rationale."""
    labels = np.array([True] * 400 + [False] * 1600)
    baseline_blocked = np.zeros(2000, dtype=bool)
    baseline_blocked[:200] = True
    baseline_blocked[400:450] = True  # fifty false positives, so precision is 0.8

    ensemble_score = np.zeros(2000)
    ensemble_score[:380] = 0.9
    ensemble_score[400:450] = 0.9

    gate = _gate_case(baseline_blocked, ensemble_score, labels)

    assert gate.baseline_precision < 1.0
    assert gate.baseline_precision_is_saturated is False
    assert gate.layer3_earns_its_place is True
    assert "saturated" not in gate.rationale


def test_gate_reads_fixed_recall_from_the_baseline(report: FullEvaluationReport) -> None:
    """The comparison point must be the baseline's own recall, not an invented one."""
    assert report.gate.fixed_recall == pytest.approx(report.baseline_recall)
    assert report.gate.baseline_precision == pytest.approx(report.baseline_precision)


def test_formatted_report_states_the_verdict_and_its_caveats(report: FullEvaluationReport) -> None:
    """A reader must not be able to find the verdict without its qualification."""
    rendered = format_full_evaluation_report(report)

    assert "HARD GATE" in rendered
    assert "VERDICT" in rendered
    assert report.gate.rationale in rendered
    assert "AUC-PR" in rendered
    assert "95% CI" in rendered
    assert "Brier score" in rendered
    assert "blocked legit/10k" in rendered
    assert "p50" in rendered and "p99" in rendered
    assert "rules-invisible" in rendered
    # The binary-baseline caveat must travel with the DeLong number.
    assert "balanced accuracy" in rendered
    # Layer 3's own figure must appear next to the inherited ensemble one.
    assert "Layer 3 alone" in rendered
    assert "largely inherited" in rendered


def test_report_is_reproducible() -> None:
    """The same corpus and seeds must produce the same headline numbers."""
    corpus = build_evaluation_corpus(1500, seed=7)
    first = run_full_evaluation(
        corpus, n_resamples=60, latency_sessions=200, run_sensitivity=False
    )
    second = run_full_evaluation(
        corpus, n_resamples=60, latency_sessions=200, run_sensitivity=False
    )

    assert first.ensemble_scores.auc_pr.point_estimate == second.ensemble_scores.auc_pr.point_estimate
    assert first.ensemble_scores.auc_pr.lower == second.ensemble_scores.auc_pr.lower
    assert first.threshold == second.threshold
    assert first.gate.layer3_earns_its_place == second.gate.layer3_earns_its_place


def test_rejects_an_empty_corpus() -> None:
    """An empty corpus has nothing to evaluate."""
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
        run_full_evaluation(empty)
