"""The full evaluation: ranking metrics, intervals, calibration, cost, latency.

Milestone A established one thing -- that the ensemble beats the rules-only
baseline on a paired McNemar test -- and deliberately deferred everything that
would tell a reader how much to trust that. This module supplies the rest:
AUC-PR with bootstrap confidence intervals, AUC-ROC and a DeLong comparison,
a calibration curve and Brier score, per-class and per-variant breakdowns for
both systems, a cost sweep across the entire threshold range, end-to-end
per-decision latency as a distribution, and a sensitivity analysis that
regenerates and re-evaluates everything across a grid of generator parameters.

The gate this feeds, and its one structural complication
-------------------------------------------------------
The project's standing policy is that Layer 3 has to beat the rules-only
baseline on precision at fixed recall, with significance, or be dropped. That
comparison has a wrinkle worth stating before any number is read rather than
after: the rules-only baseline's precision on this corpus is 1.0 and is 1.0 by
construction, because the legitimate generator places every legitimate session
inside its own mandate's scope, so no deterministic rule can fire on one. A
comparator with perfect precision cannot be beaten on precision at any recall;
it can only be tied. `precision_gate_passed` therefore reports the literal
comparison and will read False whenever the baseline is at 1.0, and
`GateAssessment` carries the diagnosis alongside it so the number is never
quoted without its reason.

What the gate is actually asking -- whether Layer 3 earns its place -- is
answered by the comparison that is not structurally foreclosed: the baseline's
recall is capped well below 1.0 because two attack variants are invisible to
every rule it has, and the question is whether Layer 3 closes that gap without
giving up the precision the baseline achieves. `recall_gain_at_baseline_
precision` measures exactly that, and `layer3_earns_its_place` combines it
with the paired significance test. Both readings are reported. Neither is
selected after the fact.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from uuid import UUID

import numpy as np

from common.schema import AttackClass, LabeledSession
from detect.attribution import compute_attribution, top_features
from detect.baseline import RulesOnlyBaseline
from detect.calibration import DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO
from eval.bootstrap import DEFAULT_RESAMPLES, BootstrapInterval, bootstrap_metric
from eval.cost_sweep import (
    CostSweep,
    format_cost_sweep,
    sweep_across_cost_ratios,
    sweep_thresholds,
)
from eval.delong import DeLongResult, delong_test
from eval.latency import (
    LatencyReport,
    TimedDecisionPipeline,
    format_latency_report,
    measure_latency,
)
from eval.metrics import CalibrationCurve, average_precision, calibration_curve, roc_auc
from eval.pipeline import PipelineFit, fit_pipeline, precision_recall
from eval.sensitivity import (
    GridOutcome,
    GridPoint,
    SensitivityReport,
    evaluate_grid,
    format_sensitivity_report,
    rules_invisible_recall,
    summarize_variant_counts,
)
from eval.significance import McNemarResult, mcnemar_test
from generator.attack_config import RULES_INVISIBLE_VARIANTS
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus

logger = logging.getLogger(__name__)

DEFAULT_ATTRIBUTION_TOP_N = 10
DEFAULT_CALIBRATION_BINS = 10

# Legitimate sessions per sensitivity grid point. Deliberately the same as the
# headline run rather than smaller: at a reduced size the held-out test block
# contains only a handful of rules-invisible attacks, and the resulting
# per-point recall swings by tens of percentage points on sampling noise alone.
# A grid measured there cannot distinguish a real parameter sensitivity from a
# small-sample artifact, and its numbers are not comparable with the headline
# ones a reader will see directly above them. Thirteen full
# regenerate-retrain-re-evaluate cycles at this size cost a few minutes, which
# is the right trade for a robustness check that means anything.
DEFAULT_SENSITIVITY_SESSIONS = 20000

# Sessions timed for the latency distribution. A p99 over fewer than a few
# thousand decisions is an order statistic over a handful of samples.
DEFAULT_LATENCY_SESSIONS = 3000


@dataclass(frozen=True)
class ScoreSummary:
    """Ranking metrics for one scoring system, with intervals.

    Attributes:
        name: Which system this describes.
        auc_pr: AUC-PR with its bootstrap confidence interval. The primary
            metric, because the class imbalance makes ROC insensitive to
            exactly the false positives that matter operationally.
        auc_roc: AUC-ROC with its interval. Secondary, and the quantity
            DeLong's test is defined over.
        is_binary_score: True when the score takes at most two distinct
            values, meaning its AUCs are balanced accuracy and carry no
            ranking information. Carried so a table cannot present a binary
            score's AUC next to a ranked one's without the caveat.
    """

    name: str
    auc_pr: BootstrapInterval
    auc_roc: BootstrapInterval
    is_binary_score: bool


@dataclass(frozen=True)
class ClassBreakdown:
    """Detection outcome for one ground-truth attack class, for one system.

    Mirrors `eval.gate.ClassBreakdown`, which reports the same shape for the
    rules-only baseline over a whole corpus; this one is computed on the
    held-out test block for whichever system is being described, so the two
    systems can be placed side by side.

    Attributes:
        attack_class: The class described.
        total: Sessions of this class in the test block.
        caught: How many the system blocked.
        recall: `caught / total`.
        recall_by_variant: Per-variant recall within the class. A class
            average hides the rules-invisible variants, which are the only
            place Layer 3 can change an outcome.
    """

    attack_class: AttackClass
    total: int
    caught: int
    recall: float
    recall_by_variant: dict[str, float]


@dataclass(frozen=True)
class VariantComparison:
    """Rules-only vs ensemble recall for one attack sub-variant.

    Attributes:
        variant: The sub-variant.
        total: Sessions of this variant in the test block.
        rules_recall: Rules-only recall.
        ensemble_recall: Ensemble recall.
        is_rules_invisible: Whether no deterministic rule can catch this
            variant, making it one of the two Layer 3 exists for.
    """

    variant: str
    total: int
    rules_recall: float
    ensemble_recall: float
    is_rules_invisible: bool


@dataclass(frozen=True)
class GateAssessment:
    """The hard gate: does Layer 3 earn its place, and by which reading.

    Attributes:
        fixed_recall: The recall level both systems are compared at, namely
            the rules-only baseline's own recall on the test block.
        baseline_precision_at_fixed_recall: Baseline precision there.
        ensemble_precision_at_fixed_recall: Best ensemble precision at or
            above `fixed_recall`.
        precision_gate_passed: Whether the ensemble strictly beat the
            baseline's precision at that recall. Read this together with
            `baseline_precision_is_saturated`.
        baseline_precision_is_saturated: True when the baseline's precision is
            1.0, in which case `precision_gate_passed` cannot be True for any
            detector and the literal comparison is uninformative rather than
            unfavourable.
        baseline_precision: Baseline precision at its own operating point.
        ensemble_recall_at_baseline_precision: The highest recall the ensemble
            reaches without dropping below the baseline's precision.
        recall_gain_at_baseline_precision: That recall minus the baseline's.
            The quantity that is not structurally foreclosed, and the one the
            verdict rests on.
        mcnemar: Paired significance test at the chosen operating threshold,
            or None when the two systems agree on every session and there are
            no discordant pairs to test.
        delong: DeLong comparison of the two AUCs, or None when the two
            scores rank every session identically.
        is_degenerate: True when Layer 3 produced exactly the rules-only
            outcome. Neither significance test is defined there, and none is
            needed: a layer that changes no decision adds nothing.
        layer3_earns_its_place: The verdict. True only when the ensemble
            achieves strictly more recall than the baseline at no cost to the
            baseline's precision, and the paired test favours it.
        rationale: One-line statement of why the verdict came out as it did.
    """

    fixed_recall: float
    baseline_precision_at_fixed_recall: float
    ensemble_precision_at_fixed_recall: float
    precision_gate_passed: bool
    baseline_precision_is_saturated: bool
    baseline_precision: float
    ensemble_recall_at_baseline_precision: float
    recall_gain_at_baseline_precision: float
    mcnemar: McNemarResult | None
    delong: DeLongResult | None
    is_degenerate: bool
    layer3_earns_its_place: bool
    rationale: str


@dataclass(frozen=True)
class MilestoneBReport:
    """Everything the full evaluation produced.

    Attributes:
        n_sessions: Corpus size.
        n_test: Test block size.
        attack_base_rate: Realized attack fraction in the corpus.
        params_digest: Digest of the generator parameters used.
        threshold: The calibrated operating threshold.
        baseline_precision: Rules-only precision on the test block.
        baseline_recall: Rules-only recall on the test block.
        ensemble_precision: Ensemble precision on the test block.
        ensemble_recall: Ensemble recall on the test block.
        baseline_scores: Ranking metrics for the rules-only baseline.
        ensemble_scores: Ranking metrics for the ensemble. Note that these are
            dominated by the deterministic layers, which already resolve most
            of the population perfectly; a high ensemble AUC-PR is largely
            inherited rather than learned.
        layer3_scores: Ranking metrics for the Layer 3 score alone, over the
            test block's rules-allowed residual. This is the number that
            characterises what the model actually learned, and it is
            substantially lower than the ensemble's by construction, because
            the residual is exactly the population the deterministic layers
            could not resolve.
        calibration: Reliability diagram and Brier score for the Layer 3
            model, over the test block's rules-allowed residual -- the rows
            where the model's output is the system's actual probability.
        baseline_class_breakdown: Per-class, per-variant recall for the
            rules-only baseline.
        ensemble_class_breakdown: The same for the ensemble.
        variant_comparison: Side-by-side per-variant recall.
        cost_sweeps: Full-range threshold sweeps, one per cost ratio.
        cost_ratio: The cost-ratio assumption that actually drove the
            operating threshold, so the detailed sweep table shows the one
            the reported numbers came from rather than whichever happened to
            be first in the list.
        latency: End-to-end per-decision latency distribution.
        sensitivity: Outcomes across the generator parameter grid, or None
            when the grid was deliberately skipped. A None here means the
            report is incomplete, and the renderer says so rather than
            leaving the omission to be inferred.
        gate: The hard-gate assessment.
        top_attribution_features: Global SHAP ranking from the trained model.
    """

    n_sessions: int
    n_test: int
    attack_base_rate: float
    params_digest: str
    threshold: float
    baseline_precision: float
    baseline_recall: float
    ensemble_precision: float
    ensemble_recall: float
    baseline_scores: ScoreSummary
    ensemble_scores: ScoreSummary
    layer3_scores: ScoreSummary
    calibration: CalibrationCurve
    baseline_class_breakdown: tuple[ClassBreakdown, ...]
    ensemble_class_breakdown: tuple[ClassBreakdown, ...]
    variant_comparison: tuple[VariantComparison, ...]
    cost_sweeps: tuple[CostSweep, ...]
    cost_ratio: float
    latency: LatencyReport
    sensitivity: SensitivityReport | None
    gate: GateAssessment
    top_attribution_features: tuple[tuple[str, float], ...]


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 on an empty denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 when the denominator is zero.
    """
    return numerator / denominator if denominator else 0.0


def _summarize_scores(
    name: str, labels: np.ndarray, scores: np.ndarray, n_resamples: int, seed: int
) -> ScoreSummary:
    """Computes both ranking metrics with bootstrap intervals for one system.

    Args:
        name: Which system is being summarised.
        labels: Ground-truth `is_attack` labels.
        scores: Per-row scores for this system.
        n_resamples: Bootstrap resamples per interval.
        seed: Bootstrap seed, so intervals reproduce exactly.

    Returns:
        The summary.
    """
    return ScoreSummary(
        name=name,
        auc_pr=bootstrap_metric(
            labels, scores, average_precision, n_resamples=n_resamples, seed=seed
        ),
        auc_roc=bootstrap_metric(labels, scores, roc_auc, n_resamples=n_resamples, seed=seed),
        is_binary_score=int(np.unique(scores).size) <= 2,
    )


def _variant_names(
    sessions: tuple[LabeledSession, ...],
    variant_by_session: dict[UUID, str],
    mask: np.ndarray,
) -> list[str]:
    """Lists the attack sub-variant of every attack session under a mask.

    Args:
        sessions: The full corpus, aligned with `mask`.
        variant_by_session: Session ID to sub-variant, ground-truth metadata.
        mask: Boolean mask selecting the rows of interest.

    Returns:
        Sub-variant names, in corpus order, for masked attack sessions.
    """
    return [
        variant_by_session.get(labeled.trace.session_id, "unknown")
        for index, labeled in enumerate(sessions)
        if mask[index] and labeled.is_attack
    ]


def _class_breakdown(
    sessions: tuple[LabeledSession, ...],
    variant_by_session: dict[UUID, str],
    test_mask: np.ndarray,
    blocked: np.ndarray,
) -> tuple[ClassBreakdown, ...]:
    """Builds the per-class, per-variant recall breakdown for one system.

    Args:
        sessions: The full corpus, aligned with the mask arrays.
        variant_by_session: Session ID to attack sub-variant.
        test_mask: Boolean mask selecting the test block.
        blocked: Per-session block/allow array for the system described.

    Returns:
        One breakdown per training attack class, in taxonomy order.
    """
    class_totals: Counter[AttackClass] = Counter()
    class_caught: Counter[AttackClass] = Counter()
    variant_totals: dict[AttackClass, Counter[str]] = {}
    variant_caught: dict[AttackClass, Counter[str]] = {}

    for index, labeled in enumerate(sessions):
        if not test_mask[index] or not labeled.is_attack:
            continue
        attack_class = labeled.attack_class
        variant = variant_by_session.get(labeled.trace.session_id, "unknown")
        class_totals[attack_class] += 1
        variant_totals.setdefault(attack_class, Counter())[variant] += 1
        variant_caught.setdefault(attack_class, Counter())
        if blocked[index]:
            class_caught[attack_class] += 1
            variant_caught[attack_class][variant] += 1

    return tuple(
        ClassBreakdown(
            attack_class=attack_class,
            total=class_totals[attack_class],
            caught=class_caught[attack_class],
            recall=_safe_ratio(class_caught[attack_class], class_totals[attack_class]),
            recall_by_variant={
                variant: _safe_ratio(variant_caught[attack_class][variant], total)
                for variant, total in sorted(variant_totals.get(attack_class, Counter()).items())
            },
        )
        for attack_class in (
            AttackClass.MANDATE_REPLAY,
            AttackClass.SCOPE_VIOLATION,
            AttackClass.AGENT_IMPERSONATION,
        )
    )


def _variant_comparison(
    sessions: tuple[LabeledSession, ...],
    variant_by_session: dict[UUID, str],
    test_mask: np.ndarray,
    baseline_blocked: np.ndarray,
    ensemble_blocked: np.ndarray,
) -> tuple[VariantComparison, ...]:
    """Compares rules-only and ensemble recall for every sub-variant.

    Args:
        sessions: The full corpus, aligned with the mask arrays.
        variant_by_session: Session ID to attack sub-variant.
        test_mask: Boolean mask selecting the test block.
        baseline_blocked: Per-session rules-only block/allow array.
        ensemble_blocked: Per-session ensemble block/allow array.

    Returns:
        One comparison per variant present in the test block, sorted by name.
    """
    totals: Counter[str] = Counter()
    rules_caught: Counter[str] = Counter()
    ensemble_caught: Counter[str] = Counter()

    for index, labeled in enumerate(sessions):
        if not test_mask[index] or not labeled.is_attack:
            continue
        variant = variant_by_session.get(labeled.trace.session_id, "unknown")
        totals[variant] += 1
        if baseline_blocked[index]:
            rules_caught[variant] += 1
        if ensemble_blocked[index]:
            ensemble_caught[variant] += 1

    return tuple(
        VariantComparison(
            variant=variant,
            total=total,
            rules_recall=_safe_ratio(rules_caught[variant], total),
            ensemble_recall=_safe_ratio(ensemble_caught[variant], total),
            is_rules_invisible=variant in RULES_INVISIBLE_VARIANTS,
        )
        for variant, total in sorted(totals.items())
    )


def _assess_gate(
    labels: np.ndarray,
    baseline_score: np.ndarray,
    ensemble_score: np.ndarray,
    baseline_blocked: np.ndarray,
    ensemble_blocked: np.ndarray,
    sweep: CostSweep,
) -> GateAssessment:
    """Evaluates the standing gate policy on the held-out test block.

    Args:
        labels: Ground-truth `is_attack` labels for the test block.
        baseline_score: Binary rules-only score over the same rows.
        ensemble_score: Ensemble score over the same rows.
        baseline_blocked: Rules-only verdicts over the same rows.
        ensemble_blocked: Ensemble verdicts at the calibrated threshold.
        sweep: A full-range threshold sweep over the ensemble score, used to
            read precision at fixed recall and recall at fixed precision off
            one consistent curve.

    Returns:
        The assessment, with both readings and an explicit rationale.
    """
    baseline_precision, baseline_recall = precision_recall(baseline_blocked, labels)

    at_fixed_recall = sweep.at_recall(baseline_recall)
    ensemble_precision_at_recall = (
        at_fixed_recall.precision if at_fixed_recall is not None else 0.0
    )
    baseline_saturated = baseline_precision >= 1.0

    matching_precision = [
        point for point in sweep.points if point.precision >= baseline_precision
    ]
    ensemble_recall_at_precision = (
        max(point.recall for point in matching_precision) if matching_precision else 0.0
    )
    recall_gain = ensemble_recall_at_precision - baseline_recall

    # A Layer 3 that changes no decision leaves McNemar with no discordant
    # pairs and DeLong with no variance, so both are undefined. That is not an
    # error to propagate: it is the clearest possible gate failure, and the
    # evaluation has to be able to report it rather than crash on it.
    baseline_correct = baseline_blocked == labels
    ensemble_correct = ensemble_blocked == labels
    verdicts_identical = bool(np.array_equal(baseline_correct, ensemble_correct))
    scores_identical = bool(np.array_equal(baseline_score, ensemble_score))

    mcnemar = None if verdicts_identical else mcnemar_test(baseline_correct, ensemble_correct)
    delong = None if scores_identical else delong_test(labels, baseline_score, ensemble_score)

    favors_challenger = bool(mcnemar is not None and mcnemar.favors_challenger)
    earns_its_place = bool(recall_gain > 0.0 and favors_challenger)

    if verdicts_identical:
        rationale = (
            "Layer 3 reproduced the rules-only outcome on every session; it changes no "
            "decision and does not earn its place"
        )
    elif earns_its_place and mcnemar is not None and baseline_saturated:
        rationale = (
            f"the baseline's precision is saturated at 1.0, so it cannot be beaten on "
            f"precision at fixed recall; Layer 3 instead adds {recall_gain:+.4f} recall at "
            f"that same precision, and the paired McNemar test favours it "
            f"(p={mcnemar.p_value:.3g})"
        )
    elif earns_its_place and mcnemar is not None:
        rationale = (
            f"Layer 3 adds {recall_gain:+.4f} recall while holding the baseline's precision "
            f"of {baseline_precision:.4f}, and the paired McNemar test favours it "
            f"(p={mcnemar.p_value:.3g})"
        )
    elif recall_gain <= 0.0:
        rationale = (
            f"Layer 3 adds no recall at the baseline's precision of {baseline_precision:.4f}; "
            f"it does not earn its place and should be dropped"
        )
    else:
        observed_p = "undefined" if mcnemar is None else f"{mcnemar.p_value:.3g}"
        rationale = (
            f"Layer 3 adds {recall_gain:+.4f} recall but the paired McNemar test does not "
            f"favour it (p={observed_p}); it does not earn its place"
        )

    return GateAssessment(
        fixed_recall=baseline_recall,
        baseline_precision_at_fixed_recall=baseline_precision,
        ensemble_precision_at_fixed_recall=ensemble_precision_at_recall,
        precision_gate_passed=bool(ensemble_precision_at_recall > baseline_precision),
        baseline_precision_is_saturated=bool(baseline_saturated),
        baseline_precision=baseline_precision,
        ensemble_recall_at_baseline_precision=ensemble_recall_at_precision,
        recall_gain_at_baseline_precision=recall_gain,
        mcnemar=mcnemar,
        delong=delong,
        is_degenerate=verdicts_identical,
        layer3_earns_its_place=earns_its_place,
        rationale=rationale,
    )


def evaluate_grid_point(point: GridPoint, n_legitimate: int, seed: int) -> GridOutcome:
    """Regenerates, retrains and re-evaluates at one sensitivity grid point.

    A full independent cycle on purpose: reusing the established setting's
    trained model against perturbed data would measure transfer, not
    sensitivity, and would understate how much the result depends on the
    parameters.

    Args:
        point: The parameter setting to evaluate.
        n_legitimate: Legitimate sessions to generate.
        seed: Corpus seed, shared across grid points so differences come from
            the parameters rather than from the draw.

    Returns:
        The outcome at this grid point.

    Raises:
        ValueError: As propagated from corpus construction or the pipeline fit
            when the perturbed parameters produce a corpus too small or too
            sparse to evaluate. That is a real finding about the parameter
            setting and is not caught here.
    """
    corpus = build_evaluation_corpus(
        n_legitimate,
        seed=seed,
        generator_config=point.generator_config,
        attack_config=point.attack_config,
    )
    fit = fit_pipeline(corpus)
    labels, baseline_score, ensemble_score = fit.test_slice()

    baseline_blocked = fit.baseline_blocked[fit.split.test]
    ensemble_blocked = fit.ensemble_blocked[fit.split.test]
    baseline_precision, baseline_recall = precision_recall(baseline_blocked, labels)
    ensemble_precision, ensemble_recall = precision_recall(ensemble_blocked, labels)

    variants = _variant_names(corpus.labeled_sessions, corpus.variant_by_session, fit.split.test)
    attack_rows = ensemble_blocked[labels]
    variant_counts = summarize_variant_counts(attack_rows, variants)

    mcnemar = mcnemar_test(baseline_blocked == labels, ensemble_blocked == labels)

    return GridOutcome(
        point=point,
        params_digest=corpus.params_digest,
        n_sessions=len(corpus.labeled_sessions),
        attack_base_rate=corpus.attack_base_rate,
        baseline_precision=baseline_precision,
        baseline_recall=baseline_recall,
        ensemble_precision=ensemble_precision,
        ensemble_recall=ensemble_recall,
        ensemble_auc_pr=average_precision(labels, ensemble_score),
        baseline_auc_pr=average_precision(labels, baseline_score),
        rules_invisible_recall=rules_invisible_recall(variant_counts),
        threshold=fit.threshold,
        beats_baseline=mcnemar.favors_challenger and ensemble_recall > baseline_recall,
    )


def _measure_latency(fit: PipelineFit, n_latency_sessions: int) -> LatencyReport:
    """Times the composed detection path over a slice of the corpus.

    A fresh baseline is constructed rather than the fit's own, because the
    fit's ledger has already absorbed the whole corpus and a decision against
    a fully-spent ledger is not the decision a deployment makes.

    Args:
        fit: The pipeline fit supplying the trained model and threshold.
        n_latency_sessions: How many leading sessions to run.

    Returns:
        The latency report.
    """
    corpus = fit.corpus
    traces = [labeled.trace for labeled in corpus.labeled_sessions][:n_latency_sessions]
    pipeline = TimedDecisionPipeline(
        baseline=RulesOnlyBaseline(corpus.registry, corpus.resolver),
        model=fit.model,
        threshold=fit.threshold,
    )
    return measure_latency(pipeline, traces)


def run_milestone_b(
    corpus: EvaluationCorpus,
    cost_ratio: float = DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    n_resamples: int = DEFAULT_RESAMPLES,
    bootstrap_seed: int = 42,
    sensitivity_sessions: int = DEFAULT_SENSITIVITY_SESSIONS,
    latency_sessions: int = DEFAULT_LATENCY_SESSIONS,
    run_sensitivity: bool = True,
) -> MilestoneBReport:
    """Runs the complete evaluation against a corpus.

    Args:
        corpus: A chronologically ordered mixed corpus.
        cost_ratio: The false-negative-to-false-positive cost ratio driving
            the chosen threshold. An assumption; see `detect/calibration.py`.
        n_resamples: Bootstrap resamples per confidence interval.
        bootstrap_seed: Seed for the bootstrap, so intervals reproduce.
        sensitivity_sessions: Legitimate sessions per sensitivity grid point.
        latency_sessions: Sessions to time for the latency distribution.
        run_sensitivity: Whether to run the generator parameter grid. Only
            ever set False for fast tests of the rest of the report; a
            reported result must include it.

    Returns:
        The full report.

    Raises:
        ValueError: If the corpus is empty, or as propagated from the pipeline
            fit and the individual metrics.
    """
    if not corpus.labeled_sessions:
        raise ValueError("cannot run the full evaluation over an empty corpus")

    fit = fit_pipeline(corpus, cost_ratio=cost_ratio)
    sessions = corpus.labeled_sessions
    test_mask = fit.split.test

    labels, baseline_score, ensemble_score = fit.test_slice()
    baseline_blocked = fit.baseline_blocked[test_mask]
    ensemble_blocked = fit.ensemble_blocked[test_mask]

    baseline_precision, baseline_recall = precision_recall(baseline_blocked, labels)
    ensemble_precision, ensemble_recall = precision_recall(ensemble_blocked, labels)

    baseline_scores = _summarize_scores(
        "rules-only baseline", labels, baseline_score, n_resamples, bootstrap_seed
    )
    ensemble_scores = _summarize_scores(
        "ensemble", labels, ensemble_score, n_resamples, bootstrap_seed
    )
    # Scored on the residual alone: on the full test block the rules layers
    # resolve most rows, and an AUC over that population would credit Layer 3
    # with separation the deterministic layers performed.
    residual_test = test_mask & fit.residual
    layer3_scores = _summarize_scores(
        "Layer 3 alone (test residual)",
        fit.labels[residual_test],
        fit.behavioral_score[residual_test],
        n_resamples,
        bootstrap_seed,
    )

    # Calibration is assessed on the same residual rows, for the same reason:
    # those are the rows where the reported probability is the model's own
    # output rather than the saturated 1.0 a rules block contributes, and a
    # reliability diagram over saturated values would describe the rules layer.
    calibration = calibration_curve(
        fit.labels[residual_test],
        fit.behavioral_score[residual_test],
        n_bins=DEFAULT_CALIBRATION_BINS,
    )

    cost_sweeps = sweep_across_cost_ratios(labels, ensemble_score)
    chosen_sweep = sweep_thresholds(labels, ensemble_score, cost_ratio=cost_ratio)

    gate = _assess_gate(
        labels, baseline_score, ensemble_score, baseline_blocked, ensemble_blocked, chosen_sweep
    )

    latency = _measure_latency(fit, latency_sessions)

    sensitivity: SensitivityReport | None = None
    if run_sensitivity:
        sensitivity = evaluate_grid(
            sensitivity_sessions,
            corpus.seed,
            lambda point: evaluate_grid_point(point, sensitivity_sessions, corpus.seed),
        )
    else:
        logger.warning("sensitivity grid skipped; this report is incomplete")

    attribution = compute_attribution(fit.model, fit.features[residual_test])

    report = MilestoneBReport(
        n_sessions=len(sessions),
        n_test=int(test_mask.sum()),
        attack_base_rate=corpus.attack_base_rate,
        params_digest=corpus.params_digest,
        threshold=fit.threshold,
        baseline_precision=baseline_precision,
        baseline_recall=baseline_recall,
        ensemble_precision=ensemble_precision,
        ensemble_recall=ensemble_recall,
        baseline_scores=baseline_scores,
        ensemble_scores=ensemble_scores,
        layer3_scores=layer3_scores,
        calibration=calibration,
        baseline_class_breakdown=_class_breakdown(
            sessions, corpus.variant_by_session, test_mask, fit.baseline_blocked
        ),
        ensemble_class_breakdown=_class_breakdown(
            sessions, corpus.variant_by_session, test_mask, fit.ensemble_blocked
        ),
        variant_comparison=_variant_comparison(
            sessions, corpus.variant_by_session, test_mask, fit.baseline_blocked,
            fit.ensemble_blocked,
        ),
        cost_sweeps=cost_sweeps,
        cost_ratio=cost_ratio,
        latency=latency,
        sensitivity=sensitivity,
        gate=gate,
        top_attribution_features=top_features(attribution, top_n=DEFAULT_ATTRIBUTION_TOP_N),
    )
    logger.info(
        "milestone B: ensemble AUC-PR=%.4f [%.4f, %.4f], gate verdict=%s",
        report.ensemble_scores.auc_pr.point_estimate,
        report.ensemble_scores.auc_pr.lower,
        report.ensemble_scores.auc_pr.upper,
        report.gate.layer3_earns_its_place,
    )
    return report


def _format_score_summary(summary: ScoreSummary) -> list[str]:
    """Renders one system's ranking metrics with their intervals.

    Args:
        summary: The summary to render.

    Returns:
        Lines of the rendered block.
    """
    caveat = (
        "  (binary score: these AUCs are balanced accuracy and carry no ranking information)"
        if summary.is_binary_score
        else ""
    )
    lines = [
        f"  {summary.name}:",
        f"    AUC-PR   {summary.auc_pr.point_estimate:.4f}  "
        f"95% CI [{summary.auc_pr.lower:.4f}, {summary.auc_pr.upper:.4f}]  "
        f"(width {summary.auc_pr.width:.4f}, {summary.auc_pr.n_resamples} resamples)",
        f"    AUC-ROC  {summary.auc_roc.point_estimate:.4f}  "
        f"95% CI [{summary.auc_roc.lower:.4f}, {summary.auc_roc.upper:.4f}]",
    ]
    if caveat:
        lines.append(caveat)
    return lines


def _format_class_breakdown(
    title: str, breakdowns: tuple[ClassBreakdown, ...]
) -> list[str]:
    """Renders a per-class, per-variant recall breakdown.

    Args:
        title: Heading for the block.
        breakdowns: The breakdowns to render.

    Returns:
        Lines of the rendered block.
    """
    lines = [title]
    for breakdown in breakdowns:
        lines.append(
            f"  {breakdown.attack_class.value:<22} recall {breakdown.recall:.4f} "
            f"({breakdown.caught}/{breakdown.total})"
        )
        for variant, recall in breakdown.recall_by_variant.items():
            lines.append(f"      {variant:<26} {recall:.4f}")
    return lines


def format_milestone_b_report(report: MilestoneBReport) -> str:
    """Renders the full evaluation as plain text.

    Ordered so the gate verdict is readable near the top without scrolling
    past the supporting numbers, and so nothing flattering is presented
    before the caveat that qualifies it.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    gate = report.gate
    lines = [
        "Full evaluation: ranking metrics, intervals, calibration, cost, latency, sensitivity",
        f"  sessions            {report.n_sessions}",
        f"  test block          {report.n_test} (all sessions, not residual-only)",
        f"  attack base rate    {report.attack_base_rate:.4f}",
        f"  generator digest    {report.params_digest[:16]}",
        f"  operating threshold {report.threshold:.4f}",
        "",
        "=== HARD GATE: does Layer 3 earn its place? ===",
        f"  VERDICT: {'YES' if gate.layer3_earns_its_place else 'NO - drop Layer 3'}",
        f"  {gate.rationale}",
        "",
        "  Literal reading (precision at fixed recall):",
        f"    fixed recall                  {gate.fixed_recall:.4f} (the baseline's own recall)",
        f"    baseline precision there      {gate.baseline_precision_at_fixed_recall:.4f}",
        f"    ensemble precision there      {gate.ensemble_precision_at_fixed_recall:.4f}",
        f"    ensemble strictly beats it    {gate.precision_gate_passed}",
        f"    baseline precision saturated  {gate.baseline_precision_is_saturated}"
        f"{'  <- cannot be beaten on precision by any detector' if gate.baseline_precision_is_saturated else ''}",
        "",
        "  Complementary reading (recall at fixed precision):",
        f"    baseline precision            {gate.baseline_precision:.4f}",
        f"    baseline recall               {gate.fixed_recall:.4f}",
        f"    ensemble recall at that precision  {gate.ensemble_recall_at_baseline_precision:.4f}",
        f"    recall gained                 {gate.recall_gain_at_baseline_precision:+.4f}",
        "",
    ]

    lines.append("  Paired significance (McNemar, at the operating threshold):")
    if gate.mcnemar is None:
        lines.append(
            "    not defined: the two systems agree on every session, so there are no"
        )
        lines.append("    discordant pairs to test.")
    else:
        lines.extend(
            [
                f"    baseline-only-correct   {gate.mcnemar.baseline_only_correct}",
                f"    ensemble-only-correct   {gate.mcnemar.challenger_only_correct}",
                f"    p-value                 {gate.mcnemar.p_value:.4g}",
                f"    favors ensemble         {gate.mcnemar.favors_challenger}",
            ]
        )

    lines.append("")
    lines.append("  DeLong (correlated AUC-ROC comparison):")
    if gate.delong is None:
        lines.append("    not defined: the two scores rank every session identically.")
    else:
        lines.extend(
            [
                f"    baseline AUC-ROC        {gate.delong.baseline_auc:.4f}",
                f"    ensemble AUC-ROC        {gate.delong.challenger_auc:.4f}",
                f"    difference              {gate.delong.auc_difference:+.4f} "
                f"(SE {gate.delong.standard_error:.5f})",
                f"    p-value                 {gate.delong.p_value:.4g}",
                f"    favors ensemble         {gate.delong.favors_challenger}",
            ]
        )
    if gate.delong is not None and gate.delong.baseline_is_degenerate:
        lines.append(
            "    NOTE: the baseline emits a block/allow verdict, not a ranking, so its"
        )
        lines.append(
            "          AUC is balanced accuracy. Treat this DeLong result as a"
        )
        lines.append(
            "          low-resolution check, not as the primary comparison."
        )

    lines.extend(
        [
            "",
            "=== Operating point (test block) ===",
            f"  baseline  precision={report.baseline_precision:.4f}  "
            f"recall={report.baseline_recall:.4f}",
            f"  ensemble  precision={report.ensemble_precision:.4f}  "
            f"recall={report.ensemble_recall:.4f}",
            "",
            "=== Ranking metrics (AUC-PR primary, AUC-ROC secondary) ===",
        ]
    )
    lines.extend(_format_score_summary(report.baseline_scores))
    lines.extend(_format_score_summary(report.ensemble_scores))
    lines.extend(_format_score_summary(report.layer3_scores))
    lines.append(
        "  (the ensemble's AUC is largely inherited from the deterministic layers, which"
    )
    lines.append(
        "   already resolve most of the population; Layer 3's own figure above is what the"
    )
    lines.append("   model learned on the rows the rules could not resolve)")

    lines.extend(
        [
            "",
            "=== Layer 3 probability calibration (test block residual) ===",
            f"  Brier score                {report.calibration.brier:.5f}",
            f"  expected calibration error {report.calibration.expected_calibration_error:.5f}",
            "  bin            n     mean_predicted  observed  gap",
        ]
    )
    for one_bin in report.calibration.bins:
        lines.append(
            f"  [{one_bin.lower:.1f},{one_bin.upper:.1f})  {one_bin.count:>6}  "
            f"{one_bin.mean_predicted:>14.4f}  {one_bin.observed_rate:>8.4f}  "
            f"{one_bin.gap:>+6.4f}"
        )

    lines.append("")
    lines.extend(
        _format_class_breakdown(
            "=== Per attack class, rules-only baseline (test block) ===",
            report.baseline_class_breakdown,
        )
    )
    lines.append("")
    lines.extend(
        _format_class_breakdown(
            "=== Per attack class, ensemble (test block) ===",
            report.ensemble_class_breakdown,
        )
    )

    lines.extend(["", "=== Per variant, rules-only -> ensemble ==="])
    for comparison in report.variant_comparison:
        marker = "  <- rules-invisible" if comparison.is_rules_invisible else ""
        lines.append(
            f"  {comparison.variant:<26} n={comparison.total:<5} "
            f"{comparison.rules_recall:.4f} -> {comparison.ensemble_recall:.4f}{marker}"
        )

    lines.append("")
    for sweep in report.cost_sweeps:
        best = sweep.minimum_cost_point
        lines.append(
            f"=== Cost sweep summary, cost_ratio={sweep.cost_ratio:>4.1f}: "
            f"min cost {best.expected_cost:.1f} at threshold {best.threshold:.4f} "
            f"(precision {best.precision:.4f}, recall {best.recall:.4f}, "
            f"{best.blocked_legitimate_per_10k:.1f} blocked legit/10k)"
        )
    # The detailed table shows the sweep at the assumption that actually set
    # the operating threshold, not whichever ratio came first in the list.
    chosen_sweep = next(
        (sweep for sweep in report.cost_sweeps if sweep.cost_ratio == report.cost_ratio),
        report.cost_sweeps[0],
    )
    lines.append("")
    lines.append(format_cost_sweep(chosen_sweep, every_n=50))

    lines.extend(["", format_latency_report(report.latency)])
    if report.sensitivity is None:
        lines.extend(
            [
                "",
                "=== Sensitivity to generator parameters ===",
                "  NOT RUN. This report is incomplete: the headline numbers above are",
                "  conditional on one generator parameter setting and nothing here shows",
                "  how far they move when it changes.",
            ]
        )
    else:
        lines.extend(["", format_sensitivity_report(report.sensitivity)])

    lines.extend(["", "=== Top SHAP features (mean |contribution|, test residual rows) ==="])
    for name, value in report.top_attribution_features:
        lines.append(f"  {name:<34} {value:.4f}")

    return "\n".join(lines)
