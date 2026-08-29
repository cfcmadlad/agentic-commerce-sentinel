"""End-to-end ensemble evaluation: behavioral model, ensemble, significance.

Runs the full pipeline over one corpus: causal feature extraction across the
whole chronological session stream, a chronological train/validation/test
split, model training restricted to the rules-allowed residual of the
training block, threshold calibration on the residual of the validation
block, and a final comparison between the rules-only baseline and the
ensemble over the *entire* test block — not just its residual — since that
is the fair, deployable comparison: "does adding Layer 3 improve overall
detection" has to be answered on all traffic, not on the subset already
picked to favor it.

The held-out attack class (mandate chaining) never appears in the corpus
this module builds against; `generator.attacks.corpus` enforces that by
construction.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from uuid import UUID

import numpy as np

from common.schema import LabeledSession
from detect.attribution import AttributionResult, compute_attribution, top_features
from detect.baseline import BaselineDecision, RulesOnlyBaseline
from detect.behavioral import ChronologicalSplit, chronological_split, train_behavioral_model
from detect.calibration import (
    DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    CalibrationResult,
    calibrate_threshold,
    sensitivity_sweep,
)
from detect.ensemble import ensemble_decide
from eval.significance import McNemarResult, mcnemar_test
from features.session import FeatureExtractor, feature_names
from generator.attacks.corpus import EvaluationCorpus

logger = logging.getLogger(__name__)

DEFAULT_TRAIN_FRACTION = 0.6
DEFAULT_VALIDATION_FRACTION = 0.2
DEFAULT_ATTRIBUTION_TOP_N = 10


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 on an empty denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 when the denominator is zero.
    """
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True)
class VariantRecallComparison:
    """Rules-only vs ensemble recall for one attack sub-variant, on the test block."""

    variant: str
    total: int
    rules_recall: float
    ensemble_recall: float


@dataclass(frozen=True)
class EnsembleEvaluationReport:
    """Everything the ensemble-vs-baseline gate decision rests on.

    Attributes:
        n_sessions: Total corpus size.
        n_train_residual: Rows the model was trained on.
        n_validation_residual: Rows used for threshold calibration.
        n_test: Rows in the final held-out test block (all sessions, not
            just residual).
        chosen_calibration: The calibration result at the default cost
            ratio, used to produce the reported ensemble numbers.
        calibration_sweep: Calibration results across a range of cost
            ratios, for sensitivity reporting.
        baseline_precision: Rules-only precision on the test block.
        baseline_recall: Rules-only recall on the test block.
        ensemble_precision: Ensemble precision on the test block.
        ensemble_recall: Ensemble recall on the test block.
        variant_comparison: Per-variant recall, rules-only vs ensemble, on
            the test block.
        significance: McNemar test result, rules-only vs ensemble, on the
            test block.
        beats_baseline: Whether the ensemble significantly outperforms the
            rules-only baseline. This is the number the project's stated
            policy is keyed to: if False, Layer 3 is reported as not earning
            its place and dropped, not re-tuned against held-out data.
        top_attribution_features: Global SHAP feature ranking from the
            trained model, computed over the test block's residual rows.
    """

    n_sessions: int
    n_train_residual: int
    n_validation_residual: int
    n_test: int
    chosen_calibration: CalibrationResult
    calibration_sweep: tuple[CalibrationResult, ...]
    baseline_precision: float
    baseline_recall: float
    ensemble_precision: float
    ensemble_recall: float
    variant_comparison: tuple[VariantRecallComparison, ...]
    significance: McNemarResult
    beats_baseline: bool
    top_attribution_features: tuple[tuple[str, float], ...]


def _extract_features_causally(sessions: tuple[LabeledSession, ...]) -> np.ndarray:
    """Extracts the full feature matrix over a chronologically ordered stream.

    A single `FeatureExtractor` absorbs every session in order, legitimate
    and attack, blocked and allowed alike — matching a real feature store
    that logs every attempt regardless of downstream outcome. No feature
    depends on whether the *current* session was blocked, so this does not
    leak the target being predicted.

    Args:
        sessions: Sessions in ascending `started_at` order.

    Returns:
        A design matrix with columns in `feature_names()` order.
    """
    names = feature_names()
    extractor = FeatureExtractor()
    rows = [extractor.extract(labeled.trace) for labeled in sessions]
    return np.array([[row[name] for name in names] for row in rows])


def run_ensemble_evaluation(
    corpus: EvaluationCorpus,
    train_fraction: float = DEFAULT_TRAIN_FRACTION,
    validation_fraction: float = DEFAULT_VALIDATION_FRACTION,
    cost_ratio: float = DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    random_state: int = 42,
) -> EnsembleEvaluationReport:
    """Runs the full ensemble-evaluation pipeline against a corpus.

    Args:
        corpus: A chronologically ordered mixed corpus, as built by
            `generator.attacks.corpus.build_evaluation_corpus`.
        train_fraction: Fraction of the corpus, by chronological position,
            used for model training.
        validation_fraction: Fraction used for threshold calibration.
        cost_ratio: The false-negative-to-false-positive cost ratio used to
            select `chosen_calibration`. See `detect.calibration` for why
            this is an explicit, named assumption.
        random_state: Seed for the behavioral model's internal randomness.

    Returns:
        The full report.

    Raises:
        ValueError: If the corpus is empty, or if the resulting splits leave
            the training or validation residual too sparse to fit or
            calibrate against — propagated from `detect.behavioral` and
            `detect.calibration` rather than caught here, since a corpus too
            small for this pipeline needs to be regenerated larger, not
            silently downgraded.
    """
    if not corpus.labeled_sessions:
        raise ValueError("cannot run the ensemble evaluation over an empty corpus")

    sessions = corpus.labeled_sessions
    n = len(sessions)

    baseline = RulesOnlyBaseline(corpus.registry, corpus.resolver)
    decisions: tuple[BaselineDecision, ...] = baseline.decide_all(s.trace for s in sessions)
    blocked = np.array([d.blocked for d in decisions])

    features = _extract_features_causally(sessions)
    labels = np.array([s.is_attack for s in sessions])

    split: ChronologicalSplit = chronological_split(n, train_fraction, validation_fraction)
    residual = ~blocked

    train_residual_mask = split.train & residual
    validation_residual_mask = split.validation & residual
    test_mask = split.test
    test_residual_mask = split.test & residual

    model = train_behavioral_model(
        features[train_residual_mask], labels[train_residual_mask], feature_names(), random_state=random_state
    )

    validation_scores = model.predict_proba(features[validation_residual_mask])
    sweep = sensitivity_sweep(labels[validation_residual_mask], validation_scores)
    chosen = calibrate_threshold(labels[validation_residual_mask], validation_scores, cost_ratio=cost_ratio)

    test_scores = model.predict_proba(features[test_residual_mask])
    test_score_by_index: dict[int, float] = dict(
        zip(np.flatnonzero(test_residual_mask).tolist(), test_scores.tolist(), strict=True)
    )

    test_indices = np.flatnonzero(test_mask)
    ensemble_blocked = np.zeros(n, dtype=bool)
    for index in test_indices:
        score = test_score_by_index.get(int(index))
        decision = ensemble_decide(decisions[index], score, chosen.threshold)
        ensemble_blocked[index] = decision.blocked

    baseline_test_blocked = blocked[test_mask]
    ensemble_test_blocked = ensemble_blocked[test_mask]
    test_labels = labels[test_mask]

    def _precision_recall(predicted_block: np.ndarray, truth: np.ndarray) -> tuple[float, float]:
        """Computes precision and recall for a block/allow prediction array.

        Args:
            predicted_block: Per-row block/allow prediction.
            truth: Per-row ground-truth `is_attack` labels.

        Returns:
            A (precision, recall) tuple.
        """
        tp = int(np.sum(predicted_block & truth))
        fp = int(np.sum(predicted_block & ~truth))
        fn = int(np.sum(~predicted_block & truth))
        return _safe_ratio(tp, tp + fp), _safe_ratio(tp, tp + fn)

    baseline_precision, baseline_recall = _precision_recall(baseline_test_blocked, test_labels)
    ensemble_precision, ensemble_recall = _precision_recall(ensemble_test_blocked, test_labels)

    baseline_correct = baseline_test_blocked == test_labels
    ensemble_correct = ensemble_test_blocked == test_labels
    significance = mcnemar_test(baseline_correct, ensemble_correct)
    beats_baseline = significance.favors_challenger and ensemble_recall > baseline_recall

    variant_comparison = _compare_variants(
        sessions, corpus.variant_by_session, test_mask, blocked, ensemble_blocked, labels
    )

    attribution: AttributionResult = compute_attribution(model, features[test_residual_mask])
    top_attribution = top_features(attribution, top_n=DEFAULT_ATTRIBUTION_TOP_N)

    logger.info(
        "ensemble evaluation: baseline recall=%.4f ensemble recall=%.4f beats_baseline=%s p=%.4g",
        baseline_recall,
        ensemble_recall,
        beats_baseline,
        significance.p_value,
    )

    return EnsembleEvaluationReport(
        n_sessions=n,
        n_train_residual=int(train_residual_mask.sum()),
        n_validation_residual=int(validation_residual_mask.sum()),
        n_test=int(test_mask.sum()),
        chosen_calibration=chosen,
        calibration_sweep=sweep,
        baseline_precision=baseline_precision,
        baseline_recall=baseline_recall,
        ensemble_precision=ensemble_precision,
        ensemble_recall=ensemble_recall,
        variant_comparison=variant_comparison,
        significance=significance,
        beats_baseline=beats_baseline,
        top_attribution_features=top_attribution,
    )


def _compare_variants(
    sessions: tuple[LabeledSession, ...],
    variant_by_session: dict[UUID, str],
    test_mask: np.ndarray,
    baseline_blocked: np.ndarray,
    ensemble_blocked: np.ndarray,
    labels: np.ndarray,
) -> tuple[VariantRecallComparison, ...]:
    """Computes rules-only vs ensemble recall per attack sub-variant on the test block.

    Args:
        sessions: The full corpus, in the same order as the mask arrays.
        variant_by_session: Map of session ID to attack sub-variant.
        test_mask: Boolean mask selecting the test block.
        baseline_blocked: Per-session rules-only block/allow array.
        ensemble_blocked: Per-session ensemble block/allow array.
        labels: Per-session ground-truth `is_attack` labels.

    Returns:
        One comparison per variant present in the test block's attack
        traffic, sorted by variant name.
    """
    totals: Counter[str] = Counter()
    rules_caught: Counter[str] = Counter()
    ensemble_caught: Counter[str] = Counter()

    for index, labeled in enumerate(sessions):
        if not test_mask[index] or not labels[index]:
            continue
        variant = variant_by_session.get(labeled.trace.session_id, "unknown")
        totals[variant] += 1
        if baseline_blocked[index]:
            rules_caught[variant] += 1
        if ensemble_blocked[index]:
            ensemble_caught[variant] += 1

    return tuple(
        VariantRecallComparison(
            variant=variant,
            total=total,
            rules_recall=_safe_ratio(rules_caught[variant], total),
            ensemble_recall=_safe_ratio(ensemble_caught[variant], total),
        )
        for variant, total in sorted(totals.items())
    )


def format_ensemble_evaluation_report(report: EnsembleEvaluationReport) -> str:
    """Renders an ensemble-evaluation report as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        "Behavioral model + ensemble vs rules-only baseline",
        f"  sessions               {report.n_sessions}",
        f"  train residual rows    {report.n_train_residual}",
        f"  validation resid rows  {report.n_validation_residual}",
        f"  test block rows        {report.n_test} (all sessions, not residual-only)",
        "",
        f"  baseline  precision={report.baseline_precision:.4f}  recall={report.baseline_recall:.4f}",
        f"  ensemble  precision={report.ensemble_precision:.4f}  recall={report.ensemble_recall:.4f}",
        "",
        "Significance (McNemar, paired on the test block):",
        f"  baseline-only-correct   {report.significance.baseline_only_correct}",
        f"  ensemble-only-correct   {report.significance.challenger_only_correct}",
        f"  p-value                 {report.significance.p_value:.4g}",
        f"  beats baseline          {report.beats_baseline}",
        "",
        f"Chosen calibration (cost_ratio={report.chosen_calibration.cost_ratio:.1f}):",
        f"  threshold={report.chosen_calibration.threshold:.4f}  "
        f"val precision={report.chosen_calibration.precision:.4f}  "
        f"val recall={report.chosen_calibration.recall:.4f}",
        "",
        "Calibration sensitivity sweep:",
    ]
    for result in report.calibration_sweep:
        lines.append(
            f"  cost_ratio={result.cost_ratio:>5.1f}  threshold={result.threshold:.4f}  "
            f"val recall={result.recall:.4f}"
        )
    lines.append("")
    lines.append("Per-variant recall on the test block (rules-only -> ensemble):")
    for comparison in report.variant_comparison:
        lines.append(
            f"  {comparison.variant:<26} n={comparison.total:<4} "
            f"{comparison.rules_recall:.4f} -> {comparison.ensemble_recall:.4f}"
        )
    lines.append("")
    lines.append("Top SHAP features (mean |contribution|, test residual rows):")
    for name, value in report.top_attribution_features:
        lines.append(f"  {name:<34} {value:.4f}")
    return "\n".join(lines)