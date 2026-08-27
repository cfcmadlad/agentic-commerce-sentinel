"""JSON serialization of a `MilestoneBReport`, for the static metrics dashboard.

The frontend's metrics view is a static export, not a live API: it renders
whatever this module wrote to disk. That means this file is the one place
the report's shape is translated into what a browser can consume, and it is
written explicitly rather than via a generic `dataclasses.asdict` walk --
several fields (`AttackClass` enum members, `GridPoint`'s embedded config
objects, `numpy` scalar types that can leak in from upstream computations)
are not JSON-safe as-is, and a generic walk would either crash on them or
silently serialize more than the dashboard needs (a `GridPoint` carries a
full `GeneratorConfig`/`AttackConfig`, which is noise once `name`/`factor`/
`description` are captured).
"""

from __future__ import annotations

from typing import Any

from eval.bootstrap import BootstrapInterval
from eval.cost_sweep import CostSweep, CostSweepPoint
from eval.delong import DeLongResult
from eval.latency import LatencyReport
from eval.metrics import CalibrationCurve
from eval.milestone_b import (
    ClassBreakdown,
    GateAssessment,
    MilestoneBReport,
    ScoreSummary,
    VariantComparison,
)
from eval.sensitivity import GridOutcome, SensitivityReport
from eval.significance import McNemarResult

# Cost-sweep points are reported at 1000 grid steps by default; the dashboard
# renders a line chart, not a table, so every Nth point is plenty of
# resolution while keeping the exported file a reasonable size.
COST_SWEEP_EXPORT_STRIDE = 10


def _bootstrap_interval_to_dict(interval: BootstrapInterval) -> dict[str, Any]:
    """Serializes one bootstrap confidence interval.

    Args:
        interval: The interval to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "point_estimate": interval.point_estimate,
        "lower": interval.lower,
        "upper": interval.upper,
        "confidence_level": interval.confidence_level,
        "n_resamples": interval.n_resamples,
        "standard_error": interval.standard_error,
    }


def _score_summary_to_dict(summary: ScoreSummary) -> dict[str, Any]:
    """Serializes one system's ranking-metric summary.

    Args:
        summary: The summary to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "name": summary.name,
        "auc_pr": _bootstrap_interval_to_dict(summary.auc_pr),
        "auc_roc": _bootstrap_interval_to_dict(summary.auc_roc),
        "is_binary_score": summary.is_binary_score,
    }


def _calibration_to_dict(calibration: CalibrationCurve) -> dict[str, Any]:
    """Serializes the Layer 3 calibration curve.

    Args:
        calibration: The curve to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "brier": calibration.brier,
        "expected_calibration_error": calibration.expected_calibration_error,
        "bins": [
            {
                "lower": one_bin.lower,
                "upper": one_bin.upper,
                "count": one_bin.count,
                "mean_predicted": one_bin.mean_predicted,
                "observed_rate": one_bin.observed_rate,
            }
            for one_bin in calibration.bins
        ],
    }


def _class_breakdown_to_dict(breakdown: ClassBreakdown) -> dict[str, Any]:
    """Serializes one attack class's detection breakdown.

    Args:
        breakdown: The breakdown to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "attack_class": breakdown.attack_class.value,
        "total": breakdown.total,
        "caught": breakdown.caught,
        "recall": breakdown.recall,
        "recall_by_variant": breakdown.recall_by_variant,
    }


def _variant_comparison_to_dict(comparison: VariantComparison) -> dict[str, Any]:
    """Serializes one variant's rules-vs-ensemble comparison.

    Args:
        comparison: The comparison to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "variant": comparison.variant,
        "total": comparison.total,
        "rules_recall": comparison.rules_recall,
        "ensemble_recall": comparison.ensemble_recall,
        "is_rules_invisible": comparison.is_rules_invisible,
    }


def _cost_sweep_point_to_dict(point: CostSweepPoint) -> dict[str, Any]:
    """Serializes one threshold's cost-sweep row.

    Args:
        point: The point to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "threshold": point.threshold,
        "true_positives": point.true_positives,
        "false_positives": point.false_positives,
        "false_negatives": point.false_negatives,
        "true_negatives": point.true_negatives,
        "precision": point.precision,
        "recall": point.recall,
        "blocked_legitimate_per_10k": point.blocked_legitimate_per_10k,
        "missed_attacks_per_10k": point.missed_attacks_per_10k,
        "expected_cost": point.expected_cost,
    }


def _cost_sweep_to_dict(sweep: CostSweep, stride: int) -> dict[str, Any]:
    """Serializes one cost-ratio's full threshold sweep, downsampled for export.

    Args:
        sweep: The sweep to serialize.
        stride: Export every `stride`-th point; the minimum-cost point is
            always included even if it would otherwise be skipped.

    Returns:
        A JSON-safe dict.
    """
    minimum = sweep.minimum_cost_point
    sampled = list(sweep.points[::stride])
    if minimum not in sampled:
        sampled.append(minimum)
        sampled.sort(key=lambda point: point.threshold)
    return {
        "cost_ratio": sweep.cost_ratio,
        "n_sessions": sweep.n_sessions,
        "n_attacks": sweep.n_attacks,
        "minimum_cost_point": _cost_sweep_point_to_dict(minimum),
        "points": [_cost_sweep_point_to_dict(point) for point in sampled],
    }


def _latency_to_dict(latency: LatencyReport) -> dict[str, Any]:
    """Serializes the end-to-end decision-latency distribution.

    Args:
        latency: The report to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "n_decisions": latency.n_decisions,
        "n_warmup": latency.n_warmup,
        "percentiles": {str(k): v for k, v in latency.percentiles.items()},
        "minimum_ms": latency.minimum_ms,
        "maximum_ms": latency.maximum_ms,
        "mean_ms": latency.mean_ms,
    }


def _grid_outcome_to_dict(outcome: GridOutcome) -> dict[str, Any]:
    """Serializes one sensitivity-grid point's outcome.

    Deliberately omits `outcome.point.generator_config` /
    `.attack_config` -- the full parameter objects are noise for a chart;
    `name`/`factor`/`description` are what a reader needs to identify the
    perturbation.

    Args:
        outcome: The outcome to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "name": outcome.point.name,
        "factor": outcome.point.factor,
        "description": outcome.point.description,
        "params_digest": outcome.params_digest,
        "n_sessions": outcome.n_sessions,
        "attack_base_rate": outcome.attack_base_rate,
        "baseline_precision": outcome.baseline_precision,
        "baseline_recall": outcome.baseline_recall,
        "ensemble_precision": outcome.ensemble_precision,
        "ensemble_recall": outcome.ensemble_recall,
        "ensemble_auc_pr": outcome.ensemble_auc_pr,
        "baseline_auc_pr": outcome.baseline_auc_pr,
        "rules_invisible_recall": outcome.rules_invisible_recall,
        "threshold": outcome.threshold,
        "beats_baseline": outcome.beats_baseline,
    }


def _sensitivity_to_dict(sensitivity: SensitivityReport | None) -> dict[str, Any] | None:
    """Serializes the sensitivity grid, or None when it was not run.

    Args:
        sensitivity: The report to serialize, or None.

    Returns:
        A JSON-safe dict, or None if `sensitivity` is None -- the dashboard
        must render "not run" rather than a fabricated empty grid.
    """
    if sensitivity is None:
        return None
    worst = sensitivity.worst_case
    low, high = sensitivity.auc_pr_range
    return {
        "baseline_outcome": _grid_outcome_to_dict(sensitivity.baseline_outcome),
        "outcomes": [_grid_outcome_to_dict(outcome) for outcome in sensitivity.outcomes],
        "worst_case_name": worst.point.name,
        "auc_pr_range": {"low": low, "high": high},
        "holds_everywhere": sensitivity.holds_everywhere,
    }


def _mcnemar_to_dict(result: McNemarResult | None) -> dict[str, Any] | None:
    """Serializes a McNemar result, or None when it was not defined.

    Args:
        result: The result to serialize, or None.

    Returns:
        A JSON-safe dict, or None.
    """
    if result is None:
        return None
    return {
        "baseline_only_correct": result.baseline_only_correct,
        "challenger_only_correct": result.challenger_only_correct,
        "p_value": result.p_value,
        "significant": result.significant,
        "favors_challenger": result.favors_challenger,
    }


def _delong_to_dict(result: DeLongResult | None) -> dict[str, Any] | None:
    """Serializes a DeLong result, or None when it was not defined.

    Args:
        result: The result to serialize, or None.

    Returns:
        A JSON-safe dict, or None.
    """
    if result is None:
        return None
    return {
        "baseline_auc": result.baseline_auc,
        "challenger_auc": result.challenger_auc,
        "auc_difference": result.auc_difference,
        "standard_error": result.standard_error,
        "z_statistic": result.z_statistic,
        "p_value": result.p_value,
        "significant": result.significant,
        "favors_challenger": result.favors_challenger,
        "baseline_is_degenerate": result.baseline_is_degenerate,
    }


def _gate_to_dict(gate: GateAssessment) -> dict[str, Any]:
    """Serializes the hard-gate assessment.

    Args:
        gate: The assessment to serialize.

    Returns:
        A JSON-safe dict.
    """
    return {
        "fixed_recall": gate.fixed_recall,
        "baseline_precision_at_fixed_recall": gate.baseline_precision_at_fixed_recall,
        "ensemble_precision_at_fixed_recall": gate.ensemble_precision_at_fixed_recall,
        "precision_gate_passed": gate.precision_gate_passed,
        "baseline_precision_is_saturated": gate.baseline_precision_is_saturated,
        "baseline_precision": gate.baseline_precision,
        "ensemble_recall_at_baseline_precision": gate.ensemble_recall_at_baseline_precision,
        "recall_gain_at_baseline_precision": gate.recall_gain_at_baseline_precision,
        "mcnemar": _mcnemar_to_dict(gate.mcnemar),
        "delong": _delong_to_dict(gate.delong),
        "is_degenerate": gate.is_degenerate,
        "layer3_earns_its_place": gate.layer3_earns_its_place,
        "rationale": gate.rationale,
    }


def milestone_b_report_to_dict(
    report: MilestoneBReport, cost_sweep_stride: int = COST_SWEEP_EXPORT_STRIDE
) -> dict[str, Any]:
    """Converts a full evaluation report into a JSON-safe dict.

    This is the single source of truth for the static metrics dashboard --
    every number the frontend renders comes from this export, not from a
    hand-copied figure, so the dashboard cannot drift from what
    `run_milestone_b.py` actually measured.

    Args:
        report: The report to serialize.
        cost_sweep_stride: Downsampling stride for each cost sweep's point
            list; see `_cost_sweep_to_dict`.

    Returns:
        A dict safe to pass to `json.dumps` with no custom encoder.
    """
    return {
        "n_sessions": report.n_sessions,
        "n_test": report.n_test,
        "attack_base_rate": report.attack_base_rate,
        "params_digest": report.params_digest,
        "threshold": report.threshold,
        "baseline_precision": report.baseline_precision,
        "baseline_recall": report.baseline_recall,
        "ensemble_precision": report.ensemble_precision,
        "ensemble_recall": report.ensemble_recall,
        "baseline_scores": _score_summary_to_dict(report.baseline_scores),
        "ensemble_scores": _score_summary_to_dict(report.ensemble_scores),
        "layer3_scores": _score_summary_to_dict(report.layer3_scores),
        "calibration": _calibration_to_dict(report.calibration),
        "baseline_class_breakdown": [
            _class_breakdown_to_dict(b) for b in report.baseline_class_breakdown
        ],
        "ensemble_class_breakdown": [
            _class_breakdown_to_dict(b) for b in report.ensemble_class_breakdown
        ],
        "variant_comparison": [
            _variant_comparison_to_dict(c) for c in report.variant_comparison
        ],
        "cost_sweeps": [
            _cost_sweep_to_dict(sweep, cost_sweep_stride) for sweep in report.cost_sweeps
        ],
        "cost_ratio": report.cost_ratio,
        "latency": _latency_to_dict(report.latency),
        "sensitivity": _sensitivity_to_dict(report.sensitivity),
        "gate": _gate_to_dict(report.gate),
        "top_attribution_features": [
            {"feature": name, "mean_abs_shap": value}
            for name, value in report.top_attribution_features
        ],
    }
