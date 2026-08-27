/**
 * Types for `frontend/public/metrics.json`, produced by
 * `run_milestone_b.py --json-out` via `eval/report_json.py`.
 *
 * This file's shape must track `milestone_b_report_to_dict` in
 * eval/report_json.py field-for-field -- it is the one place a schema drift
 * between the Python export and the frontend would surface, since nothing
 * validates the JSON against this interface at load time. If a field is
 * renamed on the Python side, this file needs the matching edit by hand.
 */

export interface BootstrapInterval {
  point_estimate: number;
  lower: number;
  upper: number;
  confidence_level: number;
  n_resamples: number;
  standard_error: number;
}

export interface ScoreSummary {
  name: string;
  auc_pr: BootstrapInterval;
  auc_roc: BootstrapInterval;
  is_binary_score: boolean;
}

export interface CalibrationBin {
  lower: number;
  upper: number;
  count: number;
  mean_predicted: number;
  observed_rate: number;
}

export interface CalibrationCurve {
  brier: number;
  expected_calibration_error: number;
  bins: CalibrationBin[];
}

export type AttackClass =
  | "legitimate"
  | "mandate_replay"
  | "scope_violation"
  | "agent_impersonation"
  | "mandate_chaining";

export interface ClassBreakdown {
  attack_class: AttackClass;
  total: number;
  caught: number;
  recall: number;
  recall_by_variant: Record<string, number>;
}

export interface VariantComparison {
  variant: string;
  total: number;
  rules_recall: number;
  ensemble_recall: number;
  is_rules_invisible: boolean;
}

export interface CostSweepPoint {
  threshold: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  precision: number;
  recall: number;
  blocked_legitimate_per_10k: number;
  missed_attacks_per_10k: number;
  expected_cost: number;
}

export interface CostSweep {
  cost_ratio: number;
  n_sessions: number;
  n_attacks: number;
  minimum_cost_point: CostSweepPoint;
  points: CostSweepPoint[];
}

export interface LatencyReport {
  n_decisions: number;
  n_warmup: number;
  /** Keys are the percentile as a string, e.g. "50.0" / "95.0" / "99.0". */
  percentiles: Record<string, number>;
  minimum_ms: number;
  maximum_ms: number;
  mean_ms: number;
}

export interface GridOutcome {
  name: string;
  factor: string;
  description: string;
  params_digest: string;
  n_sessions: number;
  attack_base_rate: number;
  baseline_precision: number;
  baseline_recall: number;
  ensemble_precision: number;
  ensemble_recall: number;
  ensemble_auc_pr: number;
  baseline_auc_pr: number;
  rules_invisible_recall: number;
  threshold: number;
  beats_baseline: boolean;
}

export interface SensitivityReport {
  baseline_outcome: GridOutcome;
  outcomes: GridOutcome[];
  worst_case_name: string;
  auc_pr_range: { low: number; high: number };
  holds_everywhere: boolean;
}

export interface McNemarResult {
  baseline_only_correct: number;
  challenger_only_correct: number;
  p_value: number;
  significant: boolean;
  favors_challenger: boolean;
}

export interface DeLongResult {
  baseline_auc: number;
  challenger_auc: number;
  auc_difference: number;
  standard_error: number;
  z_statistic: number;
  p_value: number;
  significant: boolean;
  favors_challenger: boolean;
  baseline_is_degenerate: boolean;
}

export interface GateAssessment {
  fixed_recall: number;
  baseline_precision_at_fixed_recall: number;
  ensemble_precision_at_fixed_recall: number;
  precision_gate_passed: boolean;
  baseline_precision_is_saturated: boolean;
  baseline_precision: number;
  ensemble_recall_at_baseline_precision: number;
  recall_gain_at_baseline_precision: number;
  mcnemar: McNemarResult | null;
  delong: DeLongResult | null;
  is_degenerate: boolean;
  layer3_earns_its_place: boolean;
  rationale: string;
}

export interface AttributionFeature {
  feature: string;
  mean_abs_shap: number;
}

/** The full evaluation report, as exported by eval/report_json.py. */
export interface MilestoneBReport {
  n_sessions: number;
  n_test: number;
  attack_base_rate: number;
  params_digest: string;
  threshold: number;
  baseline_precision: number;
  baseline_recall: number;
  ensemble_precision: number;
  ensemble_recall: number;
  baseline_scores: ScoreSummary;
  ensemble_scores: ScoreSummary;
  layer3_scores: ScoreSummary;
  calibration: CalibrationCurve;
  baseline_class_breakdown: ClassBreakdown[];
  ensemble_class_breakdown: ClassBreakdown[];
  variant_comparison: VariantComparison[];
  cost_sweeps: CostSweep[];
  cost_ratio: number;
  latency: LatencyReport;
  sensitivity: SensitivityReport | null;
  gate: GateAssessment;
  top_attribution_features: AttributionFeature[];
}
