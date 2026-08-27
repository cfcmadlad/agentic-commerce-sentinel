/**
 * API contract for the Sentinel decision pipeline.
 *
 * Layers 1-3 mirror real backend types exactly:
 *   - BaselineDecision  <- detect/baseline.py
 *   - EnsembleDecision  <- detect/ensemble.py
 *   - AttributionRow    <- detect/attribution.py (explain_row)
 *
 * Layer 4 (reasoning/audit) has no implementation yet -- Milestone D is not
 * built. ReasoningNarrative below is a deliberate placeholder: its shape is
 * a guess, not a frozen contract. When Milestone D lands, only this one
 * type and whatever reads it should need to change; every other type here
 * is load-bearing today and should not need to move.
 */

export type VerificationFailureReason =
  | "unknown_signer"
  | "invalid_signature"
  | "not_yet_valid"
  | "expired"
  | "budget_exhausted";

export type ScopeViolationReason =
  | "no_mandate_presented"
  | "mandate_id_mismatch"
  | "agent_binding_mismatch"
  | "user_binding_mismatch"
  | "amount_over_ceiling"
  | "currency_mismatch"
  | "merchant_category_not_allowed"
  | "item_category_not_allowed"
  | "merchant_not_allowed"
  | "outside_time_window";

/** Mirrors detect/baseline.py::BaselineDecision. */
export interface BaselineDecision {
  session_id: string;
  blocked: boolean;
  verification_reasons: VerificationFailureReason[];
  scope_reasons: ScopeViolationReason[];
  fired_rules: string[];
}

export type EnsembleSource = "rules" | "behavioral" | "allowed";

/** Mirrors detect/ensemble.py::EnsembleDecision. */
export interface EnsembleDecision {
  session_id: string;
  blocked: boolean;
  source: EnsembleSource;
  behavioral_score: number | null;
  rules_fired: string[];
}

/** One feature's signed contribution to a single session's score. Mirrors detect/attribution.py::explain_row. */
export interface AttributionRow {
  feature: string;
  shap_value: number;
}

/**
 * PLACEHOLDER -- Milestone D is not built. Shape is a guess for frontend
 * scaffolding purposes only; do not treat as frozen. Never sets or adjusts
 * blocked/behavioral_score -- narration only, per the project's standing
 * constraint that Layer 4 cannot override earlier layers.
 */
export interface ReasoningNarrative {
  summary: string;
  cited_checks: string[];
  generated_at: string;
}

/** The full per-session decision record a live demo view renders. */
export interface SessionDecisionResponse {
  session_id: string;
  baseline: BaselineDecision;
  ensemble: EnsembleDecision;
  attribution: AttributionRow[] | null;
  /** Null until Milestone D exists. The UI must render this as "not yet available", not omit the section. */
  narrative: ReasoningNarrative | null;
}
