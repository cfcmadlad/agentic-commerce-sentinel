/**
 * API contract for the Sentinel decision pipeline.
 *
 * All four layers mirror real backend types exactly:
 *   - BaselineDecision    <- detect/baseline.py
 *   - EnsembleDecision    <- detect/ensemble.py
 *   - AttributionRow      <- detect/attribution.py (explain_row)
 *   - ReasoningNarrative  <- reasoning/schema.py::Narration
 *
 * There is still no live API service (Milestone E) for this frontend to
 * call -- every value rendered by the live demo view comes from
 * `mock/sessions.ts`, not a `fetch(...)`. The fixtures were produced by
 * actually running `reasoning.narrate.narrate()` against the real Groq API
 * for each mock session's real Baseline/Ensemble/Attribution data (see the
 * comment in `mock/sessions.ts`), not written by hand, so the narrative
 * text is genuine model output, not placeholder prose.
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
 * Mirrors reasoning/schema.py::Narration. Never carries a `blocked` or
 * `behavioral_score` field -- narration only, structurally unable to
 * override what Layers 1-3 already decided (see reasoning/narrate.py's
 * module docstring for the non-mutation guarantee this mirrors).
 */
export interface ReasoningNarrative {
  session_id: string;
  verdict_summary: string;
  narrative: string;
  rule_citations: string[];
  feature_citations: string[];
  model: string;
  generated_at: string;
}

/** The full per-session decision record a live demo view renders. */
export interface SessionDecisionResponse {
  session_id: string;
  baseline: BaselineDecision;
  ensemble: EnsembleDecision;
  attribution: AttributionRow[] | null;
  /** Null only for a session that was never narrated. Every fixture below has one. */
  narrative: ReasoningNarrative | null;
}
