/**
 * API contract for the Sentinel decision pipeline.
 *
 * All four layers mirror real backend types exactly:
 *   - BaselineDecision    <- detect/baseline.py
 *   - EnsembleDecision    <- detect/ensemble.py
 *   - AttributionRow      <- detect/attribution.py (explain_row)
 *   - ReasoningNarrative  <- reasoning/schema.py::Narration
 *
 * The API service is built under /service. The live demo view POSTs real,
 * pre-signed requests to it when `VITE_API_BASE_URL` is configured, and
 * falls back to `mock/sessions.ts` otherwise (the case for the hosted
 * static build, which has no backend to call). The fixtures were produced
 * by actually running `reasoning.narrate.narrate()` against the real Groq
 * API for each mock session's real Baseline/Ensemble/Attribution data (see
 * the comment in `mock/sessions.ts`), not written by hand, so the narrative
 * text is genuine model output, not placeholder prose.
 */

export type VerificationFailureReason =
  | "unknown_signer"
  | "key_revoked"
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

/** One field a counterfactual explanation changes. Mirrors reasoning/schema.py::CounterfactualEdit. */
export interface CounterfactualEdit {
  field: string;
  real_value: string;
  suggested_value: string;
}

/**
 * A minimal-edit explanation of what would flip a blocked verdict.
 * Mirrors reasoning/schema.py::Counterfactual. `layer` is one of
 * "layer1_verification", "layer2_scope", or "layer3_behavioral" for
 * anything the live service can produce (layer2_5_containment exists in
 * counterfactual/deterministic.py but is not wired into /sessions/decide,
 * see docs/adr/0008).
 */
export interface Counterfactual {
  layer: string;
  feasible: boolean;
  edits: CounterfactualEdit[];
  explanation: string;
}

/** The full per-session decision record a live demo view renders. */
export interface SessionDecisionResponse {
  session_id: string;
  baseline: BaselineDecision;
  ensemble: EnsembleDecision;
  attribution: AttributionRow[] | null;
  /** Null only for a session that was never narrated. Every fixture below has one. */
  narrative: ReasoningNarrative | null;
  /** Null for an allowed session (nothing to explain). */
  counterfactual: Counterfactual | null;
}

/** One mandate along a delegation chain. Mirrors service/schemas.py::ChainNodeOut. */
export interface ChainNode {
  mandate_id: string;
  agent_id: string;
  parent_mandate_id: string | null;
  depth: number;
  is_root: boolean;
  /** Null for a root, or a node whose own parent could not be resolved. */
  in_bounds: boolean | null;
  reasons: string[];
  unresolvable_parent: boolean;
}

/** One parent-child link along a delegation chain. Mirrors service/schemas.py::ChainEdgeOut. */
export interface ChainEdge {
  child_mandate_id: string;
  parent_mandate_id: string;
  violates: boolean;
}

/**
 * A mandate's full delegation chain, each node's own Layer 2.5 containment
 * verdict included. Mirrors service/schemas.py::DelegationChainOut. This is
 * a live, on-demand read -- Layer 2.5 is not part of the automatic
 * `/sessions/decide` verdict itself, see docs/adr/0011.
 */
export interface DelegationChain {
  nodes: ChainNode[];
  edges: ChainEdge[];
  chain_broken: boolean;
  chain_broken_reason: string | null;
}
