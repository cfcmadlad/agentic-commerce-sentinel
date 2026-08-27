/**
 * Mock session fixtures for the live demo view.
 *
 * Stands in for Milestone E (the FastAPI service, not built yet). Every
 * fixture here uses the real BaselineDecision/EnsembleDecision/
 * AttributionRow shapes from types/contract.ts, so swapping this module
 * for a real `fetch` to E later should not require touching any component
 * that consumes it -- only this file and the fetch call itself change.
 *
 * `narrative` is null on every fixture: Milestone D does not exist yet, and
 * pretending it does here would defeat the purpose of stubbing it.
 */

import type { SessionDecisionResponse } from "../types/contract";

export const MOCK_SESSIONS: SessionDecisionResponse[] = [
  {
    session_id: "11111111-1111-4111-8111-111111111111",
    baseline: {
      session_id: "11111111-1111-4111-8111-111111111111",
      blocked: false,
      verification_reasons: [],
      scope_reasons: [],
      fired_rules: [],
    },
    ensemble: {
      session_id: "11111111-1111-4111-8111-111111111111",
      blocked: false,
      source: "allowed",
      behavioral_score: 0.012,
      rules_fired: [],
    },
    attribution: [
      { feature: "agent_prior_session_count", shap_value: -0.041 },
      { feature: "hours_since_mandate_last_use", shap_value: -0.019 },
      { feature: "event_gap_cv", shap_value: -0.008 },
    ],
    narrative: null,
  },
  {
    session_id: "22222222-2222-4222-8222-222222222222",
    baseline: {
      session_id: "22222222-2222-4222-8222-222222222222",
      blocked: true,
      verification_reasons: [],
      scope_reasons: ["amount_over_ceiling"],
      fired_rules: ["layer2:amount_over_ceiling"],
    },
    ensemble: {
      session_id: "22222222-2222-4222-8222-222222222222",
      blocked: true,
      source: "rules",
      behavioral_score: null,
      rules_fired: ["layer2:amount_over_ceiling"],
    },
    attribution: null,
    narrative: null,
  },
  {
    session_id: "33333333-3333-4333-8333-333333333333",
    baseline: {
      session_id: "33333333-3333-4333-8333-333333333333",
      blocked: false,
      verification_reasons: [],
      scope_reasons: [],
      fired_rules: [],
    },
    ensemble: {
      session_id: "33333333-3333-4333-8333-333333333333",
      blocked: true,
      source: "behavioral",
      behavioral_score: 0.94,
      rules_fired: [],
    },
    attribution: [
      { feature: "hours_since_mandate_last_use", shap_value: 0.51 },
      { feature: "mandate_prior_use_count", shap_value: 0.22 },
      { feature: "event_gap_cv", shap_value: 0.08 },
      { feature: "amount_over_agent_prior_mean", shap_value: -0.03 },
    ],
    narrative: null,
  },
  {
    session_id: "44444444-4444-4444-8444-444444444444",
    baseline: {
      session_id: "44444444-4444-4444-8444-444444444444",
      blocked: false,
      verification_reasons: [],
      scope_reasons: [],
      fired_rules: [],
    },
    ensemble: {
      session_id: "44444444-4444-4444-8444-444444444444",
      blocked: true,
      source: "behavioral",
      behavioral_score: 0.87,
      rules_fired: [],
    },
    attribution: [
      { feature: "event_gap_cv", shap_value: 0.38 },
      { feature: "mean_event_gap_seconds", shap_value: 0.29 },
      { feature: "has_catalog_browse", shap_value: 0.14 },
    ],
    narrative: null,
  },
  {
    session_id: "55555555-5555-4555-8555-555555555555",
    baseline: {
      session_id: "55555555-5555-4555-8555-555555555555",
      blocked: true,
      verification_reasons: ["invalid_signature"],
      scope_reasons: [],
      fired_rules: ["layer1:invalid_signature"],
    },
    ensemble: {
      session_id: "55555555-5555-4555-8555-555555555555",
      blocked: true,
      source: "rules",
      behavioral_score: null,
      rules_fired: ["layer1:invalid_signature"],
    },
    attribution: null,
    narrative: null,
  },
];

export const MOCK_SESSION_LABELS: Record<string, string> = {
  "11111111-1111-4111-8111-111111111111": "Legitimate — allowed",
  "22222222-2222-4222-8222-222222222222": "Scope violation — amount over ceiling (Layer 2)",
  "33333333-3333-4333-8333-333333333333": "Mandate replay — rapid reuse (Layer 3, rules-invisible)",
  "44444444-4444-4444-8444-444444444444": "Agent impersonation — behavioral only (Layer 3, rules-invisible)",
  "55555555-5555-4555-8555-555555555555": "Agent impersonation — forged signature (Layer 1)",
};
