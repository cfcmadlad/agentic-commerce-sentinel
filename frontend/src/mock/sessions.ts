/**
 * Mock session fixtures for the live demo view.
 *
 * Stands in for a live call against the FastAPI service (now built under
 * /service). Every fixture here uses the real BaselineDecision/
 * EnsembleDecision/AttributionRow/ReasoningNarrative shapes from
 * types/contract.ts, so swapping this module for a real `fetch` to the
 * running service later should not require touching any component that
 * consumes it -- only this file and the fetch call itself change.
 *
 * `narrative` on each fixture is genuine output from `reasoning.narrate.
 * narrate()`, run once against the real Groq API with a NarrationInput
 * built from this exact fixture's baseline/ensemble/attribution data --
 * not written by hand. Reproducing it: construct the matching
 * BaselineDecision/EnsembleDecision/AttributionResult in Python and call
 * `narrate()`; the text will differ on a re-run (narration prose is not
 * byte-reproducible, see reasoning/narrate.py's module docstring) but the
 * cited rule/feature names and verdict will not.
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
    narrative: {
      session_id: "11111111-1111-4111-8111-111111111111",
      verdict_summary: "allowed",
      narrative:
        "No rule fired for this session. The behavioral score of 0.0120 is well below the operating " +
        "threshold of 0.0251, indicating low risk. The top contributing features " +
        "agent_prior_session_count, hours_since_mandate_last_use, and event_gap_cv each have negative " +
        "values, which push the risk assessment further down.",
      rule_citations: [],
      feature_citations: ["agent_prior_session_count", "hours_since_mandate_last_use", "event_gap_cv"],
      model: "openai/gpt-oss-120b",
      generated_at: "2026-08-27T13:02:00Z",
    },
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
    narrative: {
      session_id: "22222222-2222-4222-8222-222222222222",
      verdict_summary: "blocked (rules)",
      narrative:
        "The session was blocked because the rule layer2:amount_over_ceiling was triggered, indicating " +
        "that the transaction amount exceeds the configured maximum limit. Since the rule caused an " +
        "immediate block, the behavioral model was not run and no behavioral score was computed. " +
        "Consequently, no additional features contributed to the decision.",
      rule_citations: ["layer2:amount_over_ceiling"],
      feature_citations: [],
      model: "openai/gpt-oss-120b",
      generated_at: "2026-08-27T13:02:05Z",
    },
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
    narrative: {
      session_id: "33333333-3333-4333-8333-333333333333",
      verdict_summary: "blocked (behavioral)",
      narrative:
        "The session was blocked because the behavioral model produced a score of 0.9400, which is far " +
        "above the operating threshold of 0.0251. The high score was driven primarily by the features " +
        "hours_since_mandate_last_use (+0.5100), mandate_prior_use_count (+0.2200), event_gap_cv " +
        "(+0.0800) and amount_over_agent_prior_mean (-0.0300). No deterministic rule fired for this " +
        "session.",
      rule_citations: [],
      feature_citations: [
        "hours_since_mandate_last_use",
        "mandate_prior_use_count",
        "event_gap_cv",
        "amount_over_agent_prior_mean",
      ],
      model: "openai/gpt-oss-120b",
      generated_at: "2026-08-27T13:02:10Z",
    },
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
    narrative: {
      session_id: "44444444-4444-4444-8444-444444444444",
      verdict_summary: "blocked (behavioral)",
      narrative:
        "The session was blocked by the behavioral model. The model generated a behavioral score of " +
        "0.8700, which is far above the operating threshold of 0.0251. The top contributing features " +
        "that pushed the score toward an attack were event_gap_cv (+0.3800), mean_event_gap_seconds " +
        "(+0.2900) and has_catalog_browse (+0.1400), and no deterministic rules fired.",
      rule_citations: [],
      feature_citations: ["event_gap_cv", "mean_event_gap_seconds", "has_catalog_browse"],
      model: "openai/gpt-oss-120b",
      generated_at: "2026-08-27T13:02:15Z",
    },
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
    narrative: {
      session_id: "55555555-5555-4555-8555-555555555555",
      verdict_summary: "blocked (rules)",
      narrative:
        "The session was blocked because the rule layer1:invalid_signature fired, indicating that the " +
        "request's signature was invalid. Since the block occurred at the rule-checking stage, no " +
        "behavioral score was computed. No other features contributed to the decision.",
      rule_citations: ["layer1:invalid_signature"],
      feature_citations: [],
      model: "openai/gpt-oss-120b",
      generated_at: "2026-08-27T13:02:20Z",
    },
  },
];

export const MOCK_SESSION_LABELS: Record<string, string> = {
  "11111111-1111-4111-8111-111111111111": "Legitimate — allowed",
  "22222222-2222-4222-8222-222222222222": "Scope violation — amount over ceiling (Layer 2)",
  "33333333-3333-4333-8333-333333333333": "Mandate replay — rapid reuse (Layer 3, rules-invisible)",
  "44444444-4444-4444-8444-444444444444": "Agent impersonation — behavioral only (Layer 3, rules-invisible)",
  "55555555-5555-4555-8555-555555555555": "Agent impersonation — forged signature (Layer 1)",
};
