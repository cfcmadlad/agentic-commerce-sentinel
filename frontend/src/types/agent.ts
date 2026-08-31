/**
 * Types for `frontend/public/agent_demo.json`, produced by
 * `run_agent_demo_export.py` -- the governed live shopper agent's four
 * fixed scenarios (see `agent/scenarios.py`), each run through the real
 * tool-calling loop and the real `service.main.decide` / Layer 2.5
 * containment check.
 *
 * `llm_backend` states plainly whether a scenario's tool calls came from a
 * real Groq call or a fixed scripted sequence (`--fake-llm`, used when
 * `GROQ_API_KEY` is unset or unreachable) -- the frontend must always
 * surface this label, never hide it, per the project's standing rule that
 * reasoning output is never presented as live when it was not.
 */

export interface AgentCatalogItem {
  item_id: string;
  name: string;
  merchant_id: string;
  merchant_category: string;
  item_category: string;
  price: string;
}

export interface AgentInvocation {
  name: "search_catalog" | "propose_purchase" | "checkout";
  arguments: Record<string, unknown>;
  result: unknown;
  is_error: boolean;
}

/** Mirrors agent/tools.py::SentinelVerdict, rendered by agent/shopper.py::render_verdict. */
export interface AgentVerdict {
  session_id: string;
  blocked: boolean;
  source: string;
  rules_fired: string[];
  behavioral_score: number | null;
  narrative: string | null;
  containment_in_bounds: boolean | null;
  containment_reasons: string[];
  escalation_opened: boolean;
  escalation_id: string | null;
}

export interface AgentScenarioTranscript {
  key: string;
  label: string;
  description: string;
  llm_backend: string;
  final_text: string | null;
  hit_iteration_cap: boolean;
  invocations: AgentInvocation[];
  verdicts: AgentVerdict[];
}

export type AgentDemoData = AgentScenarioTranscript[];
