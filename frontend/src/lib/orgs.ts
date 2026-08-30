import type { CollisionPoint } from "./collide";

/**
 * Illustrative organization grouping over the real 40-agent pool.
 *
 * The backend has no organization or multi-tenant concept anywhere in its
 * schema -- every session is produced by one AI agent acting for one human,
 * full stop. This module buckets the real agent IDs `public/collision.json`
 * carries (`SessionTrace.agent_id`, exported by `run_collision_export.py`)
 * into a fixed set of named "organizations" purely so this dashboard has
 * something to drill through above the agent level. The grouping itself is
 * fabricated for presentation, and the dashboard says so; every number
 * computed within a group is not fabricated -- it is a real aggregate over
 * real per-session data, filtered to whichever real agent IDs this
 * deterministic hash assigned to that group.
 */

export const ORG_NAMES = [
  "Northwind Retail",
  "Bluecrest Logistics",
  "Solace Markets",
  "Ferrow Group",
  "Anchorpoint Commerce",
  "Kestrel Traders",
] as const;

/** FNV-1a: fast, deterministic, evenly-distributed enough for 40 short agent IDs across 6 buckets. */
function hashString(value: string): number {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

export function orgForAgent(agentId: string): string {
  return ORG_NAMES[hashString(agentId) % ORG_NAMES.length];
}

export interface AgentSummary {
  agentId: string;
  total: number;
  blocked: number;
}

export interface OrgSummary {
  org: string;
  agents: AgentSummary[];
  total: number;
  blocked: number;
}

/** Groups real per-session points into illustrative orgs, with real aggregate stats computed within each. */
export function summarizeByOrg(points: CollisionPoint[], threshold: number): OrgSummary[] {
  const agentTotals = new Map<string, AgentSummary>();
  for (const p of points) {
    const entry = agentTotals.get(p.agent_id) ?? { agentId: p.agent_id, total: 0, blocked: 0 };
    entry.total += 1;
    if (p.score >= threshold) entry.blocked += 1;
    agentTotals.set(p.agent_id, entry);
  }

  const orgs = new Map<string, OrgSummary>();
  for (const agent of agentTotals.values()) {
    const org = orgForAgent(agent.agentId);
    const summary = orgs.get(org) ?? { org, agents: [], total: 0, blocked: 0 };
    summary.agents.push(agent);
    summary.total += agent.total;
    summary.blocked += agent.blocked;
    orgs.set(org, summary);
  }

  for (const summary of orgs.values()) {
    summary.agents.sort((a, b) => b.total - a.total);
  }

  return Array.from(orgs.values()).sort((a, b) => b.total - a.total);
}
