/**
 * Shared geometry and types for rendering the real per-session collision data
 * (`public/collision.json`, from `run_collision_export.py`) as a log-scale
 * scatter or a kernel-density terrain, both with a draggable/shared
 * threshold. Used by every view under `/explorer` plus the compact Overview
 * widget, so all of them read the exact same real data through the exact
 * same math rather than copies that could drift.
 */

export interface CollisionPoint {
  score: number;
  category: string;
  blocked_by_rules: boolean;
  feature_x: number;
  feature_y: number;
  agent_id: string;
}

export interface CollisionData {
  threshold: number;
  feature_x_name: string;
  feature_y_name: string;
  points: CollisionPoint[];
}

export const CATEGORY_LABELS: Record<string, string> = {
  legitimate: "Legitimate",
  scope_violation: "Scope violation",
  agent_impersonation: "Agent impersonation",
  mandate_replay: "Mandate replay",
  mandate_chaining: "Mandate chaining (held-out)",
};

const EPS = 1e-4;
const LOG_MIN = Math.log10(EPS);
const LOG_MAX = Math.log10(1 + EPS);

/** Log-scale x position (0..1) for a raw score, independent of pixel width. */
export function scoreToUnit(score: number): number {
  return (Math.log10(score + EPS) - LOG_MIN) / (LOG_MAX - LOG_MIN);
}

/** Inverse of `scoreToUnit`: raw score for a 0..1 position. */
export function unitToScore(t: number): number {
  const clamped = Math.max(0, Math.min(1, t));
  return Math.pow(10, clamped * (LOG_MAX - LOG_MIN) + LOG_MIN) - EPS;
}

/** Deterministic pseudo-random jitter in [0, 1), stable across re-renders. */
export function jitterFor(index: number): number {
  const x = Math.sin(index * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

/**
 * Category color, drawn from the same Ran (1985)-inspired accent trio the
 * verdict badges use (vermilion/indigo/gold), plus a distinct ember accent
 * reserved for the held-out miss so it never blends into an ordinary catch.
 */
export function colorForCategory(category: string): string {
  if (category === "legitimate") return "#c7c9cd";
  if (category === "scope_violation") return "#a6332a";
  if (category === "agent_impersonation") return "#2b4a80";
  if (category === "mandate_replay") return "#9c6f1e";
  if (category === "mandate_chaining") return "#c94a26";
  return "#17191c";
}

export async function loadCollisionData(): Promise<CollisionData> {
  const res = await fetch("/collision.json");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as CollisionData;
}

export interface CategoryStat {
  total: number;
  blocked: number;
}

/** Per-category totals and would-be-blocked counts at a given score threshold. */
export function computeCategoryStats(
  points: CollisionPoint[],
  threshold: number,
): Record<string, CategoryStat> {
  const byCategory: Record<string, CategoryStat> = {};
  for (const p of points) {
    byCategory[p.category] ??= { total: 0, blocked: 0 };
    byCategory[p.category].total += 1;
    if (p.score >= threshold) byCategory[p.category].blocked += 1;
  }
  return byCategory;
}
