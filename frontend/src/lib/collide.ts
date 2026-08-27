/**
 * Shared geometry and types for rendering the real per-session collision data
 * (`public/collision.json`, from `run_collision_export.py`) as a log-scale
 * scatter with a draggable threshold. Used by the full `/collide` page and
 * by the compact landing-page widget, so both read the exact same real data
 * through the exact same math rather than two copies that could drift.
 */

export interface CollisionPoint {
  score: number;
  category: string;
  blocked_by_rules: boolean;
}

export interface CollisionData {
  threshold: number;
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

export function colorForCategory(category: string): string {
  if (category === "legitimate") return "#c7c9cd";
  if (category === "mandate_chaining") return "#e8935f";
  return "#17191c";
}

export async function loadCollisionData(): Promise<CollisionData> {
  const res = await fetch("/collision.json");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as CollisionData;
}
