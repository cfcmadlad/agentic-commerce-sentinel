import type { SessionDecisionResponse } from "../types/contract";

/**
 * Shared pipeline-stage computation for both the full live-demo view and
 * the compact hero replay, so the two can never silently disagree about
 * which layer fired on a given session. Extracted from the decisions view's
 * original inline logic without changing any of its conditions.
 */

export type StageStatus = "fired" | "passed" | "pending";

export interface PipelineStage {
  layer: 1 | 2 | 3 | 4;
  label: string;
  status: StageStatus;
  detail: string;
}

export function computePipelineStages(session: SessionDecisionResponse): PipelineStage[] {
  const layer1Fired = session.baseline.verification_reasons.length > 0;
  const layer2Fired = session.baseline.scope_reasons.length > 0;
  const rulesBlocked = session.baseline.blocked;
  const layer3Reached = !rulesBlocked;
  const layer3Fired = session.ensemble.source === "behavioral";

  const layer2Status: StageStatus =
    (!layer3Reached && !layer1Fired) || layer2Fired ? "fired" : layer1Fired ? "pending" : "passed";
  const layer3Status: StageStatus = !layer3Reached ? "pending" : layer3Fired ? "fired" : "passed";

  return [
    {
      layer: 1,
      label: "Mandate verification",
      status: layer1Fired ? "fired" : "passed",
      detail: layer1Fired ? session.baseline.verification_reasons.join(", ") : "passed",
    },
    {
      layer: 2,
      label: "Scope enforcement",
      status: layer2Status,
      detail: layer1Fired ? "not reached" : layer2Fired ? session.baseline.scope_reasons.join(", ") : "passed",
    },
    {
      layer: 3,
      label: "Behavioral model",
      status: layer3Status,
      detail: !layer3Reached ? "not reached" : `score ${session.ensemble.behavioral_score?.toFixed(3) ?? "n/a"}`,
    },
    {
      layer: 4,
      label: "Reasoning & audit",
      status: "passed",
      detail: "narrated",
    },
  ];
}

export function badgeClassForStage(status: StageStatus): string {
  if (status === "fired") return "badge badge--block";
  if (status === "pending") return "badge badge--warn";
  return "badge badge--allow";
}
