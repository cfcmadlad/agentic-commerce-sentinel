import { computePipelineStages } from "../lib/pipeline";
import { MOCK_SESSIONS, MOCK_SESSION_LABELS } from "../mock/sessions";

/**
 * A dense, show-everything-at-once row list of the five real demo sessions
 * -- same underlying data and pipeline-stage computation as `/decisions`
 * (`lib/pipeline.ts`, real Groq-narrated fixtures in `mock/sessions.ts`),
 * rendered as a scannable activity feed instead of an auto-cycling chat
 * replay. No timers, no pause-on-hover state: every row is visible
 * immediately, matching every other panel in the app.
 */

const NARRATIVE_MAX_CHARS = 90;

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max).trimEnd()}…`;
}

export default function RecentDecisionsFeed() {
  return (
    <div className="feed">
      {MOCK_SESSIONS.map((session) => {
        const stages = computePipelineStages(session);
        const firedStage = stages.find((s) => s.status === "fired");
        const narrative = session.narrative;
        const verdictBlocked = narrative ? narrative.verdict_summary !== "allowed" : false;
        return (
          <div className="feed__row" key={session.session_id}>
            <span className={verdictBlocked ? "badge badge--block" : "badge badge--allow"}>
              {narrative ? narrative.verdict_summary : session.ensemble.blocked ? "blocked" : "allowed"}
            </span>
            <span className="feed__id mono">{session.session_id.slice(0, 8)}</span>
            <span className="feed__narrative">
              {narrative ? truncate(narrative.narrative, NARRATIVE_MAX_CHARS) : MOCK_SESSION_LABELS[session.session_id]}
            </span>
            <span className="feed__layer">{firedStage ? `Layer ${firedStage.layer}` : "no rule fired"}</span>
          </div>
        );
      })}
    </div>
  );
}
