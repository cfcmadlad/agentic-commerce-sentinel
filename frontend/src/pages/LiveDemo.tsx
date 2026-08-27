import { useState } from "react";
import { MOCK_SESSIONS, MOCK_SESSION_LABELS } from "../mock/sessions";
import type { SessionDecisionResponse } from "../types/contract";

/**
 * Live pipeline demo view.
 *
 * Reads from the mock fixture module, not a live API -- Milestone E (the
 * FastAPI service) does not exist yet. Every value rendered here comes from
 * the real BaselineDecision/EnsembleDecision/AttributionRow shapes in
 * types/contract.ts, so wiring this to a real `fetch(...)` later should
 * only require replacing the data source, not any rendering logic below.
 */

function stageClass(status: "fired" | "passed" | "pending"): string {
  return `pipeline-stage pipeline-stage--${status}`;
}

function PipelineView({ session }: { session: SessionDecisionResponse }) {
  const layer1Fired = session.baseline.verification_reasons.length > 0;
  const layer2Fired = session.baseline.scope_reasons.length > 0;
  const rulesBlocked = session.baseline.blocked;
  const layer3Reached = !rulesBlocked;
  const layer3Fired = session.ensemble.source === "behavioral";

  return (
    <div className="pipeline-stages">
      <div className={stageClass(layer1Fired ? "fired" : "passed")}>
        <div className="pipeline-stage__label">Layer 1 — Mandate verification</div>
        {layer1Fired ? (
          <span className="badge badge--block">
            {session.baseline.verification_reasons.join(", ")}
          </span>
        ) : (
          <span className="badge badge--allow">passed</span>
        )}
      </div>

      <div
        className={stageClass(
          !layer3Reached && !layer1Fired ? "fired" : layer2Fired ? "fired" : layer1Fired ? "pending" : "passed",
        )}
      >
        <div className="pipeline-stage__label">Layer 2 — Scope enforcement</div>
        {layer1Fired ? (
          <span className="badge badge--warn">not reached</span>
        ) : layer2Fired ? (
          <span className="badge badge--block">{session.baseline.scope_reasons.join(", ")}</span>
        ) : (
          <span className="badge badge--allow">passed</span>
        )}
      </div>

      <div className={stageClass(!layer3Reached ? "pending" : layer3Fired ? "fired" : "passed")}>
        <div className="pipeline-stage__label">Layer 3 — Behavioral model</div>
        {!layer3Reached ? (
          <span className="badge badge--warn">not reached</span>
        ) : (
          <span className={`badge ${layer3Fired ? "badge--block" : "badge--allow"}`}>
            score {session.ensemble.behavioral_score?.toFixed(3) ?? "n/a"}
          </span>
        )}
      </div>

      <div className="pipeline-stage pipeline-stage--pending">
        <div className="pipeline-stage__label">Layer 4 — Reasoning &amp; audit</div>
        <span className="badge badge--warn">not built (Milestone D)</span>
      </div>
    </div>
  );
}

function AttributionView({ session }: { session: SessionDecisionResponse }) {
  if (!session.attribution) {
    return (
      <p className="section-note">
        No attribution to show — the rules layers already decided this session, so Layer 3 was
        never scored.
      </p>
    );
  }
  const maxAbs = Math.max(...session.attribution.map((row) => Math.abs(row.shap_value)));
  return (
    <div>
      {session.attribution.map((row) => (
        <div className="attribution-row" key={row.feature}>
          <span style={{ width: 220, flexShrink: 0, color: "var(--text-dim)" }}>{row.feature}</span>
          <span className="attribution-bar-track">
            <span
              className="attribution-bar"
              style={{
                width: `${(Math.abs(row.shap_value) / maxAbs) * 100}%`,
                background: row.shap_value >= 0 ? "var(--danger)" : "var(--success)",
              }}
            />
          </span>
          <span style={{ width: 60, textAlign: "right" }}>{row.shap_value.toFixed(3)}</span>
        </div>
      ))}
    </div>
  );
}

export default function LiveDemo() {
  const [selectedId, setSelectedId] = useState(MOCK_SESSIONS[0].session_id);
  const session = MOCK_SESSIONS.find((s) => s.session_id === selectedId)!;

  return (
    <>
      <div className="panel">
        <h2 className="section-title">Pick a session</h2>
        <p className="section-note">
          Fixtures standing in for Milestone E (API service, not built yet). Each one walks the
          same detection pipeline the evaluation harness runs against real generated traffic.
        </p>
        <div className="session-picker">
          {MOCK_SESSIONS.map((s) => (
            <button
              key={s.session_id}
              className={s.session_id === selectedId ? "active" : ""}
              onClick={() => setSelectedId(s.session_id)}
            >
              {MOCK_SESSION_LABELS[s.session_id]}
            </button>
          ))}
        </div>
      </div>

      <div className="panel">
        <h2 className="section-title">Decision pipeline</h2>
        <PipelineView session={session} />
      </div>

      <div className="panel">
        <h2 className="section-title">Feature attribution</h2>
        <p className="section-note">
          Signed SHAP contribution per feature — positive pushes the score toward "attack",
          negative toward "legitimate".
        </p>
        <AttributionView session={session} />
      </div>

      <div className="panel">
        <h2 className="section-title">Decision narrative</h2>
        <div className="narrative-placeholder">
          Milestone D (reasoning &amp; audit layer) has not been built yet. Once it exists, this
          panel will show a plain-language explanation of the verdict above, citing exactly which
          check fired and why — narration only, never able to change the verdict itself.
        </div>
      </div>
    </>
  );
}
