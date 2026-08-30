import { useMemo, useState } from "react";
import { CATEGORY_LABELS, colorForCategory, type CollisionData, type CollisionPoint } from "../lib/collide";
import { summarizeByOrg } from "../lib/orgs";

/**
 * Company -> organization -> agent -> transaction drill-down, built entirely
 * on real per-session data (`public/collision.json`). The organization
 * layer is an illustrative grouping this dashboard invents for navigation
 * (see `lib/orgs.ts`'s own docstring) -- disclosed here, not hidden -- but
 * every count, rate, and session below it is real.
 */

type Level =
  | { kind: "orgs" }
  | { kind: "agents"; org: string }
  | { kind: "sessions"; org: string; agentId: string }
  | { kind: "session"; org: string; agentId: string; point: CollisionPoint; index: number };

function fmtScore(score: number): string {
  return score < 0.001 ? score.toExponential(2) : score.toFixed(4);
}

function Breadcrumb({ level, onNavigate }: { level: Level; onNavigate: (level: Level) => void }) {
  const parts: { label: string; level: Level }[] = [{ label: "Company", level: { kind: "orgs" } }];
  if (level.kind !== "orgs") {
    parts.push({ label: level.org, level: { kind: "agents", org: level.org } });
  }
  if (level.kind === "sessions" || level.kind === "session") {
    parts.push({ label: level.agentId, level: { kind: "sessions", org: level.org, agentId: level.agentId } });
  }
  if (level.kind === "session") {
    parts.push({ label: `session ${level.index + 1}`, level });
  }
  return (
    <div className="breadcrumb">
      {parts.map((part, i) => (
        <span key={i}>
          {i > 0 && <span className="breadcrumb__sep">/</span>}
          {i === parts.length - 1 ? (
            <span className="breadcrumb__current">{part.label}</span>
          ) : (
            <button className="breadcrumb__link" onClick={() => onNavigate(part.level)}>
              {part.label}
            </button>
          )}
        </span>
      ))}
    </div>
  );
}

export default function OrgDrilldown({ data }: { data: CollisionData }) {
  const [level, setLevel] = useState<Level>({ kind: "orgs" });

  const orgs = useMemo(() => summarizeByOrg(data.points, data.threshold), [data]);

  const sessionsForAgent = useMemo(() => {
    if (level.kind !== "sessions" && level.kind !== "session") return [];
    return data.points
      .map((p, index) => ({ p, index }))
      .filter(({ p }) => p.agent_id === level.agentId);
  }, [data, level]);

  return (
    <div>
      <p className="section-note">
        Organizations are an illustrative grouping this dashboard invents for navigation — the
        backend has no multi-tenant concept. Every agent ID, session, score, and rate below that is
        real, drawn from the same {data.points.length.toLocaleString()}-session export every other
        page reads.
      </p>

      <Breadcrumb level={level} onNavigate={setLevel} />

      {level.kind === "orgs" && (
        <div className="org-grid">
          {orgs.map((org) => (
            <button className="org-card" key={org.org} onClick={() => setLevel({ kind: "agents", org: org.org })}>
              <div className="org-card__name">{org.org}</div>
              <div className="org-card__stats">
                <span>{org.agents.length} agents</span>
                <span>{org.total} sessions</span>
                <span className={org.blocked > 0 ? "org-card__flag" : ""}>
                  {((org.blocked / org.total) * 100).toFixed(1)}% blocked
                </span>
              </div>
            </button>
          ))}
        </div>
      )}

      {level.kind === "agents" &&
        (() => {
          const org = orgs.find((o) => o.org === level.org);
          return (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Sessions</th>
                    <th>Blocked</th>
                  </tr>
                </thead>
                <tbody>
                  {org?.agents.map((agent) => (
                    <tr
                      key={agent.agentId}
                      className="data-table__row--clickable"
                      onClick={() => setLevel({ kind: "sessions", org: level.org, agentId: agent.agentId })}
                    >
                      <td className="mono">{agent.agentId}</td>
                      <td className="mono">{agent.total}</td>
                      <td className="mono">{((agent.blocked / agent.total) * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        })()}

      {level.kind === "sessions" && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Category</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {sessionsForAgent.map(({ p, index }) => (
                <tr
                  key={index}
                  className="data-table__row--clickable"
                  onClick={() => setLevel({ kind: "session", org: level.org, agentId: level.agentId, point: p, index })}
                >
                  <td>
                    <span className={`badge ${p.score >= data.threshold ? "badge--block" : "badge--allow"}`}>
                      {p.score >= data.threshold ? "blocked" : "allowed"}
                    </span>
                  </td>
                  <td>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                      <span className="category-dot" style={{ background: colorForCategory(p.category) }} />
                      {CATEGORY_LABELS[p.category] ?? p.category}
                    </span>
                  </td>
                  <td className="mono">{fmtScore(p.score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {level.kind === "session" && (
        <div className="panel" style={{ background: "var(--fog)" }}>
          <div className="grid-cards" style={{ marginBottom: 0 }}>
            <div className="stat-card">
              <div className="stat-card__label">Verdict</div>
              <div className="stat-card__value">
                <span className={`badge ${level.point.score >= data.threshold ? "badge--block" : "badge--allow"}`}>
                  {level.point.score >= data.threshold ? "blocked" : "allowed"}
                </span>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">Score</div>
              <div className="stat-card__value">{fmtScore(level.point.score)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">Category</div>
              <div className="stat-card__value" style={{ fontSize: "1rem" }}>
                {CATEGORY_LABELS[level.point.category] ?? level.point.category}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">Blocked by rules (L1/L2)</div>
              <div className="stat-card__value" style={{ fontSize: "1rem" }}>
                {level.point.blocked_by_rules ? "yes" : "no"}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">{data.feature_x_name}</div>
              <div className="stat-card__value">{level.point.feature_x.toFixed(2)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">{data.feature_y_name}</div>
              <div className="stat-card__value">{level.point.feature_y.toFixed(2)}</div>
            </div>
          </div>
          <p className="section-note" style={{ marginTop: 12, marginBottom: 0 }}>
            This export carries score, category, and the model's two top SHAP features per session,
            not a full per-layer breakdown or narration — those are only available for the five
            canonical scenarios in "Recent decisions" above. This is a real session from the same
            evaluation export the rest of this dashboard reads, not a placeholder.
          </p>
        </div>
      )}
    </div>
  );
}
