import { useEffect, useState } from "react";
import About from "./About";
import Decisions from "./Decisions";
import Delegation from "./Delegation";
import Evaluation from "./Evaluation";
import Explorer from "./Explorer";
import Operations from "./Operations";
import Sandbox from "./Sandbox";
import OrgDrilldown from "../components/OrgDrilldown";
import ThresholdSparkline from "../components/ThresholdSparkline";
import type { CollisionData } from "../lib/collide";
import { scrollToSection } from "../lib/scroll";
import type { FullEvaluationReport } from "../types/metrics";

/**
 * The whole app, one page. Every tool that used to be a separate route
 * (Decisions, Sandbox, Explorer, Evaluation, About) is a full-fidelity
 * section here instead -- same components, same real data and logic,
 * just composed inline rather than routed to. `collision.json` is fetched
 * once here and passed down to every section that needs it (Overview's
 * sparkline, Organizations, Explorer), rather than each fetching its own
 * copy of the same 270KB file.
 */

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

export default function Dashboard() {
  const [report, setReport] = useState<FullEvaluationReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [collision, setCollision] = useState<CollisionData | null>(null);
  const [collisionError, setCollisionError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/metrics.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((data: FullEvaluationReport) => setReport(data))
      .catch((err: Error) => setReportError(err.message));

    fetch("/collision.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((data: CollisionData) => setCollision(data))
      .catch((err: Error) => setCollisionError(err.message));
  }, []);

  return (
    <>
      <section id="overview">
        <div className="overview-header">
          <div>
            <h1>Overview</h1>
            <p className="overview-header__sub">
              Live status of the detection pipeline, evaluated against synthetic agentic-commerce
              traffic.
            </p>
          </div>
          <a href="#sandbox" onClick={(e) => scrollToSection("sandbox", e)} className="btn btn--filled btn--sm">
            Test a mandate →
          </a>
        </div>

        {reportError && <div className="panel error-state">Could not load metrics.json: {reportError}</div>}

        {report && (
          <div className="grid-cards">
            <div className="stat-card">
              <div className="stat-card__label">Ensemble AUC-PR</div>
              <div className="stat-card__value">{report.ensemble_scores.auc_pr.point_estimate.toFixed(4)}</div>
              <div className="stat-card__sub">
                95% CI [{report.ensemble_scores.auc_pr.lower.toFixed(4)}, {report.ensemble_scores.auc_pr.upper.toFixed(4)}]
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">Ensemble precision / recall</div>
              <div className="stat-card__value">
                {fmtPct(report.ensemble_precision)} / {fmtPct(report.ensemble_recall)}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-card__label">Hard gate</div>
              <div className="stat-card__value">
                <span className={`badge ${report.gate.layer3_earns_its_place ? "badge--allow" : "badge--block"}`}>
                  {report.gate.layer3_earns_its_place ? "Layer 3 earns its place" : "Layer 3 dropped"}
                </span>
              </div>
            </div>
            <div className="stat-card stat-card--flag">
              <div className="stat-card__label">Mandate chaining (held-out) recall</div>
              <div className="stat-card__value">0.00%</div>
              <div className="stat-card__sub">99.76% in-distribution — a total, disclosed miss</div>
            </div>
          </div>
        )}

        <div className="overview-grid">
          <div className="panel">
            <h2 className="section-title">Score distribution</h2>
            {collisionError && <p className="error-state">Could not load collision.json: {collisionError}</p>}
            {collision ? <ThresholdSparkline data={collision} /> : !collisionError && <p className="loading-state">Loading…</p>}
          </div>
          <div className="panel">
            <h2 className="section-title">Where to look next</h2>
            <p className="section-note">
              <a href="#organizations" onClick={(e) => scrollToSection("organizations", e)}>Organizations</a> — drill
              from company-wide numbers down to one agent's own sessions.
            </p>
            <p className="section-note">
              <a href="#decisions" onClick={(e) => scrollToSection("decisions", e)}>Decisions</a> — five real
              sessions walked through all four layers in full.
            </p>
            <p className="section-note">
              <a href="#sandbox" onClick={(e) => scrollToSection("sandbox", e)}>Sandbox</a> — build a mandate and
              try to break it.
            </p>
            <p className="section-note" style={{ marginBottom: 0 }}>
              <a href="#explorer" onClick={(e) => scrollToSection("explorer", e)}>Explorer</a> — every real scored
              session, as a scatter or a risk terrain.
            </p>
          </div>
        </div>
      </section>

      <section id="organizations">
        <h1>Organizations</h1>
        <p className="overview-header__sub" style={{ marginBottom: 14 }}>
          Company-wide activity, broken down by organization, then by agent, then by session.
        </p>
        {collisionError && <div className="panel error-state">Could not load collision.json: {collisionError}</div>}
        {collision ? (
          <div className="panel">
            <OrgDrilldown data={collision} />
          </div>
        ) : (
          !collisionError && <div className="panel loading-state">Loading collision.json…</div>
        )}
      </section>

      <section id="decisions">
        <h1>Decisions</h1>
        <Decisions />
      </section>

      <section id="sandbox">
        <h1>Sandbox</h1>
        <Sandbox />
      </section>

      <section id="delegation">
        <h1>Delegation</h1>
        <Delegation />
      </section>

      <section id="operations">
        <h1>Operations</h1>
        <Operations collision={collision} />
      </section>

      <section id="explorer">
        <h1>Explorer</h1>
        {collisionError && (
          <div className="error-state">
            Could not load collision.json: {collisionError}
            <br />
            Generate it with: <code>python run_collision_export.py --json-out frontend/public/collision.json</code>
          </div>
        )}
        {collision ? <Explorer data={collision} /> : !collisionError && <div className="loading-state">Loading collision.json…</div>}
      </section>

      <section id="evaluation">
        <h1>Evaluation</h1>
        <Evaluation />
      </section>

      <section id="about">
        <h1>About</h1>
        <About />
      </section>
    </>
  );
}
