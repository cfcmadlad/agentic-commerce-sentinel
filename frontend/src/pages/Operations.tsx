import { useEffect, useMemo, useRef, useState } from "react";
import type { AgentDemoData, AgentInvocation, AgentScenarioTranscript, AgentVerdict } from "../types/agent";
import type { CollisionData, CollisionPoint } from "../lib/collide";
import { CATEGORY_LABELS } from "../lib/collide";
import type { FormalPropertiesReport } from "../types/formal";
import type { FullEvaluationReport } from "../types/metrics";

/**
 * Phase 2 of the governed-live-agent sprint (`docs/adr/0016-governed-live-agent.md`):
 * makes the project's existing rigor visible in the UI instead of buried in
 * README prose.
 *
 * Three real data sources, none hand-typed:
 *   - `agent_demo.json` (`run_agent_demo_export.py`) -- the four fixed
 *     shopper-agent scenarios, each a real tool-calling run whose checkout
 *     verdict came from the real `service.main.decide` plus the real Layer
 *     2.5 containment check. `llm_backend` is always shown, honestly --
 *     this build's export used a real Groq call (`groq:openai/gpt-oss-120b`);
 *     `--fake-llm` exists as a fallback for a machine that cannot reach
 *     Groq (see the ADR) and would be labelled as such here if ever used.
 *   - `formal_properties.json` (`run_verify_policy_properties.py --json-out`)
 *     -- the real Z3 property-by-property result.
 *   - `metrics.json` -- already used elsewhere in this dashboard; reused
 *     here only for the McNemar result and the ensemble AUC-PR bootstrap CI,
 *     never recomputed.
 *
 * Visual note, a deliberate scoped choice: this app has no router or
 * per-page theme (see `components/AppShell.tsx`) -- every "page" is a
 * `<section>` on one continuous, otherwise-light scroll. A page-level dark
 * mode toggle would fight that architecture, so the denser, "live feeling"
 * treatment the project brief asked for is scoped to a single
 * self-contained panel (`.ops-terminal` below) rather than the whole
 * Operations section or the app. Everything around it stays the same light
 * ink-on-paper system as every other section.
 */

const REPLAY_WINDOW = 14;
const REPLAY_TICK_MS = 850;

function fmtScore(score: number): string {
  return score < 0.001 ? score.toExponential(2) : score.toFixed(4);
}

function summarizeInvocation(inv: AgentInvocation): string {
  const args = inv.arguments;
  if (inv.is_error) {
    return `${inv.name}(${JSON.stringify(args)}) → error: ${String(inv.result)}`;
  }
  if (inv.name === "search_catalog") {
    const items = (inv.result as { items?: { name: string }[] })?.items ?? [];
    return `search_catalog(query: "${String(args.query ?? "")}") → ${items.length} item${items.length === 1 ? "" : "s"} found`;
  }
  if (inv.name === "propose_purchase") {
    const r = inv.result as { total_amount?: string; currency?: string };
    return `propose_purchase(item_id: "${String(args.item_id)}", quantity: ${String(args.quantity)}) → total ${r.total_amount} ${r.currency}`;
  }
  return `checkout(item_id: "${String(args.item_id)}", quantity: ${String(args.quantity)}) → verdict below`;
}

function verdictBadges(verdict: AgentVerdict) {
  const decideBadge = verdict.blocked ? "badge badge--block" : "badge badge--allow";
  const decideLabel = verdict.blocked ? `blocked (${verdict.source})` : "allowed (Layers 1–3)";
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
      <span className={decideBadge}>{decideLabel}</span>
      {verdict.containment_in_bounds === false && (
        <span className="badge badge--warn">Layer 2.5 containment: violation</span>
      )}
      {verdict.containment_in_bounds === true && <span className="badge badge--allow">Layer 2.5: in bounds</span>}
      {verdict.escalation_opened && <span className="badge badge--warn">escalation opened</span>}
    </div>
  );
}

function ScenarioDetail({ scenario }: { scenario: AgentScenarioTranscript }) {
  const verdict = scenario.verdicts[scenario.verdicts.length - 1];
  const isLive = scenario.llm_backend.startsWith("groq:");
  return (
    <div className="panel">
      <p className="section-note" style={{ marginBottom: 8 }}>
        {scenario.description}
      </p>
      <p className="section-note" style={{ marginBottom: 12 }}>
        <span className={`badge ${isLive ? "badge--allow" : "badge--warn"}`}>
          {isLive ? "live Groq call" : "scripted, not live"}
        </span>{" "}
        <span className="mono" style={{ fontSize: "var(--text-2xs)", color: "var(--ash)" }}>
          {scenario.llm_backend}
        </span>
      </p>

      <h2 className="section-title">Tool calls</h2>
      <ol className="ops-invocation-list">
        {scenario.invocations.map((inv, i) => (
          <li key={i} className={inv.is_error ? "ops-invocation--error" : undefined}>
            <span className="mono">{summarizeInvocation(inv)}</span>
          </li>
        ))}
      </ol>

      {verdict && (
        <>
          <h2 className="section-title" style={{ marginTop: 14 }}>
            Real verdict
          </h2>
          {verdictBadges(verdict)}
          {verdict.containment_reasons.length > 0 && (
            <p className="section-note" style={{ marginTop: 8, marginBottom: 0 }}>
              Containment reasons:{" "}
              {verdict.containment_reasons.map((r) => (
                <span key={r} className="badge badge--block" style={{ marginRight: 4 }}>
                  {r}
                </span>
              ))}
            </p>
          )}
          {verdict.behavioral_score !== null && (
            <p className="section-note" style={{ marginTop: 8, marginBottom: 0 }}>
              Layer 3 behavioral score: <span className="mono">{fmtScore(verdict.behavioral_score)}</span>
            </p>
          )}
        </>
      )}
    </div>
  );
}

interface ReplayRow {
  sequence: number;
  point: CollisionPoint;
}

function useReplayFeed(points: CollisionPoint[] | null): ReplayRow[] {
  const [rows, setRows] = useState<ReplayRow[]>([]);
  const cursorRef = useRef(0);
  const sequenceRef = useRef(0);

  useEffect(() => {
    if (!points || points.length === 0) return;
    const interval = setInterval(() => {
      const point = points[cursorRef.current % points.length];
      cursorRef.current += 1;
      sequenceRef.current += 1;
      const row: ReplayRow = { sequence: sequenceRef.current, point };
      setRows((prev) => [row, ...prev].slice(0, REPLAY_WINDOW));
    }, REPLAY_TICK_MS);
    return () => clearInterval(interval);
  }, [points]);

  return rows;
}

function OpsTerminal({ collision }: { collision: CollisionData | null }) {
  const rows = useReplayFeed(collision?.points ?? null);
  return (
    <div className="panel">
      <h2 className="section-title">Live-feeling verdict replay</h2>
      <p className="section-note">
        Not a live traffic feed -- this hosted build has no backend to stream from. This replays real,
        already-scored sessions from the evaluation corpus (`collision.json`, {collision?.points.length ?? 0}{" "}
        real sessions), one at a time, in a genuinely updating list. Sequence numbers only, never a
        timestamp presented as elapsed real time.
      </p>
      <div className="ops-terminal" role="log" aria-live="polite">
        {rows.length === 0 && <div className="ops-terminal__row ops-terminal__row--muted">waiting for data…</div>}
        {rows.map((row) => (
          <div key={row.sequence} className="ops-terminal__row">
            <span className="ops-terminal__seq">#{row.sequence}</span>
            <span className="ops-terminal__agent">{row.point.agent_id}</span>
            <span className="ops-terminal__category">{CATEGORY_LABELS[row.point.category] ?? row.point.category}</span>
            <span className="ops-terminal__score">score {fmtScore(row.point.score)}</span>
            <span className={row.point.blocked_by_rules ? "ops-terminal__verdict ops-terminal__verdict--block" : "ops-terminal__verdict"}>
              {row.point.blocked_by_rules ? "rules: blocked" : "rules: passed"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function humanizePropertyName(name: string): string {
  return name.replace(/_/g, " ");
}

function ProofPanel({
  formal,
  formalError,
  metrics,
}: {
  formal: FormalPropertiesReport | null;
  formalError: string | null;
  metrics: FullEvaluationReport | null;
}) {
  const provedCount = formal?.properties.filter((p) => p.proved).length ?? 0;
  return (
    <div className="panel">
      <h2 className="section-title">Proof panel</h2>
      <p className="section-note">
        Every number below is read from a real, already-committed export -- nothing here is computed by
        this page. Full detail and scope boundaries: <code>docs/adr/0005-formal-verification-of-deterministic-layers.md</code>,{" "}
        <code>docs/adr/0012-property-based-verification-of-containment.md</code>, and{" "}
        <code>docs/adr/0015-run-manifests.md</code>.
      </p>

      {formalError && <p className="error-state">Could not load formal_properties.json: {formalError}</p>}

      {formal && (
        <>
          <p className="section-note" style={{ marginBottom: 6 }}>
            <strong>
              {provedCount}/{formal.properties.length} Z3 safety properties proved
            </strong>{" "}
            -- exhaustively, over a bounded domain, not sampled from a test corpus.
          </p>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Property</th>
                  <th>Layer</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {formal.properties.map((p) => (
                  <tr key={p.name} title={p.description}>
                    <td className="mono">{humanizePropertyName(p.name)}</td>
                    <td>{p.layer}</td>
                    <td>
                      <span className={p.proved ? "badge badge--allow" : "badge badge--block"}>
                        {p.proved ? "proved" : "violated"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {metrics?.gate.mcnemar && (
        <div className="grid-cards" style={{ marginTop: 14 }}>
          <div className="stat-card">
            <div className="stat-card__label">McNemar significance</div>
            <div className="stat-card__value">{metrics.gate.mcnemar.p_value.toExponential(2)}</div>
            <div className="stat-card__sub">
              Is the ensemble genuinely better than rules alone, or could this be chance? This p-value
              says: essentially no chance.
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-card__label">Ensemble AUC-PR, 95% CI</div>
            <div className="stat-card__value">{metrics.ensemble_scores.auc_pr.point_estimate.toFixed(4)}</div>
            <div className="stat-card__sub">
              [{metrics.ensemble_scores.auc_pr.lower.toFixed(4)}, {metrics.ensemble_scores.auc_pr.upper.toFixed(4)}]
              from a stratified bootstrap -- how much this number could plausibly vary on a different
              sample.
            </div>
          </div>
        </div>
      )}

      <div className="panel" style={{ marginTop: 14, background: "var(--fog)" }}>
        <h2 className="section-title" style={{ fontSize: "var(--text-base)" }}>
          Property-based testing (Hypothesis)
        </h2>
        <p className="section-note" style={{ marginBottom: 0 }}>
          Separately from the Z3 proof above (which treats containment as a pure function),{" "}
          <code>tests/test_containment_properties.py</code> generates random delegation trees and runs
          them through the real, stateful <code>ContainmentGate</code> ledger, checking: no accepted
          mandate exceeds its parent's ceiling, committed siblings under one parent never exceed it, and
          every member of a genuine cycle is rejected. All checked and passing as part of this project's
          own test suite -- not re-run by this page, which only cites the result.
        </p>
      </div>

      <div className="panel" style={{ marginTop: 12, background: "var(--fog)" }}>
        <h2 className="section-title" style={{ fontSize: "var(--text-base)" }}>
          Reproducibility manifest
        </h2>
        <p className="section-note" style={{ marginBottom: 0 }}>
          This project's headline evaluation numbers (see the README's Results section) are certified by a committed run
          manifest -- every seed, the git commit, the dependency-lock hash, and the resulting metrics,
          confirmed to reproduce byte-for-byte across two independent runs before it was cited. Content
          hash <span className="mono">c544e6a4…0943a6</span>. <a href="/manifests/headline_full_evaluation.manifest.json">View the manifest</a>.
        </p>
      </div>
    </div>
  );
}

export default function Operations({ collision }: { collision: CollisionData | null }) {
  const [agentDemo, setAgentDemo] = useState<AgentDemoData | null>(null);
  const [agentDemoError, setAgentDemoError] = useState<string | null>(null);
  const [formal, setFormal] = useState<FormalPropertiesReport | null>(null);
  const [formalError, setFormalError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<FullEvaluationReport | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  useEffect(() => {
    fetch("/agent_demo.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((data: AgentDemoData) => {
        setAgentDemo(data);
        setSelectedKey(data[0]?.key ?? null);
      })
      .catch((err: Error) => setAgentDemoError(err.message));

    fetch("/formal_properties.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((data: FormalPropertiesReport) => setFormal(data))
      .catch((err: Error) => setFormalError(err.message));

    fetch("/metrics.json")
      .then((res) => (res.ok ? res.json() : null))
      .then((data: FullEvaluationReport | null) => setMetrics(data))
      .catch(() => setMetrics(null));
  }, []);

  const selectedScenario = useMemo(() => agentDemo?.find((s) => s.key === selectedKey), [agentDemo, selectedKey]);

  return (
    <>
      <div className="panel">
        <div className="page-intro">
          <span className="page-intro__eyebrow">New here?</span>
          <p>
            Everywhere else in this dashboard, "agents" are synthetic records from a data generator.
            Here, a real LLM (Groq tool-calling) decides what to attempt against a fake merchant catalog
            -- and every attempt is decided by the exact same real pipeline the rest of this dashboard
            evaluates, not a scripted verdict. Below that: the project's formal-verification and
            statistical-significance results, pulled from real exports rather than restated from memory.
          </p>
        </div>
        {agentDemoError && (
          <div className="error-state">
            Could not load agent_demo.json: {agentDemoError}
            <br />
            Generate it with: <code>python run_agent_demo_export.py --json-out frontend/public/agent_demo.json</code>
          </div>
        )}
      </div>

      {agentDemo && (
        <div className="session-rail">
          {agentDemo.map((s) => (
            <button key={s.key} className={s.key === selectedKey ? "active" : ""} onClick={() => setSelectedKey(s.key)}>
              {s.label}
            </button>
          ))}
        </div>
      )}

      {selectedScenario && <ScenarioDetail scenario={selectedScenario} />}

      <OpsTerminal collision={collision} />

      <ProofPanel formal={formal} formalError={formalError} metrics={metrics} />
    </>
  );
}
