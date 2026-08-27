import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { MilestoneBReport } from "../types/metrics";

/**
 * Static metrics dashboard.
 *
 * Renders `public/metrics.json`, produced by:
 *   python run_milestone_b.py --n-legitimate 20000 --seed 42 --json-out frontend/public/metrics.json
 *
 * This is a static export, not a live API call -- there is no backend
 * behind this view. Every number here traces back to eval/report_json.py,
 * so the dashboard cannot drift from what the evaluation harness actually
 * measured; regenerating it means re-running the command above.
 */

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function fmtNum(value: number, digits = 4): string {
  return value.toFixed(digits);
}

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="stat-card">
      <div className="stat-card__label">{label}</div>
      <div className="stat-card__value">{value}</div>
      {sub && <div className="stat-card__sub">{sub}</div>}
    </div>
  );
}

export default function MetricsDashboard() {
  const [report, setReport] = useState<MilestoneBReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/metrics.json")
      .then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      })
      .then((data: MilestoneBReport) => setReport(data))
      .catch((err: Error) => setError(err.message));
  }, []);

  if (error) {
    return (
      <div className="error-state">
        Could not load metrics.json: {error}
        <br />
        Generate it with: <code>python run_milestone_b.py --n-legitimate 20000 --seed 42 --json-out
        frontend/public/metrics.json</code>
      </div>
    );
  }
  if (!report) {
    return <div className="loading-state">Loading metrics.json…</div>;
  }

  const gate = report.gate;
  const chosenSweep =
    report.cost_sweeps.find((s) => s.cost_ratio === report.cost_ratio) ?? report.cost_sweeps[0];
  const costChartData = chosenSweep.points.map((p) => ({
    threshold: p.threshold,
    blocked_legit_per_10k: p.blocked_legitimate_per_10k,
    missed_attacks_per_10k: p.missed_attacks_per_10k,
  }));

  return (
    <>
      <div className="panel">
        <div className="page-intro">
          <span className="page-intro__eyebrow">New here?</span>
          <p>
            This is the full, unedited report card from evaluating the system against synthetic
            attacks — how often it catches something bad ("recall"), how often it wrongly blocks
            something fine ("precision"), and whether that's a real, statistically significant
            improvement over simple rules alone ("hard gate," below) rather than a coincidence.
          </p>
        </div>
        <h2 className="section-title">Hard gate: does Layer 3 earn its place?</h2>
        <p style={{ margin: "2px 0 10px" }}>
          <span className={`badge ${gate.layer3_earns_its_place ? "badge--allow" : "badge--block"}`}>
            {gate.layer3_earns_its_place ? "yes" : "no — drop Layer 3"}
          </span>
        </p>
        <p className="section-note">{gate.rationale}</p>
      </div>

      <div className="grid-cards">
        <StatCard
          label="AUC-PR (ensemble)"
          value={fmtNum(report.ensemble_scores.auc_pr.point_estimate)}
          sub={`95% CI [${fmtNum(report.ensemble_scores.auc_pr.lower)}, ${fmtNum(report.ensemble_scores.auc_pr.upper)}]`}
        />
        <StatCard
          label="AUC-PR (Layer 3 alone)"
          value={fmtNum(report.layer3_scores.auc_pr.point_estimate)}
          sub="scored on the rules-allowed residual only"
        />
        <StatCard
          label="Baseline precision / recall"
          value={`${fmtPct(report.baseline_precision)} / ${fmtPct(report.baseline_recall)}`}
        />
        <StatCard
          label="Ensemble precision / recall"
          value={`${fmtPct(report.ensemble_precision)} / ${fmtPct(report.ensemble_recall)}`}
        />
        <StatCard
          label="McNemar p-value"
          value={gate.mcnemar ? gate.mcnemar.p_value.toExponential(2) : "n/a"}
          sub={gate.mcnemar?.favors_challenger ? "favors ensemble" : undefined}
        />
        <StatCard label="Brier score" value={fmtNum(report.calibration.brier, 5)} />
        <StatCard
          label="Latency p50 / p99"
          value={`${fmtNum(report.latency.percentiles["50.0"], 2)}ms / ${fmtNum(report.latency.percentiles["99.0"], 2)}ms`}
        />
        <StatCard label="Corpus size" value={report.n_sessions.toLocaleString()} sub={`base rate ${fmtPct(report.attack_base_rate)}`} />
      </div>

      <div className="panel">
        <h2 className="section-title">Per-variant recall: rules-only → ensemble</h2>
        <p className="section-note">Rules-invisible variants are the two Layer 3 exists to catch.</p>
        <table className="data-table">
          <thead>
            <tr>
              <th>Variant</th>
              <th>n</th>
              <th>Rules-only</th>
              <th>Ensemble</th>
            </tr>
          </thead>
          <tbody>
            {report.variant_comparison.map((v) => (
              <tr key={v.variant}>
                <td>
                  {v.variant}
                  {v.is_rules_invisible && (
                    <span className="badge badge--warn" style={{ marginLeft: 6 }}>
                      rules-invisible
                    </span>
                  )}
                </td>
                <td>{v.total}</td>
                <td>{fmtPct(v.rules_recall)}</td>
                <td>{fmtPct(v.ensemble_recall)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h2 className="section-title">
          Cost sweep (cost ratio {report.cost_ratio.toFixed(1)}:1)
        </h2>
        <p className="section-note">
          Blocked-legitimate and missed-attack rates per 10,000 sessions, across the full threshold
          range. Minimum-cost point at threshold {fmtNum(chosenSweep.minimum_cost_point.threshold)}.
        </p>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={costChartData}>
            <CartesianGrid stroke="#ececec" />
            <XAxis dataKey="threshold" stroke="#777b86" fontSize={11} />
            <YAxis stroke="#777b86" fontSize={11} />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #ececec", fontSize: 12 }} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line
              type="monotone"
              dataKey="blocked_legit_per_10k"
              name="blocked legit / 10k"
              stroke="#777b86"
              strokeDasharray="4 3"
              dot={false}
            />
            <Line type="monotone" dataKey="missed_attacks_per_10k" name="missed attacks / 10k" stroke="#17191c" dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {report.sensitivity ? (
        <div className="panel">
          <h2 className="section-title">Sensitivity to generator parameters</h2>
          <p className="section-note">
            AUC-PR range across the grid: {fmtNum(report.sensitivity.auc_pr_range.low)}–
            {fmtNum(report.sensitivity.auc_pr_range.high)}. Worst case:{" "}
            {report.sensitivity.worst_case_name}. Ensemble beats baseline at every point:{" "}
            {report.sensitivity.holds_everywhere ? "yes" : "no"}.
          </p>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={[report.sensitivity.baseline_outcome, ...report.sensitivity.outcomes]}
              layout="vertical"
              margin={{ left: 100 }}
            >
              <CartesianGrid stroke="#ececec" />
              <XAxis type="number" domain={[0, 1]} stroke="#777b86" fontSize={11} />
              <YAxis type="category" dataKey="name" stroke="#777b86" fontSize={10} width={140} />
              <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #ececec", fontSize: 12 }} />
              <Bar dataKey="ensemble_auc_pr" name="ensemble AUC-PR">
                {[report.sensitivity.baseline_outcome, ...report.sensitivity.outcomes].map((o) => (
                  <Cell key={o.name} fill={o.beats_baseline ? "#d8d9db" : "#17191c"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="panel">
          <h2 className="section-title">Sensitivity to generator parameters</h2>
          <p className="section-note">Not run in this export.</p>
        </div>
      )}

      <div className="panel">
        <h2 className="section-title">Top SHAP features (mean |contribution|)</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Mean |SHAP|</th>
            </tr>
          </thead>
          <tbody>
            {report.top_attribution_features.map((f) => (
              <tr key={f.feature}>
                <td>{f.feature}</td>
                <td>{fmtNum(f.mean_abs_shap)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
