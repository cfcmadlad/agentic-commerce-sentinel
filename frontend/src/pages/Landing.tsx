import { Link } from "react-router-dom";

/**
 * Marketing landing page.
 *
 * Static and honest on purpose: every number and claim here is one already
 * measured and reported in the evaluation harness (see /metrics), not
 * fetched live and not invented for effect. The three floating cards
 * mirror real output shapes from the live demo (a blocked decision, a
 * signed SHAP attribution, an evaluation statistic) rather than mocking up
 * a generic product screenshot.
 */

function DecisionCard() {
  return (
    <div className="artifact-card">
      <div className="artifact-card__label">Decision</div>
      <div className="artifact-card__row">
        <span className="artifact-card__mono">layer2:amount_over_ceiling</span>
      </div>
      <div className="artifact-card__row" style={{ marginTop: 10 }}>
        <span className="badge badge--block">blocked</span>
        <span className="artifact-card__mono">₹45,000.00</span>
      </div>
    </div>
  );
}

function AttributionCard() {
  const rows: [string, number][] = [
    ["hours_since_mandate_last_use", 0.51],
    ["mandate_prior_use_count", 0.22],
    ["event_gap_cv", 0.08],
  ];
  const max = Math.max(...rows.map(([, v]) => Math.abs(v)));
  return (
    <div className="artifact-card">
      <div className="artifact-card__label">Feature attribution</div>
      {rows.map(([name, value]) => (
        <div className="attribution-row" key={name}>
          <span style={{ width: 150, flexShrink: 0, fontSize: 12, color: "var(--slate)" }}>{name}</span>
          <span className="attribution-bar-track">
            <span
              className="attribution-bar attribution-bar--positive"
              style={{ width: `${(Math.abs(value) / max) * 100}%` }}
            />
          </span>
        </div>
      ))}
    </div>
  );
}

function EvaluationCard() {
  return (
    <div className="artifact-card">
      <div className="artifact-card__label">Evaluation</div>
      <div className="artifact-stat">0.9982</div>
      <div className="artifact-stat__sub">
        AUC-PR, ensemble vs. rules-only baseline
        <br />
        McNemar p ≈ 1.4×10⁻¹²
      </div>
    </div>
  );
}

function AccentCard() {
  return (
    <div className="accent-card">
      <p className="accent-card__quote">
        “We held out an entire attack class and never trained against it. The system caught 0.88%
        of it — and that's the number we're leading with, not the 99.76% next to it.”
      </p>
      <p className="accent-card__byline">
        <Link to="/metrics">See the full result →</Link>
      </p>
    </div>
  );
}

const LAYERS = [
  {
    index: "01",
    title: "Mandate verification",
    body: "Every transaction arrives with a cryptographically signed authorization. It's checked for a genuine signature, a valid time window, and remaining budget — before anything else runs.",
  },
  {
    index: "02",
    title: "Scope enforcement",
    body: "The transaction is checked against ten deterministic rules drawn from the mandate itself: amount, merchant, category, timing. Exact comparisons, no tolerance band to hide behind.",
  },
  {
    index: "03",
    title: "Behavioral detection",
    body: "A model trained only on sessions the rules above already allowed, watching for the one thing rules can't see: a session that doesn't behave like the agent it claims to be.",
  },
  {
    index: "04",
    title: "Reasoning & audit",
    body: "A plain-language explanation of the verdict, citing the exact rule or feature that drove it. It narrates the decision — it never gets a vote in what the decision is.",
  },
];

export default function Landing() {
  return (
    <>
      <section className="hero">
        <span className="hero__eyebrow">
          <span className="hero__eyebrow-dot" />
          Mandate verification for agentic payments
        </span>
        <h1 className="hero__title">
          Verify what your agent is <em>actually</em> doing.
        </h1>
        <p className="hero__subtitle">
          A defense-only layer that checks whether an AI agent's payment stays inside what a human
          actually authorized — before the payment goes through.
        </p>
        <div className="hero__actions">
          <Link to="/sandbox" className="btn btn--filled">
            Try to break it
          </Link>
          <Link to="/demo" className="btn btn--ghost">
            Open live demo
          </Link>
        </div>
      </section>

      <div className="artifact-section">
        <div className="artifact-grid">
          <DecisionCard />
          <AttributionCard />
          <EvaluationCard />
        </div>
      </div>

      <AccentCard />

      <section className="section--fog">
        <div className="section__inner">
          <div className="section__eyebrow">How it decides</div>
          <h2 className="section__title">Four checks, each answering something the last one can't.</h2>
          <p className="section__subtitle">
            The first two are exact and auditable by hand. The third exists because some attacks
            simply aren't expressible as a rule. The fourth explains the other three — and is
            structurally unable to overrule them.
          </p>
          <div className="layer-grid">
            {LAYERS.map((layer) => (
              <div className="layer-card" key={layer.index}>
                <div className="layer-card__index">{layer.index}</div>
                <div className="layer-card__title">{layer.title}</div>
                <p className="layer-card__body">{layer.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="closing">
        <h2 className="closing__title">Don't take our word for it.</h2>
        <p className="closing__subtitle">
          Build your own mandate, set your own ceiling, and try to get a transaction past it. Or
          walk through five real sessions the detection pipeline has already decided on.
        </p>
        <div className="hero__actions">
          <Link to="/sandbox" className="btn btn--filled">
            Try to break it
          </Link>
          <Link to="/demo" className="btn btn--ghost">
            Open live demo
          </Link>
        </div>
      </section>

      <footer className="app-footer">
        All data shown is synthetic. This is a detector and verifier, not an autonomous enforcement
        system — every automated finding is designed to escalate to a human reviewer.
      </footer>
    </>
  );
}
