import { Link } from "react-router-dom";
import DataBackdrop from "../components/DataBackdrop";
import MiniCollide from "../components/MiniCollide";

/**
 * Marketing landing page.
 *
 * Static and honest on purpose: every number and claim here is one already
 * measured and reported in the evaluation harness (see /metrics), not
 * fetched live and not invented for effect. The three floating cards
 * mirror real output shapes from the live demo (a blocked decision, a
 * signed SHAP attribution, an evaluation statistic) rather than mocking up
 * a generic product screenshot. `MiniCollide` and `DataBackdrop` are the one
 * exception to "static": both read the same real `public/collision.json`
 * every other data page reads, live, in the browser.
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

type IconKind = "lock" | "ruler" | "pulse" | "bubble";

function LayerIcon({ kind }: { kind: IconKind }) {
  const common = { width: 26, height: 26, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (kind) {
    case "lock":
      return (
        <svg {...common}>
          <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
          <path d="M8 10.5V7a4 4 0 0 1 8 0v3.5" />
        </svg>
      );
    case "ruler":
      return (
        <svg {...common}>
          <rect x="3.5" y="8" width="17" height="8" rx="1.5" />
          <path d="M7 8v3M11 8v3M15 8v3" />
        </svg>
      );
    case "pulse":
      return (
        <svg {...common}>
          <path d="M3 12h4l2 6 4-14 2 8h6" />
        </svg>
      );
    case "bubble":
      return (
        <svg {...common}>
          <path d="M4 5.5h16v10H9l-4 3.5v-3.5H4z" />
          <path d="M8 9.5h8M8 12.5h5" />
        </svg>
      );
  }
}

const PAGES = [
  {
    index: "01",
    title: "Live demo",
    path: "/demo",
    body: "Five real scenarios — an allowed session, a scope violation, a rules-invisible replay, a rules-invisible impersonation, and a forged signature — each walked through all four layers with the actual verdict, SHAP attribution, and narration. Pick a session from the list; every layer lights up in the order it actually ran.",
  },
  {
    index: "02",
    title: "Sandbox",
    path: "/sandbox",
    body: "Build a mandate — spending ceiling, allowed categories, time window — then build a transaction and see whether it survives the same six scope rules Layer 2 runs in production. Drag the sliders and toggle the chips; every change re-runs the real rule engine instantly, no simulation.",
  },
  {
    index: "03",
    title: "Collide",
    path: "/collide",
    body: "2,211 real scored sessions — legitimate traffic and three known attack classes, plotted against the held-out mandate-chaining class this system was never trained to catch. Drag the threshold line and watch each category's block rate recompute live, straight from the real score array.",
  },
  {
    index: "04",
    title: "Terrain",
    path: "/terrain",
    body: "The same real session scores rendered as a pannable, zoomable risk-density map with genuine contour lines, not a stylized illustration. Scroll to zoom, drag to pan, and move the sensitivity slider to see exactly where the map's blind spot sits and how far it shifts.",
  },
  {
    index: "05",
    title: "Evaluation",
    path: "/metrics",
    body: "The full evaluation report — precision and recall, bootstrap confidence intervals, significance tests against the rules-only baseline, and the thirteen-point sensitivity grid — rendered directly from a real run of the harness. Every number here traces back to the command that produced it.",
  },
];

const LAYERS: { index: string; title: string; body: string; icon: IconKind }[] = [
  {
    index: "01",
    title: "Mandate verification",
    icon: "lock",
    body: "Every transaction arrives with a cryptographically signed authorization. It's checked for a genuine signature, a valid time window, and remaining budget — before anything else runs.",
  },
  {
    index: "02",
    title: "Scope enforcement",
    icon: "ruler",
    body: "The transaction is checked against ten deterministic rules drawn from the mandate itself: amount, merchant, category, timing. Exact comparisons, no tolerance band to hide behind.",
  },
  {
    index: "03",
    title: "Behavioral detection",
    icon: "pulse",
    body: "A model trained only on sessions the rules above already allowed, watching for the one thing rules can't see: a session that doesn't behave like the agent it claims to be.",
  },
  {
    index: "04",
    title: "Reasoning & audit",
    icon: "bubble",
    body: "A plain-language explanation of the verdict, citing the exact rule or feature that drove it. It narrates the decision — it never gets a vote in what the decision is.",
  },
];

const FURTHER_READING = [
  {
    label: "AP2 — Agent Payments Protocol",
    detail: "Google's public, versioned mandate spec (google-agentic-commerce/AP2) this project's mandate schema is modeled on.",
    href: "https://github.com/google-agentic-commerce/AP2",
  },
  {
    label: "Ed25519 signatures",
    detail: "Bernstein, Duif, Lange, Schwabe & Yang — the deterministic signature scheme every mandate here is signed with.",
    href: "https://ed25519.cr.yp.to/",
  },
  {
    label: "A Unified Approach to Interpreting Model Predictions",
    detail: "Lundberg & Lee, 2017 — the SHAP method behind every feature-attribution number on this site.",
    href: "https://arxiv.org/abs/1705.07874",
  },
  {
    label: "LightGBM: histogram-based gradient boosting",
    detail: "Ke et al., 2017 — the algorithmic approach scikit-learn's HistGradientBoostingClassifier (Layer 3's model) implements.",
    href: "https://github.com/microsoft/LightGBM",
  },
  {
    label: "McNemar's test (1947) and DeLong et al. (1988)",
    detail: "The paired-classifier and correlated-AUC significance tests this project's evaluation harness hand-rolls and verifies against — cited by name, not linked, since neither has a stable open host.",
    href: null,
  },
];

export default function Landing() {
  return (
    <>
      <section className="hero">
        <DataBackdrop className="data-backdrop--hero" />
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

      <section className="section--fog">
        <div className="section__inner">
          <div className="section__eyebrow">Why this exists</div>
          <h2 className="section__title">
            Fraud detection asks one question. Agentic payments raise a second one nobody's checking.
          </h2>
          <p className="section__subtitle">
            AI agents can now spend money on a human's behalf — Razorpay and NPCI have already
            launched agentic UPI payments. Classical fraud detection asks whether a transaction is
            fraudulent: real card, real merchant, real device. Once an agent can act for someone, a
            different failure becomes possible, and nothing in that stack looks for it — a user
            authorizes "up to ₹2,000/month on groceries," and the agent spends ₹8,000 on electronics.
            Every classical signal stays clean. The agent simply acted outside the authority it was
            given. This project is a verification layer for exactly that failure: it checks the
            agent's signed authorization, enforces the scope that authorization actually grants, and
            watches for sessions that don't look like the agent that was supposed to be acting.
          </p>
          <p className="section__subtitle" style={{ marginTop: 14 }}>
            A quick glossary, since the rest of this site uses these words a lot: a{" "}
            <strong>mandate</strong> is the signed, bounded authorization a human gives an agent (a
            ceiling, a category, a time window). A <strong>session</strong> is one attempted
            transaction. A <strong>layer</strong> is one of the four checks below — each one either
            blocks a session, passes it to the next layer, or (for Layer 4) narrates what the earlier
            three already decided.
          </p>
        </div>
      </section>

      <div className="artifact-section">
        <div className="artifact-grid">
          <DecisionCard />
          <AttributionCard />
          <EvaluationCard />
        </div>
      </div>

      <section className="live-finding">
        <div className="live-finding__text">
          <div className="section__eyebrow">The honest part</div>
          <h2 className="live-finding__title">
            We held out an entire attack class and never trained against it.
          </h2>
          <p className="live-finding__body">
            The system catches 99.76% of the attacks it was built to catch. Against a class it was
            never shown — mandate chaining, exploiting the relationship between a mandate and its
            parent — it catches 0.88%. That's the number worth leading with. Drag the line yourself;
            there's no threshold in this real data that fixes it.
          </p>
        </div>
        <MiniCollide />
      </section>

      <section className="section--fog">
        <div className="section__inner">
          <div className="section__eyebrow">How it decides</div>
          <h2 className="section__title">Four checks, each answering something the last one can't.</h2>
          <p className="section__subtitle">
            The first two are exact and auditable by hand. The third exists because some attacks
            simply aren't expressible as a rule. The fourth explains the other three — and is
            structurally unable to overrule them.
          </p>

          <div className="flow-strip" aria-hidden="true">
            {LAYERS.map((layer, i) => (
              <div className="flow-strip__step" key={layer.index}>
                <div className="flow-strip__node">
                  <LayerIcon kind={layer.icon} />
                </div>
                <span className="flow-strip__label">{layer.title}</span>
                {i < LAYERS.length - 1 && <span className="flow-strip__arrow">→</span>}
              </div>
            ))}
          </div>

          <div className="layer-grid">
            {LAYERS.map((layer) => (
              <div className="layer-card" key={layer.index}>
                <div className="layer-card__icon">
                  <LayerIcon kind={layer.icon} />
                </div>
                <div className="layer-card__index">{layer.index}</div>
                <div className="layer-card__title">{layer.title}</div>
                <p className="layer-card__body">{layer.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section--fog">
        <div className="section__inner">
          <div className="section__eyebrow">Around the site</div>
          <h2 className="section__title">Five ways to look at the same real system.</h2>
          <p className="section__subtitle">
            Nothing below is a mockup. Each page reads real decisions, real per-session scores, or a
            real port of the production rule engine — no page needs the others open to make sense.
          </p>
          <div className="layer-grid">
            {PAGES.map((page) => (
              <Link to={page.path} className="layer-card guide-card" key={page.path}>
                <div className="layer-card__index">{page.index}</div>
                <div className="layer-card__title">{page.title}</div>
                <p className="layer-card__body">{page.body}</p>
                <span className="guide-card__cta">Open {page.title.toLowerCase()} →</span>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="section--fog">
        <div className="section__inner">
          <div className="section__eyebrow">Further reading</div>
          <h2 className="section__title">What this project actually builds on.</h2>
          <p className="section__subtitle">
            Every method here is a real, citable technique, not an invented one — this is the reading
            list, not a bibliography for show.
          </p>
          <ul className="reading-list">
            {FURTHER_READING.map((item) => (
              <li className="reading-list__item" key={item.label}>
                {item.href ? (
                  <a href={item.href} target="_blank" rel="noreferrer" className="reading-list__label">
                    {item.label} ↗
                  </a>
                ) : (
                  <span className="reading-list__label">{item.label}</span>
                )}
                <p className="reading-list__detail">{item.detail}</p>
              </li>
            ))}
          </ul>
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
