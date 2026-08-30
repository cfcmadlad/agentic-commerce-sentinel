/**
 * Reference documentation: what this system is, why it exists, and how it
 * decides. Secondary in the sidebar on purpose -- the Overview route is the
 * front door now, this is the page for someone who wants the background
 * before digging into a specific tool.
 */

type IconKind = "lock" | "ruler" | "pulse" | "bubble";

function LayerIcon({ kind }: { kind: IconKind }) {
  const common = { width: 22, height: 22, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
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

export default function About() {
  return (
    <>
      <div className="doc-section">
        <div className="doc-section__eyebrow">Why this exists</div>
        <h2 className="doc-section__title">Card fraud checks catch a stolen card, not an agent going off-script.</h2>
        <p>
          Tell an AI shopping agent "up to ₹2,000 a month on groceries," and today nothing stops it
          from spending ₹8,000 on electronics instead — with a real card, no theft involved.
          Classical fraud detection asks one question: is this transaction fraudulent? Real card,
          real merchant, real device. In that example, every one of those stays completely clean.
          The agent just didn't stay inside what it was actually told to do, and no fraud system
          asks that question, because it was never built to.
        </p>
        <p>
          Razorpay and NPCI have already launched AI agents that complete UPI purchases on a user's
          behalf without a human confirming each one — this is not a hypothetical scenario. This
          project sits in front of the payment and asks the second question instead: does this
          specific purchase match what the human actually agreed to?
        </p>
      </div>

      <div className="doc-section">
        <div className="doc-section__eyebrow">How it decides</div>
        <h2 className="doc-section__title">Four checks, each answering something the last one can't.</h2>
        <p>
          Two terms used throughout this app: the budget from the example above — the ceiling, the
          category, the time window — is called a <strong>mandate</strong>. One attempted purchase
          is called a <strong>session</strong>. The first two checks below are exact and auditable
          by hand. The third exists because some attacks simply aren't expressible as a rule. The
          fourth explains the other three — and is structurally unable to overrule them.
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

      <div className="doc-section">
        <div className="doc-section__eyebrow">Further reading</div>
        <h2 className="doc-section__title">What this project actually builds on.</h2>
        <p>Every method here is a real, citable technique — this is the reading list, not a bibliography for show.</p>
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
    </>
  );
}
