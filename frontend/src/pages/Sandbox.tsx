import { useState } from "react";
import {
  VIOLATION_LABELS,
  evaluateScope,
  type SandboxMandate,
  type SandboxTransaction,
  type ScopeViolation,
} from "../sandbox/scopeEngine";

/**
 * Build a mandate. Try to break it.
 *
 * Every rule here runs the real logic Layer 2 runs (see
 * `sandbox/scopeEngine.ts`), not a scripted simulation -- there is no
 * tolerance band to slip through because the real system doesn't have one
 * either. This page has no fixed narrative; it's replayable indefinitely,
 * on purpose.
 */

const CATEGORIES = ["grocery", "electronics", "fashion"];
const ITEMS = ["packaged_food", "produce", "laptops", "phones", "apparel"];
const CURRENCIES = ["INR", "USD", "EUR"];

interface Attempt {
  id: number;
  blocked: boolean;
  reasons: ScopeViolation[];
  amount: number;
}

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

export default function Sandbox() {
  const [maxAmount, setMaxAmount] = useState(2000);
  const [allowedCategories, setAllowedCategories] = useState<string[]>(["grocery"]);
  const [allowedItems, setAllowedItems] = useState<string[]>(["packaged_food", "produce"]);
  const [windowHours, setWindowHours] = useState(24);
  const [restrictMerchant, setRestrictMerchant] = useState(false);
  const [allowedMerchant, setAllowedMerchant] = useState("bigbasket");

  const [txAmount, setTxAmount] = useState(500);
  const [txCategory, setTxCategory] = useState("grocery");
  const [txItem, setTxItem] = useState("packaged_food");
  const [txMerchant, setTxMerchant] = useState("bigbasket");
  const [txCurrency, setTxCurrency] = useState("INR");
  const [txTimeHours, setTxTimeHours] = useState(2);

  const [log, setLog] = useState<Attempt[]>([]);
  const [nextId, setNextId] = useState(1);

  const mandate: SandboxMandate = {
    maxAmount,
    currency: "INR",
    allowedMerchantCategories: allowedCategories,
    allowedItemCategories: allowedItems,
    allowedMerchantIds: restrictMerchant ? [allowedMerchant] : null,
    validFromHours: 0,
    validUntilHours: windowHours,
  };

  const tx: SandboxTransaction = {
    amount: txAmount,
    currency: txCurrency,
    merchantCategory: txCategory,
    itemCategory: txItem,
    merchantId: txMerchant,
    timestampHours: txTimeHours,
  };

  // Cheap pure function over a handful of comparisons -- no memoization
  // needed, and `mandate`/`tx` are fresh object literals every render
  // anyway, which would defeat useMemo's dependency check.
  const violations = evaluateScope(mandate, tx);
  const blocked = violations.length > 0;

  const blockedCount = log.filter((a) => a.blocked).length;
  const allowedCount = log.length - blockedCount;

  function attempt() {
    setLog((prev) => [{ id: nextId, blocked, reasons: violations, amount: txAmount }, ...prev].slice(0, 12));
    setNextId((n) => n + 1);
  }

  return (
    <>
      <div className="panel">
        <div className="page-intro">
          <span className="page-intro__eyebrow">New here?</span>
          <p>
            A "mandate" is what a human authorizes an AI shopping agent to spend, and on what — a
            ceiling, a set of categories, a time window. Build one on the left, then try to sneak a
            transaction past it on the right. Every rule here is the real one this system enforces,
            ported line for line, not a simplified stand-in.
          </p>
        </div>
        <h2 className="section-title">Build a mandate. Try to break it.</h2>
        <p className="section-note">
          This runs the same six scope rules Layer 2 runs in production — exact comparisons, no
          tolerance band. Drag anything below; there's no fixed path through this page.
        </p>
      </div>

      <div className="sandbox-grid">
        <div className="panel">
          <h3 className="section-title">The mandate</h3>
          <p className="section-note">What the human actually authorized.</p>

          <label className="field-label">Spending ceiling: ₹{maxAmount.toLocaleString()}</label>
          <input
            type="range"
            min={100}
            max={10000}
            step={50}
            value={maxAmount}
            onChange={(e) => setMaxAmount(Number(e.target.value))}
            className="sandbox-slider"
          />

          <label className="field-label">Allowed merchant categories</label>
          <div className="chip-row">
            {CATEGORIES.map((c) => (
              <button
                key={c}
                className={`chip ${allowedCategories.includes(c) ? "chip--on" : ""}`}
                onClick={() => setAllowedCategories(toggle(allowedCategories, c))}
              >
                {c}
              </button>
            ))}
          </div>

          <label className="field-label">Allowed item categories</label>
          <div className="chip-row">
            {ITEMS.map((c) => (
              <button
                key={c}
                className={`chip ${allowedItems.includes(c) ? "chip--on" : ""}`}
                onClick={() => setAllowedItems(toggle(allowedItems, c))}
              >
                {c}
              </button>
            ))}
          </div>

          <label className="field-label">Valid for the next {windowHours}h</label>
          <input
            type="range"
            min={1}
            max={72}
            value={windowHours}
            onChange={(e) => setWindowHours(Number(e.target.value))}
            className="sandbox-slider"
          />

          <label className="field-label" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={restrictMerchant}
              onChange={(e) => setRestrictMerchant(e.target.checked)}
            />
            Restrict to one merchant
          </label>
          {restrictMerchant && (
            <input
              type="text"
              value={allowedMerchant}
              onChange={(e) => setAllowedMerchant(e.target.value)}
              className="sandbox-input"
              placeholder="merchant id"
            />
          )}
        </div>

        <div className="panel">
          <h3 className="section-title">The transaction</h3>
          <p className="section-note">What the agent is trying to spend it on.</p>

          <label className="field-label">Amount: ₹{txAmount.toLocaleString()}</label>
          <input
            type="range"
            min={0}
            max={12000}
            step={25}
            value={txAmount}
            onChange={(e) => setTxAmount(Number(e.target.value))}
            className="sandbox-slider"
          />

          <label className="field-label">Merchant category</label>
          <div className="chip-row">
            {CATEGORIES.map((c) => (
              <button
                key={c}
                className={`chip ${txCategory === c ? "chip--on" : ""}`}
                onClick={() => setTxCategory(c)}
              >
                {c}
              </button>
            ))}
          </div>

          <label className="field-label">Item category</label>
          <div className="chip-row">
            {ITEMS.map((c) => (
              <button key={c} className={`chip ${txItem === c ? "chip--on" : ""}`} onClick={() => setTxItem(c)}>
                {c}
              </button>
            ))}
          </div>

          <label className="field-label">Currency</label>
          <div className="chip-row">
            {CURRENCIES.map((c) => (
              <button
                key={c}
                className={`chip ${txCurrency === c ? "chip--on" : ""}`}
                onClick={() => setTxCurrency(c)}
              >
                {c}
              </button>
            ))}
          </div>

          <label className="field-label">Merchant</label>
          <input
            type="text"
            value={txMerchant}
            onChange={(e) => setTxMerchant(e.target.value)}
            className="sandbox-input"
          />

          <label className="field-label">Timing: hour {txTimeHours} (window is 0–{windowHours})</label>
          <input
            type="range"
            min={-24}
            max={96}
            value={txTimeHours}
            onChange={(e) => setTxTimeHours(Number(e.target.value))}
            className="sandbox-slider"
          />
        </div>
      </div>

      <div className="panel sandbox-verdict-panel">
        <div className="sandbox-verdict-row">
          <span className={`badge sandbox-verdict-badge ${blocked ? "badge--block" : "badge--allow"}`}>
            {blocked ? "blocked" : "allowed"}
          </span>
          <button className="btn btn--filled" onClick={attempt}>
            Attempt transaction
          </button>
        </div>
        {violations.length > 0 && (
          <div className="citation-group" style={{ marginTop: 12 }}>
            {violations.map((v) => (
              <span className="badge badge--block" key={v}>
                {VIOLATION_LABELS[v]}
              </span>
            ))}
          </div>
        )}
        {violations.length === 0 && (
          <p className="section-note" style={{ marginTop: 12, marginBottom: 0 }}>
            Every rule passes. Nudge the amount right up to the ceiling — it holds exactly at
            ₹{maxAmount.toLocaleString()}, not a rupee past it.
          </p>
        )}
      </div>

      {log.length > 0 && (
        <div className="panel">
          <h3 className="section-title">Attempt log</h3>
          <p className="section-note">
            {log.length} attempted · {blockedCount} blocked · {allowedCount} allowed. There is no
            combination above that gets a violating transaction marked "allowed" — that's not a
            game restriction, it's the rule engine having no tolerance band to find.
          </p>
          <div className="attempt-log">
            {log.map((a) => (
              <div className="attempt-row" key={a.id}>
                <span className={`badge ${a.blocked ? "badge--block" : "badge--allow"}`}>
                  {a.blocked ? "blocked" : "allowed"}
                </span>
                <span className="attempt-row__amount">₹{a.amount.toLocaleString()}</span>
                <span className="attempt-row__reasons">
                  {a.reasons.length > 0 ? a.reasons.map((r) => VIOLATION_LABELS[r]).join(", ") : "within scope"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
