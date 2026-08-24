# Agentic-Commerce Transaction Sentinel

**A defense-only verification layer that checks whether an AI agent's payment stays inside what its human actually authorized — before the payment goes through.**

Razorpay AI Buildathon 2026 · Track 02, AI Risk Manager
**Status: Day 1 of 7 build days.** This document describes what has been built and verified so far, and is explicit about what has not been built yet.

---

## 1. The problem, in plain terms

Until recently, "is this payment fraudulent" meant checking the card, the device, the location, the merchant. All of that assumed a human was the one clicking "pay."

That assumption is breaking. In February 2026, Razorpay and NPCI launched agentic UPI payments built on Claude, with Zomato, Swiggy, and Zepto as initial partners — an AI agent can now complete a UPI purchase on a user's behalf without the user tapping "confirm" each time. NPCI is separately developing a Unified Agent Protocol to register, verify, and authorize AI agents across the whole UPI network, not just individual pilots.

Once an agent can spend money on your behalf, a new question appears that no existing fraud system asks: **not "is this transaction fraudulent," but "is this agent staying inside what the human actually agreed to."**

A concrete example: a user tells their grocery-shopping agent, "you can spend up to ₹2,000/month on groceries." Every one of the resulting transactions can be completely legitimate by every classical signal — real card, real merchant, real device, no stolen credentials anywhere in sight — and still be exactly the failure this project is built to catch, if the agent quietly buys ₹8,000 of electronics instead. The card isn't stolen. The agent is just acting outside its authority.

Nobody has published an open, measurably-evaluated defensive layer for that specific failure mode. This project builds one.

## 2. Why Razorpay's existing stack doesn't already cover this

Razorpay already runs a serious risk stack, and this project is deliberately scoped to not duplicate any of it:

| Existing system | What it does | What it doesn't do |
|---|---|---|
| **Vulcan** | Razorpay's payments foundation model — per-transaction fraud scoring, routing, return-to-origin decisions | Doesn't know what a human authorized an *agent* to do; scores the transaction, not the authorization |
| **Bumblebee** | Multi-agent risk review of merchants at onboarding | Operates on merchants, not on individual agent-initiated transactions |
| **Agent Studio** (Dispute Responder, Subscription Recovery, Abandoned Cart, Cashflow Forecaster, RTO Shield) | Post-hoc and operational tooling for merchants | None of these verify a cryptographic mandate or enforce a spending scope before authorization |

The gap is specific: nothing in Razorpay's stack today verifies a signed authorization from a human, checks whether an agent's transaction fits inside it, or watches for behavioral drift in how an agent uses that authorization over time. That's the layer this project adds, sitting in front of authorization rather than reviewing after the fact.

## 3. What the finished system is designed to do

The full design has four detection layers feeding into one reasoning/audit layer. Not all of them exist yet — the table below states current status honestly rather than describing the target architecture as if it were already built.

| Layer | Purpose | Status |
|---|---|---|
| **1. Mandate verification** | Is the agent's signed authorization genuine, unexpired, bound to this agent's registered key, and not already used up? | ✅ **Built, tested (Day 1)** |
| **2. Scope enforcement** | Does this specific transaction — amount, merchant, item category, timing — fit inside what the mandate actually authorizes? | 🔜 Day 3 |
| **3. Behavioral anomaly detection** | Does this agent's session look like a legitimate agent, a bot impersonating one, or a compromised agent, based on patterns rules can't express? | 🔜 Day 4 |
| **4. LLM reasoning & audit** | Given the three deterministic layers' outputs, write a plain-language explanation of the decision. Never sets the score itself — only narrates what the deterministic layers already decided. | 🔜 Day 6 |

Every decision the finished system makes will write an append-only audit record, and every automated block will be human-reviewable — this is a **detector and verifier**, not an autonomous enforcement system, and it is designed to escalate to a human rather than act alone. See [Section 8](#8-defense-only-by-design) for why that matters for this track specifically.

## 4. What's actually built and verified right now — Day 1

Everything below has been implemented, unit-tested, and passed a clean lint and strict type-check pass, not just designed.

**Mandate verification (Layer 1)**
- A cryptographically signed mandate format (`Mandate`, `MandateScope`, `SignedMandate`) that encodes exactly what a human authorized: a spending ceiling, allowed merchant categories (and optionally specific merchants), allowed item categories, a valid time window, and a maximum number of times the mandate can be used.
- Ed25519 digital signatures over a deterministic, byte-exact encoding of every mandate, so a mandate cannot be altered after signing without invalidating the signature.
- A verifier that checks four independent things about a presented mandate — genuine signature from a registered key, not expired, within its valid window, and not already spent past its usage budget — and reports *every* reason a mandate fails, not just the first one found, so an audit trail can say "this was rejected for being both expired and over-budget" rather than hiding the second reason.

**Synthetic data generator**
- A fully parameterized generator that produces realistic legitimate agent sessions: a simulated population of AI agents (each with its own signing key and category preferences), a simulated population of users, and transaction amounts drawn from distributions loosely grounded in public 2025–2026 Indian e-commerce market data (category GMV share and average order value from Mordor Intelligence, IMARC, and the Bain & Company/Flipkart "How India Shops Online 2025" report).
- Every session includes a full lifecycle trace (intent captured → mandate presented → catalog browsed → cart built → payment attempted → payment result), with realistic timing jitter between steps.
- Fully reproducible: every random decision — including which cryptographic keys get generated and which UUIDs get assigned — is derived from a single seed, so the exact same synthetic dataset can be regenerated by anyone from a clean clone. This matters directly for the evaluation honesty this track requires: a reviewer doesn't have to take our word for the numbers later, they can regenerate the exact data those numbers came from.

**Anti-rigging safeguard, built into the type system, not just a policy**
- Every generated session carries a ground-truth label (`LabeledSession`) that wraps the session data rather than sitting alongside it. This is deliberate: it means passing the raw session into a feature extractor or detector is the only thing that type-checks in the code, and leaking the ground-truth label into a feature would require a developer to deliberately reach into a wrapper object detector code has no ordinary reason to touch. The rule "no feature may be a deterministic function of the label" is enforced structurally, not left to be remembered.

**Verification**
- 47 automated tests, all passing, covering mandate validation rules, signature forgery/tampering resistance, every verification failure mode, and generator correctness (including a direct check that every synthetically generated "legitimate" session actually passes mandate verification when replayed through a ledger in chronological order — the generator is checked against the verifier it will eventually be scored by, not assumed to be correct).
- Clean `ruff` lint pass and a clean **strict** `mypy` type-check pass across all source and test code.
- Confirmed reproducible from a genuinely clean environment: a fresh Python virtual environment, dependencies installed from a full pinned lock file, tests re-run — 47/47, unchanged.

## 5. A note on sourcing: why this follows AP2, not NPCI's UAP

The mandate format is modeled on **AP2 (Google's Agent Payments Protocol)**, specifically its Intent Mandate — a real, public, versioned specification (`google-agentic-commerce/AP2`, v0.2.0, April 2026) that already defines exactly the kind of bounded authorization this project needs: a signed record of spending limits, category constraints, and an expiration, produced by a user's own device.

It is **not** modeled on NPCI's own Unified Agent Protocol, because as of this writing, UAP has no published technical schema. It is publicly reported to be under active development at NPCI, built on top of UPI Circle's existing delegated-payments feature, and still awaiting RBI regulatory approval before launch. Building against a real, citable spec is a defensible engineering choice; claiming to implement UAP itself, when no public schema exists to implement, would not be. Where UAP's reported design is known — per-merchant spending limits, consent-based delegation — this project's schema follows that direction anyway, so the fit is closer than "arbitrary substitute."

## 6. How to run this yourself

```bash
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-lock.txt
pip install -e ".[dev]"

pytest -q                        # expect: 47 passed
ruff check .                     # expect: All checks passed!
mypy mandate common generator tests   # expect: Success: no issues found
```

Generate a batch of synthetic sessions and inspect them directly:

```python
from generator.legitimate import generate_legitimate_sessions

out = generate_legitimate_sessions(n_sessions=500, seed=42)
print(len(out.labeled_sessions), "sessions generated")
print(len(out.signed_mandates), "unique mandates issued")
```

`requirements-lock.txt` pins the full dependency closure — not just this project's direct dependencies but every transitive one — so this reproduces the exact environment the numbers above were verified against, not "whatever the latest compatible versions happen to be today."

## 7. Repository structure

```
/mandate      mandate schema, Ed25519 signing, verification         Day 1 — done
/common       shared session trace / ground-truth label types       Day 1 — done
/generator    legitimate traffic generator (attack classes: Day 2)  Day 1 — partial
/features     session feature extraction for the behavioral model   Day 3-4
/detect       scope-enforcement rules engine, behavioral model      Day 3-4
/reasoning    LLM analyst — narrates decisions, never scores them   Day 6
/eval         metrics, significance tests, false-positive-cost curve Day 5
/service      FastAPI service, Dockerfile                           Day 6
/dashboard    Streamlit dashboard                                   Day 7
tests/        47 tests today, growing alongside every layer
```

## 8. The remaining roadmap

| Day | Deliverable |
|---|---|
| 1 ✅ | Mandate schema, signing/verification, session trace format, legitimate traffic generator |
| 2 | Attack generator: mandate replay, scope violation, agent impersonation — deliberately hardened, not trivially separable |
| 3 | Feature extraction + a rules-only baseline (Layers 1+2 only). **Gate day**: if the rules baseline alone already catches everything, the attacks get hardened further before any ML is added |
| 4 | Behavioral anomaly model (Layer 3), ensembled with the rules layer |
| 5 | Full evaluation harness: AUC-PR with bootstrap confidence intervals, calibration, per-attack-class breakdown, DeLong and McNemar significance tests against the rules baseline, and a full false-positive-cost threshold sweep |
| 6 | LLM reasoning/audit layer, FastAPI service, Dockerfile |
| 7 | Streamlit dashboard, **held-out attack class (mandate chaining / privilege escalation) evaluated exactly once**, `EXCEPTIONS.md` documenting every session the system couldn't confidently classify |

One attack class — mandate chaining and privilege escalation, where an agent uses a legitimate small mandate to bootstrap a larger unauthorized action — is deliberately excluded from every stage of training and tuning. It will be generated and evaluated exactly once, at the very end, and whatever degradation shows up relative to in-distribution performance will be reported as-is.

## 9. Defense-only, by design

This project is a **detector and verifier**, not an enforcement or offensive system, at every layer including the ones not yet built. The attack generator (Day 2) exists solely to produce synthetic traffic to test this project's own detector against; it is not designed to, and does not, generalize to attacking real systems. Every automated finding is designed to escalate to a human reviewer rather than act unilaterally. This is a stated disqualification criterion for this track, and is treated as a hard constraint throughout the build, not a checkbox added at the end.

## 10. Known limitation, stated plainly

All data used in this project is synthetic, produced by the generator committed in `/generator`. This is a real limitation, not a hidden one — the anti-rigging measures in Section 4 (held-out attack class, ground-truth labels that can't leak into features, full reproducibility from a committed seed) exist specifically to make the resulting metrics as credible as a synthetic dataset can be, and every number this project ultimately reports will be presented alongside that caveat rather than around it.

## License

MIT — see `LICENSE`.