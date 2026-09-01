# Threat model

One page, per layer: what it stops, what it explicitly does not, and why. This is a defense-only system throughout ([README](README.md#defense-only-and-where-this-falls-short)). Nothing here generates, launches, or automates an attack against a real system; the attack generators exist solely to produce synthetic test traffic against this project's own detectors, and every automated finding escalates to a human rather than acting unilaterally.

## Layer 1: mandate verification (`/mandate`, `mandate/verification.py`)

**Stops:** an unregistered signing key, a forged or corrupted signature, a mandate presented outside its own valid time window, a mandate whose transaction budget is already exhausted, and a session presented after its signing key has been explicitly revoked, checked against the actual decision instant so a backdated session timestamp cannot evade a live revocation ([docs/adr/0014](docs/adr/0014-agent-key-lifecycle.md)).

**Does not stop:** a session that presents a *genuinely* signed, currently-valid mandate for something the mandate never should have authorized in the first place. That's Layer 2's job, not this one. Does not detect a compromised private key being used to sign *new*, freshly-valid mandates before anyone revokes it; revocation is a human action ([docs/adr/0014](docs/adr/0014-agent-key-lifecycle.md)), never automatic, so the gap between compromise and revocation is a real window this layer cannot close on its own.

## Layer 2: scope enforcement (`/detect/scope.py`)

**Stops:** a transaction over the mandate's own amount ceiling, outside its allowed merchant or item categories, against a merchant not on its allowlist, outside its valid time window, or from an agent whose identity doesn't match the mandate's binding.

**Does not stop:** anything *inside* the declared scope, by definition. A scope violation is only ever a mismatch between the transaction and the mandate's own stated limits, not a judgment about whether those limits were wise. Has no concept of a mandate's place in a delegation chain at all: a sub-mandate that is itself within its own stated scope but was never actually authorized by anything upstream passes Layer 2 cleanly. That gap is Layer 2.5's.

## Layer 2.5: delegation-chain containment (`/containment`)

**Stops:** a delegated mandate whose amount, category set, time window, or transaction count exceeds what its immediate parent actually authorized it to have, including a sibling-cap violation (several children of one parent collectively over-committing its budget) checked against a sequential, insertion-order ledger, and a broken chain topology (a cycle, an unresolvable ancestor, or a depth bound exceeded).

**Does not stop:** `unauthorized_subdelegation`, a hand-off that is genuinely, validly signed at every link, and every link individually stays within its parent's declared authority, but the human who granted the *root* mandate never actually authorized this particular downstream agent to hold it at all. Containment checks authority *width* against a parent, not agent-identity continuity across the whole chain. Measured at 2.59% recall on this specific sub-variant, a disclosed, undone gap, not a rounding error ([README](README.md#results)).

## Layer 3: behavioral anomaly detection (`/detect`, gradient-boosted model)

**Stops:** the two attack variants deliberately constructed to be invisible to Layers 1 and 2 by construction, `rapid_reuse` mandate replay and `behavioral_only` impersonation, by learning session-timing and usage-pattern signal Layers 1-2 have no representation for at all.

**Does not stop, and cannot ever be relied on alone to stop:** anything by itself. It only ever adds a block on top of what Layers 1-2 already allow, never overrides a deterministic rejection ([README](README.md#defense-only-and-where-this-falls-short)). Trained entirely on synthetic session timing; the sensitivity grid found that widening scripted-client pacing to sit inside legitimate jitter halves recall on exactly the two variants this layer exists to catch, at which point it no longer significantly beats the rules-only baseline ([README](README.md#results), [EXCEPTIONS.md](EXCEPTIONS.md)). This is the layer most in need of retraining before any real-world use; real agent traffic will not match this generator's timing distribution.

## Layer 4: reasoning and narration (`/reasoning`, Groq-backed)

**Stops:** nothing. Layer 4 is structurally non-mutating by design. It never touches a score or a verdict; `reasoning/narrate.py`'s own module docstring and the adversarial prompt-injection test suite (`tests/test_prompt_injection_resistance.py`) both hold that a narration prompt, however crafted, cannot flip the reported verdict or leak its own system prompt, because the verdict and citations are parsed from `NarrationInput`, never from the model's own text.

**Does not stop, and is not meant to:** a narration call failing does not fail the decision itself. `service/main.py::decide()` catches any Layer 4 exception (a provider error, a rate limit, a timeout) and falls back to an honest placeholder, a real robustness gap discovered and fixed this session precisely because it violated this layer's own "always best-effort, never a precondition for a decision" claim ([docs/adr/0014](docs/adr/0014-agent-key-lifecycle.md)). Narration text itself is not reproducible the way every other number in this project is; an LLM's prose cannot meet a from-seed reproducibility bar even at temperature 0, so treat it as an explanation of a reproducible decision, never as a reproducible artifact in its own right.

## Formal verification (`/formal`, Z3)

**Proves:** eight named safety properties hold *exhaustively* over the bounded domains encoded (amount-ceiling and merchant-allowlist bypass resistance, expired/budget-exhausted denial, delegated-scope attenuation, the depth bound, the sibling-cap invariant, allow/hold mutual exclusivity) for Layers 1, 2, and 2.5's real decision logic, not a hand-written model of it. Demonstrated to catch a real bug on purpose: a deliberately reversed `IsSubset` direction returns a genuine `sat` counterexample.

**Does not prove:** anything about Layer 3 at all. The learned model is abstracted as a free input to the proof, never encoded, since a gradient-boosted model has no closed form Z3 could reason about. Does not prove containment's own *stateful*, arbitrary-length sibling ledger in general; P7 unrolls the sibling-cap recurrence for a fixed 4-sibling group, which is exactly the gap Milestone L's property-based tests (Hypothesis, arbitrary-length trees against the real `ContainmentGate`) exist to cover instead: exhaustive proof over a bounded case, generative sampling over the unbounded one, deliberately not the same guarantee.

## Collusion / ring detection (`/collusion`)

**Stops:** three planted malicious coordination archetypes (shared device/network fingerprint reuse across agents, cross-agent purchase structuring, and counterparty rings) at 100% recall and 100% precision at the calibrated threshold, with 0% false positives on two deliberately hard legitimate look-alikes (a real household, a shared network gateway).

**Does not stop:** collusion at higher per-agent session density than calibrated for. Baseline-agent false-positive noise rises measurably as volume increases against a fixed agent pool, an honestly measured and reported density-sensitivity boundary, not a hidden cliff ([docs/adr/0006](docs/adr/0006-collusion-ring-detection.md)). Is a separate detection surface entirely from Layers 1-4 and is not wired into `/sessions/decide`'s live per-session verdict.

## What no layer here stops

**A key compromised and used before revocation.** Revocation is real and checked at decision time, but it is a human action, never automatic. Nothing in this system detects a compromise on its own and triggers revocation itself.

**Real-world distribution shift.** Every number in this document comes from a synthetic generator ([README](README.md#defense-only-and-where-this-falls-short)). The rules layers transfer directly to real data since they are explicit logic, but Layer 3 and the collusion layer are both trained/calibrated on synthetic timing and volume distributions that real agent traffic is not guaranteed to match.

**A compromised deployment process itself.** Nothing here defends the service's own supply chain, host, or secrets management. This is a detection and verification layer sitting in front of a payment flow, not a general application-security posture for whatever infrastructure runs it.
