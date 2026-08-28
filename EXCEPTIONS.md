# Exceptions

Every number in the README's evaluation section is an aggregate. This document is the aggregate's
opposite: it names the specific, reproducible categories of sessions this system currently cannot
confidently classify, why each one falls through, what signal (if any) came closest to firing, and
what would actually close the gap. Nothing here is a hypothetical "known limitation" restated in the
abstract — every count below comes from a run of this repository's own evaluation code, against the
same seeds the README's headline numbers use, and is reproducible with the command given in each
section.

This list is not exhaustive in the sense of naming every individual synthetic session — the data is
regenerated from a seed on every run, so a specific session ID is not a stable thing to point at.
It is exhaustive in the sense that every population-level exception this evaluation surfaces is
named here, not just the one the README leads with.

---

## 1. Mandate-chaining / privilege escalation — what Layer 2.5 still misses

**What it is.** An agent uses a legitimate, correctly scoped mandate to bootstrap a larger,
unauthorized action by exploiting a declared delegation relationship (`Mandate.parent_mandate_id`)
rather than by forging or misusing a single mandate directly. Five sub-variants: `budget_escalation`,
`breadth_escalation`, `temporal_outlive`, `unauthorized_subdelegation`, `fanout_structuring`. Full
definitions in README §6.

**Layers 1-3 alone miss all of it — Layer 2.5 (containment) recovers most of it.** Every check in
Layers 1-3 reasons about one mandate in isolation, or one session against the mandate it presents —
never a mandate's authority against its parent's, so all 3,529 held-out attacks scored below half the
operating threshold before Layer 2.5 existed (`docs/adr/0003-held-out-class-evaluation.md`). Layer 2.5
(`/containment`, `docs/adr/0004-delegation-chain-containment.md`) was built afterward specifically for
this gap: five deterministic rules comparing a delegated mandate to its resolved parent (scope subset,
remaining sibling cap, bounded expiry, bounded depth, no cycles). Evaluated once against the same
frozen held-out corpus, it lifts ensemble recall from 0.00% to 76.14%. What follows is what still falls
through *after* Layer 2.5, not the original three-layer picture.

**Why the remainder falls through.** `unauthorized_subdelegation` is a genuinely-signed hand-off to a
second agent the user never authorized — its scope otherwise matches its parent exactly, so none of
Layer 2.5's five rules (all about authority *width*, not identity) have any reason to fire. The small
amount that is caught (2.59%) is incidental: it happens only when that subdelegated mandate shares a
parent with an unrelated, already-committed sibling, so the remaining-cap rule fires for a reason that
has nothing to do with the subdelegation itself. `fanout_structuring`'s residual 24.54% is the first
sibling in each structuring group: individually within its own declared ceiling and, at the moment it
is decided, genuinely the first claim against its parent's capacity — indistinguishable from an
ordinary well-scoped delegation until later siblings arrive and the pattern becomes visible in
hindsight.

| Variant | n | Rules-only recall | Rules+containment recall | Full stack recall |
|---|---|---|---|---|
| `budget_escalation` | 456 | 0.00% | 100.00% | 100.00% |
| `breadth_escalation` | 439 | 0.00% | 100.00% | 100.00% |
| `temporal_outlive` | 462 | 0.00% | 100.00% | 100.00% |
| `fanout_structuring` | 1,748 | 0.00% | 75.46% | 75.46% |
| `unauthorized_subdelegation` | 424 | 0.00% | 2.59% | 2.59% |

**What would resolve it.** For `unauthorized_subdelegation`: a rule checking agent-identity continuity
across a delegation chain (does the receiving agent appear anywhere the user actually authorized),
which is a different kind of property than anything Layer 2.5 currently checks. For the residual
`fanout_structuring` share: nothing short-circuits the "first sibling looks ordinary" problem within a
single deterministic pass — a behavioral feature comparing a mandate's sibling count or fan-out rate
against its own agent's history is the more plausible fix, and Layer 3 does not currently have one. Per
the project's own standing constraint, this is a legitimate future milestone with its own design
reasoning, not a same-session patch written in reaction to these numbers.

**Reproduce with:**
```bash
python run_held_out_eval.py --n-legitimate 20000 --seed 42 --held-out-n-legitimate 20000 --held-out-seed 90042
python run_containment_eval.py --n-legitimate 20000 --seed 42 --held-out-n-legitimate 20000 --held-out-seed 90042
```

---

## 2. The one known-class session that still gets through, in-distribution

**What it is.** Even restricted to the three attack classes this system is actually trained and
tuned against, the deployed operating threshold does not achieve literal 100% recall. On the
Milestone B test block (411 attacks), the `behavioral_only` impersonation variant is caught at
98.21% recall (55 of 56) rather than 100% — the single miss behind the reported 99.76% ensemble
recall figure.

**Why it falls through.** This is not a zero-signal case like §1 above — Layer 3 does score this
session, just under the calibrated cutoff. It is the ordinary tail of any thresholded classifier: a
`behavioral_only` session (a scripted client operating a genuinely valid mandate, paced faster and
more uniformly than the legitimate distribution) that happened to land on the well-behaved side of
that spectrum.

**Closest signal that fired.** Its behavioral score was 0.00676, against an operating threshold of
0.02513 — 27% of the threshold. That places it in the `behaviorally_ordinary` bucket by the same
half-threshold convention Milestone C's held-out evaluation uses, not a near-miss the threshold could
plausibly be nudged to catch without moving a great many legitimate sessions with it (see the cost
sweep in README §7: the threshold basin is broad, but not free to move).

**What would resolve it.** Nothing free. Lowering the threshold trades this exact miss for more
false positives elsewhere, at the rate the cost sweep already reports. This is disclosed as the
honest cost of operating a probabilistic layer at a fixed cutoff, not as a bug to be patched.

**Reproduce with:**
```bash
python run_milestone_a.py --n-legitimate 20000 --seed 42
```
(the per-variant recall table's `behavioral_only` row)

---

## 3. Scripted-client pacing, if it turns out to resemble real agent timing

**What it is.** Not a currently observed failure — a documented condition under which Layer 3's
confidence would collapse if real agentic traffic turns out to look like it. The sensitivity grid in
README §7 widens the scripted-client inter-event pacing that defines `behavioral_only` and
`rapid_reuse` from the established 20-second maximum to 35 seconds, pushing it almost entirely inside
the legitimate traffic's own 2–45 second jitter range.

**Why it would fall through.** Both rules-invisible variants exist specifically because they are
invisible to rules and rely on Layer 3's timing features to be caught at all. If those features can
no longer separate scripted pacing from ordinary jitter, there is nothing else in the system standing
behind them.

**Closest signal that fired.** At the established setting, ensemble recall on the two
rules-invisible variants is 0.9859. At the widened pacing setting, it collapses to 0.5070 — Layer 3
catches roughly half of what it exists to catch — and the ensemble no longer significantly
outperforms the rules-only baseline at that grid point. AUC-PR barely moves (−0.0186) while this
recall figure halves, so AUC-PR alone would not have surfaced this.

**What would resolve it.** Measuring real agentic inter-event timing before relying on this
project's pacing-based features for production detection. This is the same conclusion README §11
already states as the biggest open question for real-world transfer — restated here as a named
exception category rather than a general caveat.

**Reproduce with:**
```bash
python run_milestone_b.py --n-legitimate 20000 --seed 42
```
(the sensitivity grid section, `scripted_pacing_max35` row)

---

## 4. The sparse middle of the score distribution

**What it is.** The calibration reliability diagram (README §7) is dominated by a single near-zero
bin holding 3,752 of the test residual's rows. Every bin between roughly 0.1 and 0.9 holds fewer than
ten sessions each.

**Why it's an exception.** A session whose score happens to land in that thin middle band gets a
probability estimate this evaluation cannot actually vouch for — the reported Brier score (0.00499)
and expected calibration error (0.00532) are correct as aggregate statistics, but they are almost
entirely a statement about the well-populated near-zero bin, not about the middle of the range.

**Closest signal that fired.** None distinguishable from noise — with under ten sessions per bin,
any single session's placement is not a stable measurement of that bin's true calibration.

**What would resolve it.** Substantially more evaluation volume in the middle score range. This is
unlikely to come from more synthetic data alone, since the generator's own class separation pushes
most sessions toward the extremes by construction — real traffic, with its messier natural spread of
ambiguous cases, is the more plausible source.

**Reproduce with:**
```bash
python run_milestone_b.py --n-legitimate 20000 --seed 42
```
(the calibration section's reliability diagram)

---

## 5. The mirror case: legitimate sessions this system blocks anyway

**What it is.** At the deployed operating threshold, the ensemble's precision is 0.9785, not 1.0 —
the cost sweep in README §7 reports roughly 21.6 wrongly blocked legitimate sessions per 10,000, at
the threshold this project actually runs at.

**Why it happens.** Speculative, and stated as such rather than measured: the top two SHAP features
by mean contribution are `agent_prior_session_count` and `mandate_prior_use_count` — both, by
construction, about how new an agent or mandate is. Attack sessions are frequently first-use-by-nature
(a freshly minted impersonation, a mandate replayed for the first illegitimate time), so a legitimate
agent or mandate genuinely new to the system may present similarly thin history and score closer to
the attack population than an established one would.

**Closest signal that fired.** Not separately instrumented in this evaluation — the cost sweep
reports the aggregate false-positive rate, not which sessions specifically drove it or whether they
cluster on low prior-history counts. This causal claim is plausible from the feature ranking, not
confirmed by a dedicated analysis.

**What would resolve it.** A deliberate cold-start policy for agents or mandates with little history
— a grace period, a blended prior, or a separate lower-confidence review lane — is not currently
implemented anywhere in this project. If the speculative cause above is confirmed by a proper
per-session breakdown, that is the concrete next feature to design, not to retrofit into the frozen
Milestone B model.

**Reproduce with:**
```bash
python run_milestone_b.py --n-legitimate 20000 --seed 42
```
(the cost-sweep table, `Blocked legitimate /10k` column at the deployed threshold)

---

Sections 1, 2, and 4 above come directly from this repository's evaluation output with no additional
analysis. Section 3 restates an already-computed sensitivity-grid result as a named exception rather
than a general caveat. Section 5's mechanism is explicitly flagged as inference, not measurement —
consistent with this project's standing rule that an assumption gets named as one rather than
presented with the confidence of a measured result.
