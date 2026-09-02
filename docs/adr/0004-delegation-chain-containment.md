# ADR 0004: Layer 2.5, delegation-chain containment

## Status

Accepted. Layer 2.5 is built, tested, and evaluated exactly once against the
same frozen held-out corpus `docs/adr/0003-held-out-class-evaluation.md`
measured. This document is a record of a design decision and a measurement,
not a proposal.

## Context

`docs/adr/0003` measured a real, disclosed architectural gap: Layers 1-3
each reason about one mandate, or one session against one mandate, in
isolation. None of them compare a mandate's authority to the authority of
the mandate it was delegated from (`Mandate.parent_mandate_id`). The result
was a total miss -- 0.00% recall on every mandate-chaining sub-variant, both
rules-only and ensemble -- and the standing constraint that ADR exists to
enforce is explicit: no code in `detect/`, `features/`, or the generator was
to change in reaction to that number, and any future chain-aware check would
be a legitimate, separate design decision, made and reasoned about on its
own terms.

This document is that decision. Layer 2.5 is a new package (`containment/`), not a
modification to `detect/`, `features/`, or the generator's attack-side
tuning. Nothing in `detect/scope.py`, `detect/behavioral.py`,
`features/session.py`, or any attack generator was touched to build it. It
sits between Layer 2 and Layer 3 in the pipeline and can veto independently,
on the same "add, never override" rule every other deterministic layer in
this project already follows.

**Scope, decided before any evaluation ran.** The brief for this layer fixed
its rule set in advance: deterministic rules only, no ML, no features
borrowed from Layer 3. Five rules, all about a delegated mandate's *authority*
relative to its parent's -- not about who is allowed to receive delegated
authority, not about behavioral pacing, not about anything Layer 3 already
covers. This scope boundary matters for reading the result section below
honestly: a variant this layer does not catch is not necessarily a design
failure, if the reason it evades containment is a property outside what this
layer was ever scoped to check.

## Design

### The five rules (`containment/engine.py`)

Given a mandate that declares a `parent_mandate_id`, and its resolved
immediate parent:

1. **Scope subset.** Every `MandateScope` field must fit inside the parent's:
   the ceiling (`max_amount`), currency, merchant categories, item
   categories, merchant-ID allowlist (a child with no allowlist under a
   parent that has one is a widening, not an absence of restriction), the
   authorized transaction window (`valid_from`/`valid_until`), and the
   transaction count. All eight fields are checked explicitly, one
   comparison each -- no generic walk that could silently skip a field.
2. **Remaining sibling cap.** A delegated mandate's own ceiling must not
   exceed what its parent has left after every *other* child already
   committed against the same parent. This is the rule aimed directly at
   `fanout_structuring`: several individually-unremarkable siblings whose
   combined ceilings exceed the parent's. It is stateful
   (`containment/gate.py::ContainmentGate`), tracking a running commitment
   per parent as sessions are decided in chronological order, mirroring
   `mandate.verification.MandateLedger`'s "budget is consumed only on
   allowed transactions" discipline: a mandate containment rejects never
   counts toward its siblings' remaining cap. Commitments are tracked per
   child mandate, not as a single running total, so re-deciding an
   already-allowed mandate (a session reusing it) is always measured against
   the same remaining cap it originally passed against, never a total that
   double-counts its own prior contribution.
3. **Bounded expiry.** A delegated mandate's own `expires_at` cannot exceed
   its parent's.
4. **Bounded depth.** A delegation chain longer than `MAX_DELEGATION_DEPTH`
   (3 hops) is rejected outright, walked and checked by
   `containment/chain.py::resolve_ancestor_chain`.
5. **No cycles.** A chain that revisits a mandate ID it has already seen --
   including a mandate declaring itself as its own parent -- is rejected
   outright.

A broken chain (cycle, depth exceeded, or an ancestor the store cannot
resolve) fails the whole evaluation closed, rather than checking whatever
partial chain was recovered: a delegation whose ancestry cannot be fully and
safely established is not one this layer can vouch for.

### Fail-closed on what the engine does not recognize

The brief's own words: "any constraint field the engine does not recognise
fails closed rather than passing." This is implemented literally, not as a
comment promising it. `containment/schema.py::assert_known_scope_fields`
compares `MandateScope.model_fields`'s actual field set against the fixed
set of eight fields this engine has an explicit rule for, on every call to
`enforce_containment`, and raises `ContainmentSchemaDriftError` the moment
they diverge -- a future scope field added without a matching containment
rule fails loudly instead of silently becoming an unchecked authority-widening
channel.

The chain store extends the same discipline to a different kind of
unrecognized input: `containment/store.py::build_store_from_signed_mandates`
refuses to let a mandate ID that resolves to two different pieces of content
silently pick one arbitrarily. It drops the ID from the index entirely, so
`get()` reports it as unresolvable, and containment fails closed on it the
same way it fails closed on a cycle. This defense-in-depth check found a real
bug during this layer's own development -- see the addendum in
`docs/adr/0003-held-out-class-evaluation.md` for the full account of the
mandate-ID-collision issue it caught in `generator/attacks/held_out.py`, and
why that bug is now fixed at its root as well, not just contained here. Both
fixes stand independently: the root-cause fix means the collision no longer
happens for this corpus; the store-level check means containment would still
behave correctly even if it did.

### Wiring

`eval/containment_evaluation.py` composes the three deterministic sources
(Layer 1+2 via the existing `RulesOnlyBaseline`, Layer 2.5 via
`ContainmentGate`, and the frozen Layer 3 model/threshold via the existing
`ensemble_decide`) into one pass over a chronologically ordered session
stream: containment only evaluates a session the rules already allowed
(mirroring why Layer 3 skips a rules-blocked session), and Layer 3 only
evaluates a session that also cleared containment. This is a new composition
in `/eval`, not a change to `detect/ensemble.py`'s own scope -- that module
still only knows about the Layer 1/2 verdict and a Layer 3 score, unchanged.

## Evaluation protocol

Evaluated **exactly once**, against the same frozen `PipelineFit` and the
same held-out corpus (`n_legitimate=20000, seed=42,
held_out_n_legitimate=20000, held_out_seed=90042`) `docs/adr/0003` uses --
matching that ADR's own once-only discipline precisely. Nothing was
retrained or recalibrated; the containment rules themselves were not tuned
in response to this run. `run_containment_eval.py` is the reproducing
command.

## Result

76.14% ensemble recall overall (rules-only, matching `docs/adr/0003`, stays
at 0.00% since containment is a new deterministic layer, not a change to
Layers 1 or 2). Zero false positives on legitimate traffic in the default
held-out corpus -- verified by direct measurement
(`containment_false_positives` in the evaluation report), not asserted: no
legitimate mandate this project's generator produces ever declares a
`parent_mandate_id`, so containment structurally cannot fire on one. **That
measurement was, on its own, a structural non-event, not a real test of
containment's false-positive behavior -- see the addendum below for the
real one.**

| Variant | n | Rules-only | Rules+containment | Full stack |
|---|---|---|---|---|
| `budget_escalation` | 456 | 0.00% | 100.00% | 100.00% |
| `breadth_escalation` | 439 | 0.00% | 100.00% | 100.00% |
| `temporal_outlive` | 462 | 0.00% | 100.00% | 100.00% |
| `fanout_structuring` | 1,748 | 0.00% | 75.46% | 75.46% |
| `unauthorized_subdelegation` | 424 | 0.00% | 2.59% | 2.59% |

Layer 3 adds nothing on top of rules+containment on this held-out class --
`rules+containment recall` and `full stack recall` are identical to four
decimal places in every row. This is expected, not a bug: Layer 3 was never
trained or tuned against this class (that is the entire point of the
held-out methodology), and `docs/adr/0003` already showed it has no learned
signal here at all.

### The three variants containment catches completely

`budget_escalation`, `breadth_escalation`, and `temporal_outlive` are each a
single delegated mandate whose own scope, category reach, or expiry openly
exceeds its parent's -- exactly the shape rule 1 or rule 3 above was written
to catch, and each is caught on every one of its held-out sessions.

### `fanout_structuring`: caught at 75.46%, exactly the partial result expected

Predicted in advance, before this layer's own evaluation ran: small-siblings
structuring was expected to mostly survive containment. It mostly does not,
but not completely, and the shape of the miss is precise rather than random. Each
fan-out group is several siblings chained from one parent, minted in close
succession, each individually within its own ceiling but summing well past
the parent's. Processed in chronological order: the first sibling in a group
is measured against the parent's full remaining cap and fits, so it commits.
Every subsequent sibling in that same group is measured against a shrinking
remaining cap and is caught by rule 2. The result is that roughly one in four
sessions of this variant -- the first sibling of every group -- passes,
because at the moment it is decided it is, correctly, indistinguishable from
an ordinary, well-scoped, one-off delegation. Containment has no way to know
in advance that siblings are coming. This is not a bug to patch reactively;
it is the honest limit of a rule that can only reason about commitments
already made, stated plainly rather than reframed as a near-complete catch.

### `unauthorized_subdelegation`: caught only 2.59% of the time, and only incidentally

This is the variant that most directly tests this layer's stated scope
boundary. A subdelegation child is a genuinely-signed hand-off to a second,
real, registered agent the user never authorized -- the confused-deputy
pattern `docs/adr/0003`'s Context describes. Its scope is deliberately built
to match its parent's exactly on every dimension containment checks: same
ceiling, same categories, same window, same expiry. None of the five rules
above have any reason to fire on it, because none of them inspect *who* the
authority moved to -- only how much authority moved and for how long. The
small nonzero recall observed is not this layer succeeding at a different
kind of check; every one of the 2.59% caught sessions was caught by the
remaining-sibling-cap rule, and only because that specific subdelegation
child happened to share a parent with an unrelated, already-committed
sibling from a *different* attack (containment's ledger tracks total
committed capacity per parent across every child, with no awareness of which
generator variant a sibling belongs to, matching the same label-isolation
discipline `features/session.py` already enforces). Verified directly, not
assumed: every caught `unauthorized_subdelegation` session in this
evaluation carries exactly `sibling_cap_exceeds_parent_remaining` as its
reason, never a scope or expiry reason.

**This is disclosed as a real, unclosed gap, not reframed as a near-miss.**
Closing it needs a different kind of check -- whether the receiving agent
identity appears anywhere the user actually consented to, which is an
authorization-provenance question, not an authority-width one -- and that is
real, undone work for a future decision, not a same-session patch to this
layer's rule set.

## Consequences

**Per the same standing constraint `docs/adr/0003` established, this
layer did not touch `detect/`, `features/`, or the generator's
attack-side tuning.** The one change adjacent to the generator
(`generator/attacks/held_out.py::SEED_OFFSET_CHAINING`) is documented
separately, in `docs/adr/0003`'s own addendum, as a mandate-ID-uniqueness
correctness fix this layer's development surfaced -- not a reaction to
any recall number, and not a change to attack difficulty, generation logic,
or any tuning parameter.

**Layer 2.5's own remaining gaps are legitimate future work, not a case for
extending this layer's rule set reactively.** `unauthorized_subdelegation`
needs an identity-provenance check outside this layer's stated scope; the
residual quarter of `fanout_structuring` needs either a different
containment strategy (batching sibling decisions rather than deciding them
one at a time) or a Layer 3 feature representing an agent's own fan-out
rate, which does not currently exist. Neither is addressed here, matching
the discipline this layer was itself built to demonstrate.

## Addendum: a real false-positive measurement, 2026-09-02

The "zero false positives" claim above was true but measured nothing: this
project's generator never produces a legitimate mandate with
`parent_mandate_id` set, so containment structurally cannot fire on the
default held-out corpus regardless of whether the rules are actually
correct. `generator/attacks/legitimate_delegation.py` closes that gap: a
new generator producing genuinely in-bounds delegated mandates (narrower
child than parent on every dimension `_check_scope_subset` checks, both
with and without an explicit child merchant allowlist, plus a legitimate
sibling-fanout shape whose combined ceiling stays comfortably under its
parent's cap) -- the same shapes the mandate-chaining attack variants
distort, but never distorted. `run_containment_eval.py --n-legitimate-
delegation N` adds `N` of these to the held-out corpus.

**In isolation** (this generator's own output, scored against the real
`ContainmentGate`, with no attack corpus sharing the parent pool):
**0 false positives** out of 3,000 sessions, confirmed directly (not
inferred) and pinned by
`tests/test_legitimate_delegation.py::test_zero_false_positives_against_the_real_containment_gate`.
None of the five containment rules -- including the merchant-ID subset
check, the likeliest suspect for a `child=None`-under-a-restricted-parent
false positive -- ever fired incorrectly. No rule needed changing.

**Mixed into the full held-out corpus** alongside the mandate-chaining
attack class (`run_containment_eval.py --n-legitimate 20000 --seed 42
--held-out-n-legitimate 20000 --held-out-seed 90042
--n-legitimate-delegation 3000`): **65 false positives out of 3,000**
(2.17%), **100% attributed to `sibling_cap_exceeds_parent_remaining`**,
zero from any scope/expiry subset rule. Root cause, confirmed by
comparison against the isolated measurement above (not assumed): the
legitimate-delegation generator and the mandate-chaining attack generator
independently draw parents from the same eligible pool. Where an accepted
`fanout_structuring` first sibling (the already-disclosed, un-caught 24.54%
residual documented above and in `EXCEPTIONS.md` §1) happens to share a
parent with a legitimate delegation, that attacker's sibling has genuinely
already consumed part of the parent's real remaining capacity by the time
the legitimate one is decided -- containment correctly rejects the
legitimate one for exceeding what the parent actually has left. This is
the sibling-cap rule doing exactly its job under real resource contention,
not a bug: fixing it would mean letting a delegation through that would
push a parent's committed total over its own declared cap, which is the
one invariant this rule exists to hold. It is a downstream, disclosable
restatement of the already-known `fanout_structuring` gap, not a new one,
and is reported here rather than patched reactively, per this project's
own standing methodology (`docs/adr/0003`).

**Fresh-seed generalization check, rules completely unchanged.** The five
containment rules were fixed before any evaluation ran, but they were
designed by someone who had read the held-out variant taxonomy in advance
-- a close-enough resemblance between rules and variants that it is worth
checking the 76.14% figure isn't an artifact of one particular held-out
seed. Regenerated the held-out corpus at a fresh seed
(`--held-out-seed 123456`, versus the frozen `90042`), same `n_legitimate
=20000`, same fitting corpus, containment rules byte-for-byte unchanged:
overall recall **75.01%** (vs. 76.14% at the original seed), per-variant
`budget_escalation`/`breadth_escalation`/`temporal_outlive` still 100.00%
across all three, `fanout_structuring` 75.98% (vs. 75.46%),
`unauthorized_subdelegation` 1.48% (vs. 2.59%). Every difference is small
and in the direction ordinary seed-to-seed sampling variance would produce,
not a cliff -- the finding is disclosed as measured, not tuned toward.

One side effect worth naming: mixing legitimate-delegation traffic into the
held-out corpus changes the sibling-cap ledger's processing order for the
whole corpus (it is a single running ledger over chronologically-sorted
sessions), which measurably shifts the mandate-chaining recall numbers
(`fanout_structuring` 75.46%→76.49%, `unauthorized_subdelegation`
2.59%→7.55% in one run) relative to the frozen headline. The headline
76.14% figure is unaffected -- it is always measured at
`--n-legitimate-delegation 0` (the default), confirmed byte-identical to
the original run above -- but a report combining both numbers must not
present the shifted recall as the headline. `tests/test_containment_
evaluation.py::test_legitimate_delegation_gives_a_real_nonvacuous_fp_measurement`
pins the false-positive-attribution claim (only `sibling_cap_exceeds_
parent_remaining`, low rate) as a regression test.
