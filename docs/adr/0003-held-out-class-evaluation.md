# ADR 0003: Held-out class (mandate chaining) evaluation result

## Status
Accepted. This is a record of a measurement, not a decision to be revisited.

## Context

The project's taxonomy names a fourth attack class -- mandate chaining /
privilege escalation -- that was deliberately never generated, referenced, or
looked at while Layers 1-3 were designed, trained, or tuned (Milestones A and
B). The generator for this class was authored in an isolated context with no
visibility into this project's detector internals, briefed only on the
mandate schema and the taxonomy's one-sentence definition; the authoring
process never read `detect/`, `features/`, `eval/`, or the three existing
attack generator files. Its output was independently re-verified against the
project's real pinned environment (not trusted on its own self-report)
before being used for anything: 14/14 tests passed, ruff and mypy clean,
both helper functions it called confirmed to be real project functions, and
both files were grepped for any leak of detector-internal terms.

Five sub-variants were designed, each holding every field but one fixed to a
real, legitimately-issued parent mandate's own values:

- `budget_escalation` -- a chained child declares a ceiling multiples of the
  parent's own.
- `breadth_escalation` -- a chained child reaches merchant/item categories the
  parent never covered.
- `temporal_outlive` -- a chained child's validity survives the parent's own
  expiry.
- `unauthorized_subdelegation` -- a chained child is genuinely signed by a
  *different*, real, registered agent than the parent's holder -- a
  confused-deputy pattern, not a forgery.
- `fanout_structuring` -- several individually-unremarkable sibling children
  from one parent, whose combined authorized value is a large multiple of
  anything the parent alone was sized for.

The held-out corpus is built by `generator/attacks/held_out.py`, a module the
training/tuning corpus builder (`generator/attacks/corpus.py`) never imports
-- checked by an AST-level test, not just documentation, so the "never
generated in the training path" guarantee cannot silently erode.

## The evaluation

`run_held_out_eval.py` fits the ordinary three-class pipeline at exactly the
parameters the committed Milestone B headline run used (`n_legitimate=20000,
seed=42`), producing a byte-identical model and threshold to the one already
reported. That fit is then applied, unmodified, to a held-out corpus
(`n_legitimate=20000, seed=90042, attack_base_rate=0.15`) containing only
legitimate traffic and the five mandate-chaining variants. Nothing is
retrained or recalibrated; only Layer 1/2 (which have no learned parameters)
and feature extraction run fresh, against the held-out corpus's own session
stream.

## Result

23,529 held-out sessions, 3,529 mandate-chaining attacks. (Revised once; see
the addendum at the end of this document for why these numbers differ from
the first version of this ADR, and why the finding itself did not change.)

| | Recall |
|---|---|
| In-distribution ensemble recall (Milestone B test block, for reference) | 99.76% |
| Held-out rules-only (Layer 1+2) recall | 0.00% |
| Held-out ensemble recall | 0.00% |
| Degradation | 99.76 points |

Per variant (rules-only -> ensemble):

| Variant | n | Recall |
|---|---|---|
| `budget_escalation` | 456 | 0.00% -> 0.00% |
| `unauthorized_subdelegation` | 424 | 0.00% -> 0.00% |
| `temporal_outlive` | 462 | 0.00% -> 0.00% |
| `breadth_escalation` | 439 | 0.00% -> 0.00% |
| `fanout_structuring` | 1748 | 0.00% -> 0.00% |

Of the 3,529 sessions the ensemble missed, **every single one** scored below
half the operating threshold -- zero fell into the "elevated but
insufficient" bucket. The model is not registering partial, below-threshold
suspicion on this class; each of these sessions is fully indistinguishable
from ordinary legitimate traffic in the feature space Layer 3 was given.

## Why, in plain terms

This is not a bug and not a surprising failure of the model to generalize
well. It is the direct, predictable consequence of what Layers 1-3 check.
Every generated chaining session is, by the generator's own design, a
scope-internally-consistent, genuinely-signed, normally-paced session -- the
only thing wrong is the *relationship between the child mandate's authority
and its parent's*, and nothing in this project currently inspects that
relationship:

- **Layer 1** (`mandate/verification.py`) checks a mandate's own signature,
  expiry, and budget. All five variants' child mandates pass every one of
  these checks on their own terms -- a freshly issued, correctly signed,
  unexpired, unspent mandate.
- **Layer 2** (`detect/scope.py`) checks a session against the mandate it
  presents. It does not, and structurally cannot as currently written, check
  a mandate's scope against its own `parent_mandate_id`'s scope -- that
  comparison does not exist anywhere in the rule set.
- **Layer 3** (`features/session.py`) computes thirteen features, none of
  which reference `parent_mandate_id` or compare one mandate's fields to
  another's. Every feature it does compute -- pacing, composition, amount
  relative to the *agent's own* prior mean -- looks exactly as it would for a
  legitimate session, because the generator was built precisely to keep those
  dimensions ordinary and isolate the escalation to the parent-child
  relationship alone.

The zero recall is a direct measurement of a real, previously undocumented
architectural gap: **nothing in this project reasons about mandate
delegation as a chain**, only about one mandate in isolation. Every one of
the five variants sits at exactly 0.00% recall under both rules-only and the
ensemble -- there is no partial, incidental overlap with any existing check
worth naming; the gap is total, not merely severe.

## Consequences -- and the constraint this ADR exists to enforce

This result is reported exactly as measured, including in the README, rather
than softened, re-run under different generator parameters, or quietly left
out of the headline evaluation section.

**No code in `detect/`, `features/`, or the generator's attack-side tuning
was changed in response to this result during the milestone that produced
it.** Doing so would have been tuning a detector against the exact test
meant to measure whether it generalizes -- the one thing this entire
methodology (fresh-context authorship, file-level import isolation,
evaluate-exactly-once) was built to prevent.

This finding belongs to Milestone D (the reasoning/audit layer) and
Milestone H (`EXCEPTIONS.md`) as real input: a plain-language explanation of
*why* a chaining session was allowed should be able to say, honestly, "no
layer in this system currently checks a mandate against its parent's
authority" -- which is a stronger, more credible answer to a panel question
than a system that either doesn't know it has this gap or hides it.

A Layer 2.5 (mandate-chain scope containment) has since been built as a
legitimate, separate design decision for a later milestone, with its own
reasoning recorded rather than as a reflexive same-session patch -- see
`docs/adr/0004-delegation-chain-containment.md` for its design, its own
once-only evaluation against this same held-out corpus, and what it does and
does not recover of the gap this ADR measures.

## Addendum: numbers revised once, 2026-08-28

The Result section above was corrected once, after Layer 2.5's development
surfaced a latent bug this evaluation's own numbers had never been checked
against: `generator/attacks/held_out.py` passed the identical `seed` value to
both `generate_legitimate_sessions` and `generate_mandate_chaining_attacks`,
unlike `generator/attacks/corpus.py`'s three attack generators, which
deliberately offset their seeds from the legitimate generator's own for
exactly this reason. Two independently constructed
`np.random.default_rng(seed)` streams from an identical seed are the same
deterministic function of draw position, and across a full corpus generation
(tens of thousands of draws in each stream) enough draw positions land in
alignment to produce genuine `mandate_id` collisions between an unrelated
legitimate mandate and a chaining-generated one -- confirmed directly (about
a dozen colliding IDs in a moderate test corpus, not a one-in-a-trillion
coincidence).

This was invisible to every consumer of this corpus before Layer 2.5,
including this ADR's own first measurement: Layers 1-3, and
`eval/held_out_evaluation.py` itself, only ever resolve a mandate by
*session*, never by ID, so a colliding ID never caused a session to be scored
against the wrong mandate. It became visible only once containment needed to
resolve an *ancestor* mandate by ID for the first time -- and, on the small
number of sessions it affected, it was producing an artificially nonzero
rules-only recall on `temporal_outlive`, `breadth_escalation`, and
`fanout_structuring` by incidentally routing a session's scope check against
the wrong mandate's content.

The fix (`generator/attacks/held_out.py::SEED_OFFSET_CHAINING`) is a one-line,
purely mechanical change -- it offsets an internal seed value and touches no
attack-generation logic, no generator configuration parameter, and nothing in
`detect/` or `features/`. It is not a reaction to this ADR's recall number in
the sense the standing constraint above prohibits: it does not make any
attack easier or harder to generate or to catch. It does change the held-out
corpus's exact realization for a given seed, which is why the specific counts
and percentages in the Result section above differ from this ADR's original
version. **The finding itself is unchanged, and is now stated more starkly
than before:** every one of the five variants sits at exactly 0.00% recall,
where the original (bug-affected) measurement showed a few variants with a
small, spurious nonzero recall that this addendum's own root-cause account
shows was never real signal. Containment's own store
(`containment/store.py::build_store_from_signed_mandates`) additionally fails
closed on any ID that still resolves to conflicting content, as defense in
depth independent of this fix -- see `docs/adr/0004`.
