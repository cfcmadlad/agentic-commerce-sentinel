# ADR 0008: Counterfactual explanations

## Status

Accepted. Built and tested; Layers 1 and 2 wired into the live API service,
Layer 2.5 kept at library level, Layer 3 wired into the live service.

## Context

The reasoning layer (`reasoning/narrate.py`) and its SHAP attribution
(`detect/attribution.py`) already answer "why was this session blocked" --
which rule fired, or which behavioral features pushed the score up. Neither
answers a different, complementary question a reviewer or an agent operator
actually asks next: "what would have needed to be true for this to be
allowed". That is a counterfactual explanation, and it is the last item in
this project's Tier 2 scope, depending on the Z3 encoding
(`formal/model.py`) Milestone P already built.

## Design

### Two methods, not one, because the layers admit different guarantees

`counterfactual/deterministic.py` covers Layers 1 (`mandate.verification`),
2 (`detect.scope`), and 2.5 (`containment.engine`). `counterfactual/
behavioral.py` covers Layer 3. They are split into separate modules, not
unified behind one interface, because they are not the same kind of claim:

- The deterministic layers' rules are independent conjuncts -- Layer 1's six
  checks, Layer 2's ten, Layer 2.5's nine each depend on their own field(s),
  and no two named failure reasons in `VerificationFailureReason`,
  `ScopeViolationReason`, or `ContainmentViolationReason` share a field. That
  makes "edit exactly the currently-failing fields to their own boundary"
  provably the *minimal* edit: no smaller edit can work (every failing
  clause must change, by definition), and nothing outside the failing set
  needs to move (every clause it belongs to already holds). This is a real,
  checkable guarantee, and it is checked: every suggested edit is verified
  satisfiable against the exact `mandate_verified`/`in_scope`/`contained` Z3
  predicates `formal/model.py` built for Milestone P's exhaustive proofs --
  not a second, independently hand-written copy of "is this valid" that
  could quietly drift from the real rule. If a future change to
  `formal/model.py`, or a mistake in this module's own field-to-clause
  mapping, ever produces an edit the real predicate rejects, `_verify`
  returns False and the public function raises `AssertionError` before
  returning a wrong answer.
- Layer 3 has no such closed form to consult -- `formal/__init__.py`
  already states why the learned model is never Z3-encoded. There is
  nothing to prove an edit against except the model itself, so
  `counterfactual/behavioral.py` searches it directly: bisection against
  `BehavioralModel.predict_proba`, one feature at a time, prioritized by
  that session's own SHAP attribution. This is explicitly a heuristic, not
  an exhaustive search of the model's decision surface, and the module's
  own docstring and every explanation string it produces say so -- it can
  report "no counterfactual found" when a smaller one may exist outside the
  features or search bounds it tried, but it never reports an edit that was
  not actually verified against the real model's own output.

### Why the "solver" role is verification, not search, for Layers 1/2/2.5

An earlier design considered using Z3's `Optimize` to *search* for each
boundary value. That turned out to be unnecessary: every boundary this
project's real rules produce is already an explicit, already-known
constant -- a mandate's own ceiling, its own window edge, its own
transaction budget, a parent's own category grant. There is nothing to
discover. What Z3 is used for instead is *confirming* the edited assignment
against the real predicate -- an independent correctness oracle over the
exact encoding Milestone P already proved properties about, catching a
mistake in this module's own field-to-clause mapping rather than trusting
it blindly. This is a smaller claim than "the solver found this," and a
more honest one: it earns the "derived from the solver, not hand-written"
standard the original brief asked for by construction, not by search cost.

### A wrong assumption caught before it shipped: no fixed direction for Layer 3

The first cut of `counterfactual/behavioral.py` assumed every suspicious
feature should be reduced toward zero. That assumption is actively wrong
for at least one real feature this project ships:
`hours_since_agent_last_session` is suspicious when *low* (rapid reuse), so
the fix there is to *increase* it, not decrease it. Rather than hand-encode
a direction per feature -- which would mean guessing, feature by feature,
which side of its real value is "more legitimate," and getting it wrong
silently -- the search bisects toward whichever side of a feature's real
value the model's own `predict_proba` output actually moves the score down,
discovered empirically per call, never assumed from a feature's name or its
SHAP sign.

### Excluded from the Layer 3 search entirely: calendar features and flags

`hour_of_day` and `day_of_week` are never edited, regardless of how strongly
SHAP ranks them for a given session. This project has a standing rule
against day/calendar framing in anything that ships, and "the score would
drop if this had happened at a different hour" is exactly that framing,
model behavior notwithstanding. `has_catalog_browse`, `has_cart_build`,
`has_mandate_presented`, and `presented_a_mandate` are boolean flags, tested
only as a single flip (0 to 1 or the reverse) -- bisecting a fractional
value between them would suggest an edit ("`has_catalog_browse` = 0.42")
that does not correspond to any real session.

### Scope boundary: Layer 2.5 is library-level, not live-wired

`service/main.py` calls only Layers 1, 2, and 3 (`verify_mandate`,
`enforce_scope`, the behavioral model) -- containment (Layer 2.5) is not
part of the live `/sessions/decide` path at all, and adding it there is a
separate, larger decision this milestone does not make reactively.
`containment_counterfactual` is therefore a tested library function,
exercised directly by `tests/test_counterfactual_deterministic.py` and
available to any caller with a resolved delegation chain (for example a
future audit tool reading `eval/containment_evaluation.py`'s corpus), not
surfaced through the API or the dashboard. A chain-topology violation (a
cycle, an unresolvable ancestor, the depth bound exceeded) has no
field-level fix at all regardless -- reported honestly as infeasible, not
invented.

### Set-valued edits: trim to the intersection, not replace wholesale

When a delegated mandate's category set is not a subset of its parent's
(`SCOPE_MERCHANT_CATEGORY_NOT_SUBSET` and the item/merchant-ID equivalents),
the minimal edit is the *intersection* of the child's requested set and the
parent's allowed set -- keeping everything the child already asked for that
the parent also allows, dropping only what exceeded it. If that
intersection is empty, there is no minimal trim to suggest -- the child
would need an entirely different grant, not a smaller one -- and this is
reported as infeasible (`_no_overlap_counterfactual`) rather than silently
suggesting the parent's full set as if that were still "the child's own
request, trimmed."

### Layer 3 was a deliberate stop-and-ask, not an assumed yes

A minimal-edit counterfactual for Layer 3 is, by construction, a minimal
adversarial perturbation -- the standard technique for constructing an
evasion attack against the one layer specifically built to catch attacks
that already look legitimate to Layers 1 and 2. That is a meaningfully
different, more actionable disclosure than the per-session SHAP attribution
already shipped, and this project's standing rule is to stop and ask before
building anything that could read as attack-capability generation. Asked
directly, the answer was to build it as specified. The scope narrowing that
follows -- direction discovered empirically rather than assumed, calendar
features excluded, the method's heuristic (non-exhaustive) nature stated in
every explanation string it produces -- is this module's own attempt to
keep that yes honestly bounded, not a reason to skip asking.

## What is surfaced, and where

`reasoning.schema.Counterfactual`/`CounterfactualEdit` are new, plain
(non-`detect`, non-`counterfactual`) types added to `AuditRecord` --
following the same discipline `NarrationInput`/`Narration` already
established: a value copy at construction time, never a live reference to
either `counterfactual.deterministic.Counterfactual` or
`counterfactual.behavioral.BehavioralCounterfactual`, so nothing in this
package can be threaded back into a decision. **As originally shipped**,
`service/main.py::decide` computed at most one counterfactual per session:
the deterministic one when `SOURCE_RULES` blocked it (verification's, if
verification itself failed; otherwise scope's), the behavioral one when
`SOURCE_BEHAVIORAL` did, and none for an allowed session -- returned from
`POST /sessions/decide` and persisted on the audit record, readable via
`GET /audit/{session_id}`, both labelled with `layer`. **Revised, see the
addendum below: the behavioral half is no longer wired into `decide()` at
all.**

## A real forward-compatibility bug caught before it shipped

Adding `counterfactual` to `AuditRecord` and always serializing it (even as
an explicit `null`) would have broken `reasoning.audit_chain.verify_chain`
for every audit-log entry written before this change: `record_hash` is
computed by hashing the canonical JSON of the record, and an entry appended
under the old schema was hashed with no `"counterfactual"` key present at
all -- adding that key, even as `null`, on re-serialization changes the
canonical bytes and makes every pre-existing entry's stored hash appear not
to match, i.e. every one of them would report as tampered. This is the same
class of forward-compatibility question ADR 0007 already hit once (a stray
old-format audit file crashing `_last_hash`), caught here before it shipped
rather than after: `_record_to_json_dict` now omits the `"counterfactual"`
key entirely when the value is `None`, which is exactly what a pre-existing
entry (implicitly `counterfactual=None`, since the field did not exist when
it was written) already looked like on disk. `tests/test_audit_log.py::
test_absent_counterfactual_is_omitted_from_the_stored_line` and
`tests/test_audit_chain.py::
test_chain_stays_intact_across_entries_written_with_and_without_a_counterfactual`
lock this in directly, the latter mixing both schema shapes in one chain --
the realistic case for any log that already existed before this change.

## Consequences

**Per this project's standing constraint, nothing in `detect/`, `features/`,
`mandate/`, `containment/`, or the generator was touched.** This is a new
top-level package (`counterfactual/`) consuming `formal.model`'s exported
predicates and variable builders, plus additive fields on `reasoning/
schema.py`/`reasoning/audit_log.py` and new branches in `service/main.py` --
no existing decision logic changed.

**What this buys.** For a session blocked by Layers 1 or 2 (the only
layers live in the API today), a reviewer gets an exact, solver-verified
statement of what would need to change, not a guess. For a session flagged
by Layer 3, a reviewer gets a documented-heuristic estimate, clearly
labelled as such, of what the model's own decision boundary implies for
that specific session.

**What this does not buy.** Layer 2.5's counterfactual is not reachable
through the live service or the dashboard -- only through direct library
use -- until containment itself is wired into `/sessions/decide`, a
separate decision. The Layer 3 search is bounded (a fixed number of
top-contributing features, a fixed search span per feature) and heuristic;
"no counterfactual found" is an honest report of this search's limits, not
a proof that none exists.

## Addendum: behavioral counterfactual pulled out of the live HTTP path, 2026-09-02

On review, attaching a real Layer 3 counterfactual to `POST /sessions
/decide`'s response was a genuine, if narrow, offense-capability leak: the
response goes to the same caller whose session was just blocked, and the
counterfactual's whole content is "change feature X from its real value to
this suggested value to flip your own verdict to allowed" -- a live
evasion recipe for that caller's own next attempt, not merely an
explanation for a separate human reviewer. `GET /audit/{session_id}` is
equally unauthenticated and would have re-exposed the same thing. The
deterministic counterfactual carries no equivalent risk (it only restates
what the presented mandate's own scope already says, nothing the caller
could not already work out by reading Layer 2's comparison directly), so
it is unaffected.

Fix: `service/main.py::decide()` no longer calls `counterfactual.
behavioral.behavioral_counterfactual` at all -- the `SOURCE_BEHAVIORAL`
branch that used to compute and attach it is removed, along with the
now-dead `_behavioral_to_schema` conversion helper. A behaviorally-blocked
session's `counterfactual` field is simply `None`, matching what an
allowed session already looked like. The library function itself is
untouched and still fully tested directly
(`tests/test_counterfactual_behavioral.py`), for a future internal-only
reviewer tool to call -- gated to library-only use, per this project's own
defense-only standard, not exposed over HTTP anywhere today. See
`counterfactual/behavioral.py`'s own module docstring for the fuller
"why this isn't offense-capable as a technique" reasoning, which stands
regardless of this wiring decision.
