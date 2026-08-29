# ADR 0005: Formal verification of the deterministic layers with Z3

## Status

Accepted. Eight properties defined, all eight proved, and the method's own
ability to catch a real transcription bug demonstrated directly. This
document is a record of a design decision and a measurement, not a proposal.

## Context

Every layer before this one has been tested, not proved. `tests/` exercises
Layer 1, 2, and 2.5's decision logic against hundreds of concrete cases --
hand-picked boundaries, generated corpora, adversarial constructions -- and
that discipline has already found real bugs (`mandate/signing.py::
canonical_bytes`'s frozenset-ordering bug, `containment/gate.py`'s
sibling-ledger double-counting bug). But a test suite, however thorough,
answers "does this pass for the cases we thought to write." It cannot answer
"is there any input, anywhere in the space this logic operates over, where
it fails" -- and for a system whose whole premise is catching exactly the
inputs nobody thought to write (see `docs/adr/0003`'s held-out result), that
gap matters.

An SMT solver answers the second question directly. Given a decision
function encoded as constraints and a property stated as a formula, Z3 either
proves the formula holds for *every* input in the encoded space, or returns a
concrete counterexample showing exactly where it fails. This layer encodes
Layers 1, 2, and 2.5's real decision logic -- not a simplified model of it --
and proves eight safety properties about it exhaustively.

**Deliberately, explicitly out of scope: Layer 3.** The behavioral model's
decision boundary is learned from data, not expressible in closed-form SMT
constraints, and encoding an approximation of it would prove something about
the approximation, not the model this project actually ships. Every property
below either concerns Layers 1, 2, and 2.5 alone, or treats Layer 3's
contribution as a free, entirely unconstrained boolean input -- a property
that holds for every possible value of that variable holds regardless of
what the real model would ever output for it.

**Also explicitly out of scope: this package never generates attack
payloads.** Its outputs -- proofs and counterexamples -- describe gaps in
this repository's own encoded policy model, not techniques against a real
payment system. A counterexample here is a statement like "if the merchant-
category subset check were reversed, a child claiming every category from a
parent claiming none would be accepted" -- a fact about this project's own
Z3 encoding, not an executable input any real system would accept.

## Design

### Encoding philosophy: bounded, not simplified

Every builder in `formal/model.py` is a direct, line-for-line transcription
of the real Python decision logic it names in its docstring --
`mandate.verification.verify_mandate`, `detect.scope.enforce_scope`,
`containment.engine.enforce_containment` (including
`containment.gate.ContainmentGate`'s sequential sibling-ledger algorithm),
and `detect.ensemble.ensemble_decide`'s combination rule. Nothing here is a
new or independent policy; it is the existing policy, restated in a form Z3
can reason about.

Two kinds of abstraction are used, both stated per field in `formal/model.py`
itself:

- **Free boolean inputs** for facts the encoding does not reason about
  further: whether a signature is cryptographically valid, whether a key is
  registered, whether Layer 3 flagged a session. Ed25519 math is not
  expressible as, nor faithfully approximable by, a bounded SMT domain; a
  property proved for every value of a free boolean holds regardless of what
  the real, un-encoded check would ever decide.
- **Bounded numeric and finite-set domains** for every comparison the real
  logic actually performs: amounts (bounded to 1-100,000,000₹ in paise, far
  beyond any realistic mandate), timestamps (abstract bounded integer
  "ticks" -- only relative order is ever compared, never calendar
  arithmetic, inside the decision logic being verified), transaction counts,
  delegation depth, and category/merchant membership (abstract `EnumSort`
  domains sized to match `generator/config.py`'s real catalog -- 5 merchant
  categories, 6 item categories, 6 merchants -- rather than picked
  arbitrarily). Bounded rather than left as Z3's default unbounded integer
  sort: an unbounded domain can hit a real SMT performance cliff on some
  constraint shapes; every domain
  here is bounded to a value comfortably beyond anything the real system
  would see, keeping every check both exhaustive within the bound and fast
  (the full eight-property suite checks in well under a second).

The category/merchant abstraction deserves its own sentence: `detect/scope.
py` and `containment/engine.py` never special-case a specific category
name -- both are generic set-membership and subset logic over whatever
catalog `generator/config.py` defines. A property proved for every subset of
an N-element abstract domain therefore holds for every subset of any real
domain of size N or smaller, by direct substitution, because the decision
logic being verified never inspects *which* element it received.

### The eight properties

| # | Name | Layer | Statement |
|---|---|---|---|
| P1 | `amount_ceiling_no_tolerance` | Layer 2 | An over-ceiling amount always denies scope, regardless of every other field. |
| P2 | `merchant_allowlist_cannot_be_bypassed` | Layer 2 | A restricted merchant allowlist always denies an unlisted merchant, regardless of every other field. |
| P3 | `expired_mandate_never_verifies` | Layer 1 | A mandate past its own `expires_at` never verifies, regardless of signature validity, key registration, or budget. |
| P4 | `budget_exhausted_mandate_never_verifies` | Layer 1 | A mandate at or past its usage budget never verifies, regardless of signature validity, key registration, or the time window. |
| P5 | `delegated_scope_only_attenuates` | Layer 2.5 | Containment's acceptance implies every scope dimension (ceiling, categories, merchant allowlist, window, transaction count) is no broader than the parent's. |
| P6 | `no_accepted_chain_exceeds_depth_bound` | Layer 2.5 | Containment's acceptance implies the resolved delegation depth is within `MAX_DELEGATION_DEPTH`. |
| P7 | `sibling_committed_total_never_exceeds_parent_cap` | Layer 2.5 | For any group of siblings decided by the real sequential ledger algorithm, the sum of every accepted sibling's cap never exceeds the parent's, over every possible combination of amounts in the bounded space. |
| P8 | `no_session_both_allowed_and_flagged_for_hold` | Combination logic | No session can be simultaneously auto-approved and flagged for escalation, for any combination of the deterministic layers' verdicts and any value Layer 3's score might take. |

P1-P2 come from `detect/scope.py`; P3-P4 from `mandate/verification.py`;
P5-P7 from `containment/engine.py` and `containment/gate.py`; P8 from
`detect/ensemble.py` and `eval/containment_evaluation.py`'s composition,
with Layer 3 abstracted per the Context section above. P1, P3, P6, and P8
are the single most safety-critical check for each layer and the
combination logic on top of them; P2, P4, P5, and P7 were added to give
each of the three deterministic layers real coverage rather than one
property apiece.

**On why several of these read as "prove the specification implies its own
conjunct."** Properties like P5, P6, and P8 are, in a strict sense, implied
by construction: `contained()` is *defined* as a conjunction that includes
the scope-subset check, so "containment's acceptance implies the scope-
subset check holds" is analytically true once the definitions are fixed.
This is not a weakness particular to this exercise -- it is the normal shape
of formally verifying a conjunctive specification against a stated
invariant. The value is not philosophical depth; it is exhaustive protection
against *mistranscription*: a bug where the encoded conjunction does not
actually say what its docstring claims (an accidental `OR` where an `AND`
belongs, a reversed comparison, a swapped operand) breaks exactly these
"obvious" implications, and Z3 catches it with a concrete counterexample
where a human skim of the code would not. The demonstration below is that
claim, exercised for real, not asserted.

### Evaluation protocol

Each property is checked by asserting its *negation* and requiring `unsat`
(`formal/verify.py::verify_property`). If the negation were satisfiable, the
satisfying assignment would be a concrete counterexample to the property;
`unsat` means none exists anywhere in the bounded encoded space. A result of
`unknown` -- which should not occur, since this encoding uses only linear
integer arithmetic and finite-set theory over bounded domains, both fully
decidable -- raises loudly rather than being treated as either a proof or a
violation, matching this project's standing "fail loudly, never silently
pass" rule.

## Result

`python run_verify_policy_properties.py`: **8/8 properties proved.** Every
property returned `unsat` on its negation, on the first real run, with no
retuning of the encoding needed. Runtime is under a second for the full
suite -- the bounded, faithful-to-real-catalog-size domains keep the search
space small enough that Z3's decision procedures for linear arithmetic and
finite sets resolve it essentially instantly.

## The demonstration: a real bug, a real counterexample, a real fix

Kept as permanent, re-runnable
tests (`tests/test_formal_verify.py::test_deliberately_broken_subset_check_
yields_a_real_counterexample` and `::test_the_same_check_fixed_is_proved`)
rather than a one-off script -- so this demonstration cannot silently bit-rot
and the transcript below is reproducible by anyone who runs the suite, not
only quoted here.

**The bug.** `containment/engine.py::_check_scope_subset` contains three
near-identical subset checks in a row (merchant categories, item categories,
merchant IDs), differing only in which field they read -- exactly the shape
that invites a copy-paste mistake. The deliberately broken variant reverses
one direction:

```python
# Real (correct): child's categories must fit inside the parent's.
z3.IsSubset(v.child_merchant_categories, v.parent_merchant_categories)

# Broken (deliberately, for this demonstration only): reversed.
z3.IsSubset(v.parent_merchant_categories, v.child_merchant_categories)
```

**Step 1: Z3 catches it, with a concrete counterexample.**

```
[VIOLATED (sat -- counterexample found)] delegated_scope_only_attenuates_BROKEN
    layer: Layer 2.5 (delegation-chain containment) -- DELIBERATELY BROKEN for this demonstration
    reversed merchant-category IsSubset direction: parent subset of child, not child subset of parent
    counterexample:
      demo_child_item_categories = K(ItemCategory, False)
      demo_child_max_amount = 0
      demo_child_max_transaction_count = 1
      demo_child_merchant_categories = K(MerchantCategory, True)
      demo_child_merchant_ids = K(MerchantId, False)
      demo_child_valid_from = 0
      demo_child_valid_until = 1
      demo_parent_has_merchant_restriction = True
      demo_parent_item_categories = K(ItemCategory, True)
      demo_parent_max_amount = 0
      demo_parent_max_transaction_count = 0
      demo_parent_merchant_categories = K(MerchantCategory, False)
      demo_parent_merchant_ids = K(MerchantId, True)
      demo_parent_valid_from = 1
      demo_parent_valid_until = 0

0/1 properties proved.
```

`K(MerchantCategory, True)` and `K(MerchantCategory, False)` are Z3's own
notation for a constant array -- "true for every element" and "false for
every element," i.e. the universal set and the empty set. Z3 did not find an
edge case; it found the *most extreme possible* counterexample on its own:
a child claiming the entire merchant-category universe
(`demo_child_merchant_categories = K(MerchantCategory, True)`), delegated
from a parent claiming none at all
(`demo_parent_merchant_categories = K(MerchantCategory, False)`), accepted
by the broken check because the reversed direction reduces to "is the empty
set a subset of the child's set" -- trivially true for any child, which is
exactly why the bug is a real one: it silently deletes the merchant-category
containment guarantee entirely, for every input, not just some.

**Step 2: fixed, and proved again.**

```
[PROVED (unsat)] delegated_scope_only_attenuates_FIXED
    layer: Layer 2.5 (delegation-chain containment)
    corrected: child merchant categories must be a subset of the parent's

1/1 properties proved.
```

Reverting the one line to the real, shipped direction (`IsSubset(v.child_
merchant_categories, v.parent_merchant_categories)`) returns the property to
`unsat` -- proved, exhaustively, over the same bounded space that found the
counterexample a moment before.

## Scope boundary: what this proves, and what it does not

Stated explicitly, so the guarantee above is not overread:

**Proved, exhaustively, over the bounded encoded space:** the eight
properties above, for Layers 1, 2, and 2.5's *decision logic* as currently
written -- the boolean/comparison structure of `verify_mandate`,
`enforce_scope`, `enforce_containment`, and `ContainmentGate`'s sequential
ledger, and the combination rule across all three plus an abstracted Layer
3. This is a real, exhaustive guarantee within the stated bounds: not "these
cases pass," but "no case in this space fails."

**Not proved, and not claimed:**

- **Layer 3's actual behavior.** Entirely out of scope by design (see
  Context above). `escalated` is a free variable; nothing here says
  anything about when the real model sets it.
- **Cryptographic correctness.** Signature validity and key registration are
  free boolean inputs. Ed25519's own correctness, and `mandate/signing.py`'s
  implementation of it, are unverified here -- they are tested, not proved,
  and formally verifying an Ed25519 implementation is a different, much
  larger undertaking than this document's scope.
- **The ancestor-chain *walk* itself.** `containment/chain.py::resolve_
  ancestor_chain`'s graph traversal (following `parent_mandate_id` pointers,
  detecting a cycle by tracking visited IDs) is not re-encoded in SMT; it is
  ordinary Python graph traversal, not a policy decision. What is verified
  is the *bound being checked against the walk's result* (P6): if the walk
  reports a depth beyond `MAX_DELEGATION_DEPTH`, containment must not
  accept. Whether the walk itself correctly computes that depth is covered
  by `tests/test_containment_chain.py`, not by this ADR.
- **Values outside the declared bounds.** Every numeric domain is bounded
  (see Design above). A property is proved exhaustively *within* that
  bound, not for literally every mathematical integer. The bounds were
  chosen to comfortably exceed anything the real system would ever see, not
  chosen to make a property easier to prove.
- **The real system's Python implementation, byte for byte.** This encoding
  is a faithful transcription, checked by direct comparison against the
  source it names, but it is not the same code running under a different
  interpreter -- a bug introduced into `detect/scope.py` after this ADR was
  written would not automatically be caught here unless the corresponding
  encoding in `formal/model.py` is updated to match. Keeping the two in
  sync is a discipline this project chooses to maintain, not a guarantee
  the tooling enforces automatically.

## Consequences

**Per the standing constraint this project has held since the held-out
evaluation (`docs/adr/0003`), this layer did not touch `detect/`,
`features/`, `containment/`, or the generator.** `formal/` is a new,
read-only-with-respect-to-those-modules
package: it encodes their logic for verification purposes and changes
nothing about how they run. The one dependency added
(`z3-solver==5.1.0.0`, pinned in `pyproject.toml` and
`requirements-lock.txt`) is used exclusively inside `formal/` and the
`run_verify_policy_properties.py` entry point.

**Keeping the encoding synchronized with the real code is future work, not
solved here.** If `detect/scope.py`, `mandate/verification.py`, or
`containment/engine.py` change, `formal/model.py`'s corresponding builder
must be updated by hand to match, or this ADR's proofs describe logic the
system no longer runs. No automated check currently enforces that the two
stay in sync -- stated here as a known limitation, matching this project's
own evaluation-honesty discipline, not left implicit.
