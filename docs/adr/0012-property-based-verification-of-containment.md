# ADR 0012: Property-based verification of containment

## Status

Accepted. Built and tested; a real bug shape demonstrated and confirmed caught.

## Context

Milestone P proved eight safety properties about the deterministic layers' decision logic exhaustively with Z3, including two about Layer 2.5 (delegated scope only attenuates; a sibling group's committed total never exceeds its parent's cap). Both proofs are genuinely exhaustive over their encoded space — but both encode `containment/engine.py::enforce_containment` as a **pure, stateless function** and, for the sibling-cap property specifically, unroll `containment/gate.py::ContainmentGate`'s real recurrence for a **fixed-size group of exactly `FANOUT_SIBLING_COUNT` (4) siblings**, decided in a fixed symbolic order. Neither proof ever runs `ContainmentGate` itself: the class that actually holds a per-parent ledger in a `dict`, updates it after every call, and is meant to behave correctly across an arbitrarily long, arbitrarily shaped stream of real mandates over a real service's lifetime. This milestone closes that specific gap with Hypothesis-driven, generative testing of the real, stateful class.

## Design

### What Z3 proves vs. what this suite proves — stated plainly, as the brief asks

Z3 answers: "for any single call to `enforce_containment`, with any values in the bounded field space, does the pure function return the correct verdict." That is unconditionally the stronger guarantee for the question it answers — exhaustive over a well-defined space, not sampled.

This suite answers a different question Z3's proof structurally cannot: "does `ContainmentGate`'s own accumulation code — the `dict` it maintains, the update it performs after each accepted mandate, the sum it computes before the next — correctly implement the sibling-cap invariant across an arbitrary-length, arbitrary-shape, arbitrary-order sequence of real calls." A bug in that bookkeeping (a stale key, an off-by-one, forgetting to update on acceptance, using the wrong parent ID) would leave `enforce_containment` itself perfectly correct and Z3's proof of it still perfectly true, while the real system silently over-commits a parent's budget. Both are worth having for exactly this reason: one is the stronger guarantee for the pure function, the other is the only guarantee that exists at all for the stateful orchestration built on top of it.

### `@given` over a custom tree strategy, not `RuleBasedStateMachine`

The brief calls for "stateful strategies generating arbitrary well-formed delegation chains." A full Hypothesis `RuleBasedStateMachine` was considered and set aside in favor of a `@st.composite` strategy (`mandate_trees`) that generates a complete random tree up front — root, then a random number of children per node for a random number of levels — and feeds it through a real `ContainmentGate` in one pass. This is a lighter mechanism than a rule-based state machine, but it is still genuinely property-based (Hypothesis controls generation, shrinking, and example count) and it exercises the exact stateful code path a real service runs: `store.add` then `gate.decide`, in order, mandate by mandate. Given the deadline this milestone was built under, this was the pragmatic choice that still meets the brief's actual intent — testing the stateful ledger against varied, generated input — without the added complexity of modeling containment as a set of Hypothesis rules with their own invariant-checking machinery.

### Scoped to the amount dimension, deliberately

Every generated mandate shares the same category, item, window, and count defaults; only `max_amount` is drawn per node. Category/item/window/count subset-attenuation is exactly what Z3's property P5 already proves exhaustively over the *full* field space — re-testing the same dimension here would be redundant coverage, not complementary. Amount is where this project's own attack generator concentrates its delegation-chain variants (`generator/attacks/chaining.py`'s budget-escalation and fan-out-structuring shapes), and it is the dimension a stateful-ledger bug would actually manifest on. This is stated in the test module's own docstring, not left implicit.

### Two generated properties, one deterministic demonstration, one already-covered invariant

- `test_no_accepted_mandate_exceeds_its_declared_parents_ceiling` — "no descendant holds authority absent from its ancestors," for the amount dimension.
- `test_committed_siblings_never_exceed_parent_cap` — the real ledger invariant, checked after running a full generated tree through the gate.
- `test_cyclic_chain_is_never_accepted` — a dedicated ring-shaped strategy (2-4 mandates, each declaring the previous as parent) confirms every member of a genuine cycle is rejected with `CYCLE_DETECTED`, regardless of which member is decided.
- The brief's fourth invariant — "any chain with an unrecognized constraint is rejected" — is `assert_known_scope_fields`'s fail-closed schema-drift guard, already covered by `tests/test_containment_schema.py` (built for Milestone G) and deliberately not duplicated here.

### The demonstration: a real bug shape, shown caught, not just asserted

Per the brief ("if Hypothesis finds a counterexample, report it rather than weakening the property... record any counterexample found during development"), `test_broken_gate_that_never_accumulates_fails_the_sibling_cap_property` reintroduces a real, plausible bug — a `_BrokenGateNeverAccumulates` variant that always passes `committed_sibling_total=0`, as if every child were its parent's only one — against a small, fixed, hand-picked tree (two siblings, 700 and 600, under a 1000 cap) chosen so the bug is guaranteed to manifest rather than left to chance. The broken variant accepts both siblings (1300 committed against a 1000 cap); the real `ContainmentGate`, run against the identical tree in the same test, correctly rejects the second. This mirrors `formal/verify.py`'s own deliberate-bug-then-fixed demonstration for the Z3 side (a reversed `IsSubset`) and is kept as a permanent, re-runnable test for the same reason: proving the property is a real check, not a rubber stamp, is itself worth asserting forever, not just narrating once in an ADR.

No counterexample was found against the *real* `ContainmentGate` during development of the two generated properties above — both passed on the first run once the strategy itself was correctly constructed. The deliberate-bug test above is what demonstrates the properties would have caught a real regression had one existed.

### Dependency

`hypothesis==6.167.0` (pinned, current version confirmed live via `pip install --use-feature=truststore` against this machine's TLS-intercepting-proxy workaround, not assumed), added as a dev-only dependency (`pyproject.toml`, `requirements-lock.txt`) — this suite is test-only, nothing in the shipped system imports it.

## Consequences

**Per this project's standing constraint, `containment/gate.py`, `containment/engine.py`, `containment/chain.py`, `detect/`, `features/`, and the generator were untouched.** One new test module and one new dev dependency.

**What this buys.** A real, generative check on the one piece of Layer 2.5 Milestone P's formal proof cannot reach — the stateful ledger's own bookkeeping — plus a permanent, re-runnable demonstration that the check would catch a real regression of the shape it is designed for.

**What this does not buy.** This suite does not generate malformed or adversarial mandate content (invalid signatures, schema violations) — that is `mandate/verification.py`'s and pydantic's own job, already tested elsewhere. It also does not vary category/item/window/count, by design (see above); a bug specific to the ledger's interaction with one of those other dimensions, rather than amount, would not be caught here.
