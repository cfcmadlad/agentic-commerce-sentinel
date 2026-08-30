"""Property-based tests for Layer 2.5's real, stateful orchestration code.

Milestone P's Z3 encoding (`formal/model.py`, `formal/properties.py`)
already proves the deterministic decision *functions* -- `enforce_containment`
and one fixed-size (`FANOUT_SIBLING_COUNT`) unrolling of the sibling-cap
recurrence -- exhaustively, for every input in a bounded space. What it does
not, and by design cannot, cover is `containment/gate.py::ContainmentGate`
itself: the real, stateful, arbitrary-length loop that calls those pure
functions in sequence and accumulates a running per-parent ledger across an
unbounded stream of mandates. Z3's own encoding treats `committed_sibling_
total` as a free input handed to it, never as something *computed* by real
Python accumulation code -- an off-by-one, a double-count, or a stale-key
bug in that accumulation would not be caught by the formal proof at all,
since the proof never runs that code.

This is exactly the class of bug property-based, generative testing is
suited to: run `ContainmentGate` for real, many times, over randomly
generated trees of mandates (varying shape, varying amounts, varying
order), and assert the ledger invariants hold regardless of what was
generated. Where Milestone P proves "this function is correct for every
input," this proves "this stateful loop maintains its invariant no matter
what stream of real calls it receives" -- a different, complementary
guarantee, not a duplicate of the same one. See `docs/adr/0012-property-
based-verification-of-containment.md` for the full comparison and a
counterexample this suite actually found during development.

Scoped to the amount dimension deliberately, not every `MandateScope`
field: category/item/window/count subset-attenuation is exactly what
Milestone P's Z3 proof already covers exhaustively over the full field
space (property P5), and amount is where this project's own real attack
generator concentrates its delegation-chain variants
(`generator/attacks/chaining.py`'s budget-escalation and fan-out-structuring
shapes) -- the dimension where a real stateful-ledger bug would actually
matter. Every mandate in a generated chain shares the same category/item/
window/count defaults, so those dimensions trivially satisfy subset
attenuation by construction and are not the point of this suite.

The fourth invariant the brief names -- "any chain with an unrecognized
constraint is rejected" -- is `containment.schema.assert_known_scope_fields`'s
fail-closed schema-drift guard, already covered by
`tests/test_containment_schema.py` (built for Milestone G) and not
duplicated here.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID, uuid4

from hypothesis import given, settings
from hypothesis import strategies as st

from containment.chain import resolve_ancestor_chain
from containment.engine import enforce_containment
from containment.gate import ContainmentGate
from containment.schema import ContainmentResult, ContainmentViolationReason
from containment.store import MandateChainStore, MutableMandateChainStore
from mandate.schema import Mandate
from mandate.signing import generate_keypair
from tests.factories import build_mandate, build_scope

# One shared key for every generated mandate in this module: containment
# logic operates on `Mandate` content, never on a `SignedMandate`'s
# signature, and generating a fresh Ed25519 key per Hypothesis example
# (there can be hundreds) would be pure, irrelevant overhead.
_PRIVATE_KEY, _ = generate_keypair()

_AMOUNTS = st.decimals(
    min_value=Decimal("1"), max_value=Decimal("100000"), places=2, allow_nan=False, allow_infinity=False
)

MAX_DEPTH = 3
MAX_CHILDREN_PER_NODE = 2
MAX_EXAMPLES = 150


@st.composite
def mandate_trees(draw: st.DrawFn) -> list[Mandate]:
    """Generates a root mandate plus a random tree of delegated children.

    Amounts are drawn independently at every node -- deliberately not
    constrained to attenuate -- so a generated tree contains a realistic
    mix of mandates `ContainmentGate` will accept and reject, exercising
    both paths through the real ledger update logic. Returned in
    parent-before-child (breadth-first) order, so processing the list in
    order always resolves each child's parent from mandates already known.

    Args:
        draw: Hypothesis's draw function.

    Returns:
        The generated tree, root first.
    """
    root = build_mandate(_PRIVATE_KEY, scope=build_scope(max_amount=draw(_AMOUNTS)))
    tree = [root]
    frontier = [root]
    depth = draw(st.integers(min_value=1, max_value=MAX_DEPTH))
    for _level in range(depth):
        next_frontier: list[Mandate] = []
        for parent in frontier:
            n_children = draw(st.integers(min_value=0, max_value=MAX_CHILDREN_PER_NODE))
            for _ in range(n_children):
                child = build_mandate(
                    _PRIVATE_KEY,
                    parent_mandate_id=parent.mandate_id,
                    scope=build_scope(max_amount=draw(_AMOUNTS)),
                )
                tree.append(child)
                next_frontier.append(child)
        frontier = next_frontier
    return tree


@given(mandate_trees())
@settings(max_examples=MAX_EXAMPLES)
def test_no_accepted_mandate_exceeds_its_declared_parents_ceiling(tree: list[Mandate]) -> None:
    """Every mandate ContainmentGate accepts must have a ceiling no larger than its parent's.

    "No descendant holds authority absent from its ancestors," restated for
    the amount dimension this suite focuses on (see module docstring).
    """
    store = MutableMandateChainStore()
    gate = ContainmentGate(store)
    by_id = {m.mandate_id: m for m in tree}

    for mandate in tree:
        store.add(mandate)
        result = gate.decide(mandate)
        if result.in_bounds and mandate.parent_mandate_id is not None:
            parent = by_id[mandate.parent_mandate_id]
            assert mandate.scope.max_amount <= parent.scope.max_amount, (
                f"gate accepted {mandate.mandate_id} with ceiling {mandate.scope.max_amount} "
                f"under parent {parent.mandate_id} whose own ceiling is only {parent.scope.max_amount}"
            )


@given(mandate_trees())
@settings(max_examples=MAX_EXAMPLES)
def test_committed_siblings_never_exceed_parent_cap(tree: list[Mandate]) -> None:
    """The sum of every accepted child's ceiling, per parent, must never exceed that parent's own ceiling.

    Exercises `ContainmentGate`'s real running ledger (`_committed_by_parent`)
    across an arbitrary-shaped, arbitrary-order tree -- the stateful
    accumulation Z3's own proof of the sibling-cap rule (P7) does not run,
    since P7 checks the recurrence unrolled for a fixed-size group, not this
    class's actual dict-based bookkeeping.
    """
    store = MutableMandateChainStore()
    gate = ContainmentGate(store)
    by_id = {m.mandate_id: m for m in tree}
    committed: dict[UUID, Decimal] = {}

    for mandate in tree:
        store.add(mandate)
        result = gate.decide(mandate)
        if result.in_bounds and mandate.parent_mandate_id is not None:
            committed[mandate.parent_mandate_id] = committed.get(mandate.parent_mandate_id, Decimal(0)) + (
                mandate.scope.max_amount
            )

    for parent_id, total_committed in committed.items():
        parent = by_id[parent_id]
        assert total_committed <= parent.scope.max_amount, (
            f"parent {parent_id} (ceiling {parent.scope.max_amount}) has {total_committed} "
            f"committed across its accepted children -- over its own cap"
        )


@st.composite
def cyclic_chains(draw: st.DrawFn) -> list[Mandate]:
    """Generates a ring of 2-4 mandates, each declaring the previous as its parent.

    A genuine cycle: walking `parent_mandate_id` from any member eventually
    revisits a mandate already seen, wrapping all the way around.

    Args:
        draw: Hypothesis's draw function.

    Returns:
        The ring, in an arbitrary but fixed order.
    """
    length = draw(st.integers(min_value=2, max_value=4))
    ids = [uuid4() for _ in range(length)]
    return [
        build_mandate(
            _PRIVATE_KEY,
            mandate_id=ids[i],
            parent_mandate_id=ids[(i - 1) % length],
            scope=build_scope(max_amount=draw(_AMOUNTS)),
        )
        for i in range(length)
    ]


@given(cyclic_chains())
@settings(max_examples=50)
def test_cyclic_chain_is_never_accepted(ring: list[Mandate]) -> None:
    """No mandate in a genuine delegation cycle may ever be accepted by the gate."""
    store = MutableMandateChainStore()
    gate = ContainmentGate(store)
    for mandate in ring:
        store.add(mandate)

    for mandate in ring:
        result = gate.decide(mandate)
        assert not result.in_bounds
        assert ContainmentViolationReason.CYCLE_DETECTED in result.reasons


class _BrokenGateNeverAccumulates:
    """A deliberately reintroduced bug: forgets to track committed siblings at all.

    Exists solely to demonstrate `test_committed_siblings_never_exceed_
    parent_cap`'s property is a real check, not a rubber stamp -- the same
    demonstration `formal/verify.py`'s own tests make for the Z3 side with a
    deliberately reversed `IsSubset`. Never imported by
    `containment/gate.py` or anything real; this class always passes
    `committed_sibling_total=0`, as if every child were the only one its
    parent had ever delegated to.
    """

    def __init__(self, store: MandateChainStore) -> None:
        """Initializes the broken gate with its chain store.

        Args:
            store: Resolves a mandate by ID, for ancestor-chain walking.
        """
        self._store = store

    def decide(self, mandate: Mandate) -> ContainmentResult:
        """Decides one mandate, using the bug: committed_sibling_total is always zero.

        Args:
            mandate: The mandate to evaluate.

        Returns:
            The (wrong) verdict.
        """
        if mandate.parent_mandate_id is None:
            return ContainmentResult(mandate_id=mandate.mandate_id, in_bounds=True, reasons=())
        chain = resolve_ancestor_chain(mandate, self._store)
        return enforce_containment(mandate, chain, Decimal(0))  # BUG: real siblings never counted


def test_broken_gate_that_never_accumulates_fails_the_sibling_cap_property() -> None:
    """A gate that forgets to track committed siblings must violate the invariant above -- proving it is real.

    A small, fixed, hand-picked tree (not Hypothesis-generated) chosen so
    the bug is guaranteed to manifest: two siblings, 700 and 600, under a
    parent capped at 1000. The real `ContainmentGate` (see
    `test_committed_siblings_never_exceed_parent_cap`, which this exact
    shape is well within the space Hypothesis explores) correctly rejects
    the second sibling. This broken variant accepts both -- 1300 committed
    against a 1000 cap -- exactly the counterexample class Hypothesis would
    report if this bug were ever reintroduced into the real class.
    """
    parent = build_mandate(_PRIVATE_KEY, scope=build_scope(max_amount=Decimal("1000")))
    sibling_a = build_mandate(
        _PRIVATE_KEY, parent_mandate_id=parent.mandate_id, scope=build_scope(max_amount=Decimal("700"))
    )
    sibling_b = build_mandate(
        _PRIVATE_KEY, parent_mandate_id=parent.mandate_id, scope=build_scope(max_amount=Decimal("600"))
    )
    store = MutableMandateChainStore()
    for mandate in (parent, sibling_a, sibling_b):
        store.add(mandate)

    broken_gate = _BrokenGateNeverAccumulates(store)
    result_a = broken_gate.decide(sibling_a)
    result_b = broken_gate.decide(sibling_b)

    assert result_a.in_bounds
    assert result_b.in_bounds  # the bug: both accepted, 700 + 600 = 1300 > parent's 1000 cap

    real_store = MutableMandateChainStore()
    for mandate in (parent, sibling_a, sibling_b):
        real_store.add(mandate)
    real_gate = ContainmentGate(real_store)
    assert real_gate.decide(sibling_a).in_bounds
    assert not real_gate.decide(sibling_b).in_bounds  # the real gate catches exactly what the broken one missed
