"""Builds a mandate's delegation chain, each node's own containment verdict included.

Pure function, no FastAPI dependency -- shared between `service/main.py`'s
`GET /mandates/{id}/chain` endpoint and `run_delegation_demo_export.py`,
which needs the identical computation offline to export static fixtures for
the frontend's recorded (non-live) mode. Kept out of `service/main.py`
specifically so the export script can import it without also importing the
FastAPI app.
"""

from __future__ import annotations

from decimal import Decimal

from containment.chain import AncestorChainResolution, resolve_ancestor_chain
from containment.engine import enforce_containment
from containment.store import MutableMandateChainStore
from mandate.schema import Mandate
from service.schemas import ChainEdgeOut, ChainNodeOut, DelegationChainOut


def build_delegation_chain(mandate: Mandate, store: MutableMandateChainStore) -> DelegationChainOut:
    """Walks a mandate's ancestor chain, computing each node's own containment verdict.

    Each node's own chain is a suffix of the originally resolved one: since
    `resolve_ancestor_chain`'s walk only appends an ancestor after
    confirming it is not a repeat of any node seen so far and is still
    within the depth bound counted from the *original* starting mandate,
    every node already in the resolved chain is, from its own position,
    unambiguously closer to the root than that -- its own suffix can never
    newly introduce a cycle or exceed the depth bound the original walk did
    not already hit. Only the deepest node in the resolved chain can
    actually be the one a cycle, the depth bound, or an unresolvable link
    stopped at, which is exactly the case `parent is None` below handles.

    Sibling commitment is computed by summing every *earlier-arriving*
    sibling's own ceiling -- `store.all_mandates()` returns mandates in the
    order `MutableMandateChainStore.add` received them, a plain Python
    dict's insertion order, and only mandates before this one's own arrival
    index count toward what it must fit under. This mirrors
    `containment.gate.ContainmentGate`'s real sequential ledger semantics
    (the first sibling in a fan-out group commits against the parent's full
    remaining budget; the second sees the first's commitment already taken)
    rather than a symmetric "every other sibling" sum, which would flag
    *both* siblings in a two-sibling group whenever their amounts jointly
    exceed the parent's cap -- wrong for the first, which a real sequential
    check would accept. For a live service, "arrival order" here means
    order of presentation to `/sessions/decide`, which is a real ordering
    but not necessarily wall-clock event order if requests arrive out of
    sequence -- the same disclosed limitation `service/state.py`'s own
    module docstring already states for causal features.

    Args:
        mandate: The mandate to build the chain for.
        store: The mandate store to resolve ancestors and scan siblings
            against.

    Returns:
        The full chain, root-ward from `mandate`, each node's own
        containment verdict included.
    """
    if mandate.parent_mandate_id is None:
        return DelegationChainOut(
            nodes=[
                ChainNodeOut(
                    mandate_id=mandate.mandate_id,
                    agent_id=mandate.agent_id,
                    parent_mandate_id=None,
                    depth=0,
                    is_root=True,
                    in_bounds=None,
                    reasons=[],
                    unresolvable_parent=False,
                )
            ],
            edges=[],
            chain_broken=False,
            chain_broken_reason=None,
        )

    resolution = resolve_ancestor_chain(mandate, store)
    chain_mandates = [mandate, *resolution.ancestors]
    all_mandates = store.all_mandates()

    nodes: list[ChainNodeOut] = []
    edges: list[ChainEdgeOut] = []
    for i, node in enumerate(chain_mandates):
        if node.parent_mandate_id is None:
            nodes.append(
                ChainNodeOut(
                    mandate_id=node.mandate_id,
                    agent_id=node.agent_id,
                    parent_mandate_id=None,
                    depth=i,
                    is_root=True,
                    in_bounds=None,
                    reasons=[],
                    unresolvable_parent=False,
                )
            )
            continue

        parent = chain_mandates[i + 1] if i + 1 < len(chain_mandates) else None
        if parent is None:
            nodes.append(
                ChainNodeOut(
                    mandate_id=node.mandate_id,
                    agent_id=node.agent_id,
                    parent_mandate_id=node.parent_mandate_id,
                    depth=i,
                    is_root=False,
                    in_bounds=None,
                    reasons=[],
                    unresolvable_parent=True,
                )
            )
            continue

        node_arrival_index = next(idx for idx, m in enumerate(all_mandates) if m.mandate_id == node.mandate_id)
        committed_sibling_total = sum(
            (
                m.scope.max_amount
                for m in all_mandates[:node_arrival_index]
                if m.parent_mandate_id == parent.mandate_id
            ),
            start=Decimal("0"),
        )
        node_chain = AncestorChainResolution(
            immediate_parent=parent,
            ancestors=tuple(chain_mandates[i + 1 :]),
            cycle_detected=False,
            depth_exceeded=False,
            unresolvable=False,
        )
        result = enforce_containment(node, node_chain, committed_sibling_total)
        nodes.append(
            ChainNodeOut(
                mandate_id=node.mandate_id,
                agent_id=node.agent_id,
                parent_mandate_id=node.parent_mandate_id,
                depth=i,
                is_root=False,
                in_bounds=result.in_bounds,
                reasons=[r.value for r in result.reasons],
                unresolvable_parent=False,
            )
        )
        edges.append(
            ChainEdgeOut(
                child_mandate_id=node.mandate_id, parent_mandate_id=parent.mandate_id, violates=not result.in_bounds
            )
        )

    chain_broken_reason: str | None = None
    if resolution.cycle_detected:
        chain_broken_reason = "cycle_detected"
    elif resolution.depth_exceeded:
        chain_broken_reason = "depth_exceeded"
    elif resolution.unresolvable:
        chain_broken_reason = "unresolvable_ancestor"

    return DelegationChainOut(
        nodes=nodes, edges=edges, chain_broken=resolution.broken, chain_broken_reason=chain_broken_reason
    )
