"""Stateful orchestration for Layer 2.5, mirroring `detect/baseline.py`'s design.

`ContainmentGate` is the single entry point a pipeline calls: it resolves a
mandate's ancestor chain, applies the containment rules, and -- the one piece
of state this layer needs -- tracks how much of each parent's authority has
already been committed to its other children, so the "remaining cap given
already-committed siblings" rule means something across a stream of sessions
rather than only within one.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from uuid import UUID

from containment.chain import resolve_ancestor_chain
from containment.engine import enforce_containment
from containment.schema import MAX_DELEGATION_DEPTH, ContainmentResult
from containment.store import MandateChainStore
from mandate.schema import Mandate

logger = logging.getLogger(__name__)

_ZERO = Decimal("0")


class ContainmentGate:
    """Evaluates delegated mandates against their parent chain, in session order.

    Stateful across a run because the "already-committed sibling mandates"
    rule requires a running per-parent total, incremented only for mandates
    this gate itself allowed -- mirroring `mandate.verification.MandateLedger`'s
    "budget is consumed only on allowed transactions" discipline: a mandate
    containment rejects never gets to count toward its siblings' remaining
    cap. Committed amounts are tracked per child mandate, not as one running
    total per parent, so that re-deciding an already-allowed mandate (a
    session reusing it) always measures it against the same remaining cap it
    originally passed against -- never against a total that already includes
    its own prior contribution. Construct one per evaluation run; reusing an
    instance across two runs carries committed-sibling state between them.
    """

    def __init__(self, store: MandateChainStore, max_depth: int = MAX_DELEGATION_DEPTH) -> None:
        """Initializes the gate with its injected chain store.

        Args:
            store: Resolves a mandate by ID, for ancestor-chain walking.
            max_depth: Delegation depth bound passed to chain resolution.
        """
        self._store = store
        self._max_depth = max_depth
        self._committed_by_parent: dict[UUID, dict[UUID, Decimal]] = {}

    def _committed_sibling_total(self, parent_id: UUID, excluding_child_id: UUID) -> Decimal:
        """Sums every other committed child's cap under one parent.

        Args:
            parent_id: The immediate parent to sum committed children under.
            excluding_child_id: The mandate currently being decided -- excluded
                from the sum even if it was itself committed by an earlier call,
                so a mandate is never measured against its own prior
                contribution.

        Returns:
            The sum of `scope.max_amount` for every other committed child.
        """
        siblings = self._committed_by_parent.get(parent_id, {})
        return sum(
            (amount for child_id, amount in siblings.items() if child_id != excluding_child_id),
            start=_ZERO,
        )

    def decide(self, mandate: Mandate) -> ContainmentResult:
        """Evaluates one mandate's containment verdict and advances ledger state.

        Args:
            mandate: The mandate to evaluate, in chronological order relative
                to any other call on this same gate instance -- the sibling
                cap rule reads a running total, so out-of-order calls check
                against a total from the future. A root mandate
                (`parent_mandate_id is None`) passes trivially: containment
                has nothing to check it against.

        Returns:
            The verdict. If `in_bounds`, this mandate's `scope.max_amount` is
            (re-)recorded as committed against its parent; a later session
            reusing the same already-allowed mandate is measured against the
            same remaining cap it originally passed against, not a smaller
            one that double-counts its own prior contribution.
        """
        if mandate.parent_mandate_id is None:
            return ContainmentResult(mandate_id=mandate.mandate_id, in_bounds=True, reasons=())

        chain = resolve_ancestor_chain(mandate, self._store, self._max_depth)
        committed = self._committed_sibling_total(mandate.parent_mandate_id, mandate.mandate_id)
        result = enforce_containment(mandate, chain, committed)

        if result.in_bounds:
            self._committed_by_parent.setdefault(mandate.parent_mandate_id, {})[mandate.mandate_id] = (
                mandate.scope.max_amount
            )
            logger.debug(
                "mandate %s: committed %s against parent %s (other siblings committed %s)",
                mandate.mandate_id, mandate.scope.max_amount, mandate.parent_mandate_id, committed,
            )

        return result
