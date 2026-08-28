"""Walks a mandate's `parent_mandate_id` links to resolve its ancestor chain.

Cycle detection and the depth bound live here, separate from the containment
rules themselves (`containment/engine.py`), so a broken-chain outcome and a
scope-authority violation are reported as distinct, named findings rather
than conflated into one catch-all reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from containment.schema import MAX_DELEGATION_DEPTH
from containment.store import MandateChainStore
from mandate.schema import Mandate

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AncestorChainResolution:
    """The result of walking one mandate's delegation chain upward.

    Attributes:
        immediate_parent: The mandate's direct parent, or None if it could
            not be resolved before a stopping condition was hit.
        ancestors: Every resolved ancestor, immediate parent first, in walk
            order. Stops at the first cycle, depth-bound breach, or
            unresolvable link, so a broken chain's `ancestors` may be
            shorter than the true chain.
        cycle_detected: True if walking the chain revisited a mandate ID
            already seen, including the starting mandate's own ID.
        depth_exceeded: True if the chain was still unresolved after
            `MAX_DELEGATION_DEPTH` ancestor hops.
        unresolvable: True if a `parent_mandate_id` pointed to a mandate the
            store has no record of.
    """

    immediate_parent: Mandate | None
    ancestors: tuple[Mandate, ...]
    cycle_detected: bool
    depth_exceeded: bool
    unresolvable: bool

    @property
    def broken(self) -> bool:
        """Whether the chain could not be fully and safely resolved.

        Returns:
            True if any of `cycle_detected`, `depth_exceeded`, or
            `unresolvable` is True. A broken chain cannot be trusted to
            check scope, cap, or expiry rules against, so containment fails
            closed on it rather than comparing against a partial ancestor.
        """
        return self.cycle_detected or self.depth_exceeded or self.unresolvable


def resolve_ancestor_chain(
    mandate: Mandate,
    store: MandateChainStore,
    max_depth: int = MAX_DELEGATION_DEPTH,
) -> AncestorChainResolution:
    """Walks `mandate.parent_mandate_id` upward to resolve its ancestor chain.

    Args:
        mandate: The mandate whose delegation chain is being resolved. Must
            have a non-None `parent_mandate_id` -- a root mandate has
            nothing to resolve, and containment does not apply to it (see
            `containment.gate.ContainmentGate.decide`).
        store: Resolves a mandate by ID.
        max_depth: Maximum number of ancestor hops permitted before the
            chain is rejected as too deep.

    Returns:
        The resolution, stopping at the first cycle, depth-bound breach, or
        unresolvable link.

    Raises:
        ValueError: If `mandate.parent_mandate_id` is None.
    """
    if mandate.parent_mandate_id is None:
        raise ValueError(
            f"mandate {mandate.mandate_id} has no parent; resolve_ancestor_chain "
            f"only applies to a mandate that declares a parent_mandate_id"
        )

    ancestors: list[Mandate] = []
    visited: set[UUID] = {mandate.mandate_id}
    cycle_detected = False
    depth_exceeded = False
    unresolvable = False

    current_parent_id: UUID | None = mandate.parent_mandate_id
    while current_parent_id is not None:
        if current_parent_id in visited:
            cycle_detected = True
            logger.warning(
                "mandate %s: cycle detected in delegation chain at %s",
                mandate.mandate_id, current_parent_id,
            )
            break
        if len(ancestors) >= max_depth:
            depth_exceeded = True
            logger.warning(
                "mandate %s: delegation depth exceeds %d", mandate.mandate_id, max_depth
            )
            break
        parent = store.get(current_parent_id)
        if parent is None:
            unresolvable = True
            logger.warning(
                "mandate %s: ancestor %s not found in chain store",
                mandate.mandate_id, current_parent_id,
            )
            break
        ancestors.append(parent)
        visited.add(parent.mandate_id)
        current_parent_id = parent.parent_mandate_id

    return AncestorChainResolution(
        immediate_parent=ancestors[0] if ancestors else None,
        ancestors=tuple(ancestors),
        cycle_detected=cycle_detected,
        depth_exceeded=depth_exceeded,
        unresolvable=unresolvable,
    )
