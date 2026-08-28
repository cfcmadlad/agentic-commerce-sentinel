"""How the containment engine resolves a mandate's parent by ID.

Mirrors `detect/resolution.py`'s `MandateResolver`: an injected abstraction
so the backing store (a static in-memory index over a synthetic corpus here,
a real mandate ledger service in a deployment) can change without the chain
walker or engine changing. Keyed by mandate ID rather than by session, unlike
`MandateResolver` -- containment needs to look up an *ancestor* mandate that
may never have been presented in any session this run has seen yet.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Protocol
from uuid import UUID

from mandate.schema import Mandate, SignedMandate

logger = logging.getLogger(__name__)


class MandateChainStore(Protocol):
    """Resolves a mandate's own content by mandate ID, for chain walking."""

    def get(self, mandate_id: UUID) -> Mandate | None:
        """Returns the mandate with this ID, or None if unknown to this store.

        Args:
            mandate_id: The mandate ID to resolve.

        Returns:
            The mandate, or None if this store has no record of it.
        """
        ...


class InMemoryMandateChainStore:
    """A chain store backed by an in-memory mandate_id -> Mandate index."""

    def __init__(self, mandates: dict[UUID, Mandate]) -> None:
        """Initializes the store.

        Args:
            mandates: Map of mandate ID to its content. Copied defensively
                so the caller's own dict can't be mutated mid-run to change
                what the store resolves.
        """
        self._mandates: dict[UUID, Mandate] = dict(mandates)

    def get(self, mandate_id: UUID) -> Mandate | None:
        """Returns the mandate with this ID, or None.

        Args:
            mandate_id: The mandate ID to resolve.

        Returns:
            The mandate, or None if this store has no record of it.
        """
        found = self._mandates.get(mandate_id)
        if found is None:
            logger.debug("mandate %s not found in chain store", mandate_id)
        return found


def build_store_from_signed_mandates(
    signed_mandates: Iterable[SignedMandate],
) -> InMemoryMandateChainStore:
    """Indexes a collection of signed mandates by mandate ID.

    A mandate ID is documented (`mandate/schema.py::Mandate.mandate_id`) as
    globally unique, so two mandates observed under the same ID should always
    carry identical content. If they don't -- an upstream ID-generation
    collision, or two unrelated code paths supplying inconsistent data for
    the same ID -- this store refuses to silently pick one of the conflicting
    versions. It drops the ID from the index entirely, so `get()` reports it
    as unresolvable, matching `containment.chain.resolve_ancestor_chain`'s
    existing "fail closed on anything not safely resolvable" discipline
    rather than adding a second, different kind of failure this engine would
    need a separate reason for.

    Args:
        signed_mandates: Every signed mandate the chain store should be able
            to resolve -- in an offline evaluation, every mandate presented
            anywhere in the corpus (both the legitimate mandates that can
            serve as delegation roots and every attack-generated child).

    Returns:
        The indexed store, with any ID that resolved to conflicting content
        excluded rather than arbitrarily resolved.
    """
    index: dict[UUID, Mandate] = {}
    conflicting: set[UUID] = set()
    for signed in signed_mandates:
        mandate = signed.mandate
        existing = index.get(mandate.mandate_id)
        if existing is not None and existing != mandate:
            conflicting.add(mandate.mandate_id)
            logger.error(
                "mandate %s resolves to conflicting content across this corpus; "
                "excluding it from the chain store rather than picking one arbitrarily",
                mandate.mandate_id,
            )
            continue
        index[mandate.mandate_id] = mandate
    for mandate_id in conflicting:
        index.pop(mandate_id, None)
    return InMemoryMandateChainStore(index)
