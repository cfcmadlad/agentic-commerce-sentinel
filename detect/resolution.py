"""How a detector obtains the mandate a session claims to present.

An injected abstraction rather than a passed-around dict, so the backing
store (synthetic generator here, an agent-registry service in a real
deployment) can change without Layer 2 changing.

Keyed by session, not by mandate ID: an impostor can claim a mandate ID it
doesn't own or one that was never issued. Keying by mandate ID would let a
forged document silently overwrite the genuine one in a shared store.
"""

from __future__ import annotations

import logging
from typing import Protocol
from uuid import UUID

from mandate.schema import SignedMandate

logger = logging.getLogger(__name__)


class MandateResolver(Protocol):
    """Resolves the mandate document presented alongside a given session."""

    def resolve(self, session_id: UUID) -> SignedMandate | None:
        """Returns the mandate presented in a session, or None if there is none.

        Args:
            session_id: The session whose presented mandate is wanted.

        Returns:
            The presented mandate, or None if the session presented none or
            presented one that cannot be produced.
        """
        ...


class InMemoryMandateResolver:
    """A resolver backed by an in-memory session-to-mandate map."""

    def __init__(self, presented: dict[UUID, SignedMandate]) -> None:
        """Initializes the resolver.

        Args:
            presented: Map of session ID to the mandate presented in that
                session. Copied defensively so the caller's own dict can't
                be mutated mid-run to change what the detector sees.
        """
        self._presented: dict[UUID, SignedMandate] = dict(presented)

    def resolve(self, session_id: UUID) -> SignedMandate | None:
        """Returns the mandate presented in a session, or None.

        Args:
            session_id: The session whose presented mandate is wanted.

        Returns:
            The presented mandate, or None.
        """
        found = self._presented.get(session_id)
        if found is None:
            logger.debug("session %s presented no resolvable mandate", session_id)
        return found