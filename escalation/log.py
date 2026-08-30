"""Append-only, hash-chained persistence for `EscalationEvent`.

Built on `common/hash_chain.py`'s generic primitives rather than
duplicating `reasoning/audit_log.py`'s hash-chain logic a second time --
see that module's own docstring for why. This module owns only the
`EscalationEvent`-specific JSON mapping and the typed, narrow interface
callers actually use.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from uuid import UUID

from common.hash_chain import ChainVerificationResult, HashChainedLog, StoredEntry, verify_hash_chain
from escalation.schema import EscalationEvent, EscalationEventKind

logger = logging.getLogger(__name__)


def _event_to_json_dict(event: EscalationEvent) -> dict[str, object]:
    """Renders one `EscalationEvent` as a JSON-safe dict.

    Args:
        event: The event to render.

    Returns:
        A dict safe to pass to `json.dumps`.
    """
    return {
        "event_id": str(event.event_id),
        "escalation_id": str(event.escalation_id) if event.escalation_id is not None else None,
        "session_id": str(event.session_id) if event.session_id is not None else None,
        "agent_id": event.agent_id,
        "kind": event.kind.value,
        "actor": event.actor,
        "note": event.note,
        "created_at": event.created_at.isoformat(),
    }


def _event_from_json_dict(data: dict[str, object]) -> EscalationEvent:
    """Reconstructs one `EscalationEvent` from a JSON-decoded dict.

    Args:
        data: A dict previously produced by `_event_to_json_dict`.

    Returns:
        The reconstructed event.
    """
    escalation_id_raw = data["escalation_id"]
    session_id_raw = data["session_id"]
    return EscalationEvent(
        event_id=UUID(str(data["event_id"])),
        escalation_id=UUID(str(escalation_id_raw)) if escalation_id_raw is not None else None,
        session_id=UUID(str(session_id_raw)) if session_id_raw is not None else None,
        agent_id=str(data["agent_id"]),
        kind=EscalationEventKind(str(data["kind"])),
        actor=str(data["actor"]),
        note=str(data["note"]),
        created_at=datetime.fromisoformat(str(data["created_at"])),
    )


class EscalationLog:
    """A typed, hash-chained, append-only store of `EscalationEvent`s.

    Interface stays append-only, matching `reasoning.audit_log.AuditLog`:
    `append`, `read_all`, `read_entries`, and `path` only -- no update,
    delete, or clear method exists anywhere on this class.
    """

    def __init__(self, path: Path) -> None:
        """Initializes the log, creating an empty file if none exists.

        Args:
            path: File path to append events to and read events from.
        """
        self._log = HashChainedLog(path)

    @property
    def path(self) -> Path:
        """Returns the backing file path.

        Returns:
            The path this log reads from and appends to.
        """
        return self._log.path

    def append(self, event: EscalationEvent) -> None:
        """Appends one event to the log, chained to whatever precedes it.

        Args:
            event: The event to append.
        """
        self._log.append(_event_to_json_dict(event))
        logger.info("appended escalation event %s (%s) for agent %s", event.event_id, event.kind, event.agent_id)

    def read_entries(self) -> tuple[StoredEntry, ...]:
        """Reads every entry currently in the log, in append order.

        Returns:
            All entries, oldest first, each carrying its hash-chain fields.
        """
        return self._log.read_entries()

    def read_all(self) -> tuple[EscalationEvent, ...]:
        """Reads every event currently in the log, in append order.

        Returns:
            All events, oldest first.
        """
        return tuple(_event_from_json_dict(entry.record_dict) for entry in self._log.read_entries())

    def __len__(self) -> int:
        """Returns the number of events currently in the log.

        Returns:
            The event count.
        """
        return len(self._log)


def verify_chain(log: EscalationLog) -> ChainVerificationResult:
    """Walks an escalation log's hash chain and finds the first tamper point, if any.

    Args:
        log: The log to verify.

    Returns:
        Where (if anywhere) the chain first breaks.
    """
    return verify_hash_chain(log.read_entries())
