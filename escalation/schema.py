"""Types for the escalation queue: events (what actually happened, at rest) and the materialized view built from them.

Mirrors the split `mandate/schema.py` vs. `mandate/verification.py` and
`reasoning/schema.py` vs. `reasoning/audit_log.py` already use in this
project: pure data here, the logic that builds and persists it in
`escalation/queue.py` and `escalation/log.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import UUID

# The actor recorded for a transition the system itself performs (opening
# an escalation when Layer 3 flags a session, auto-suspending an agent) --
# never a human identity, so a reader of the log can tell at a glance which
# transitions had a human behind them and which did not.
SYSTEM_ACTOR = "system"


class EscalationStatus(str, Enum):
    """The three states an escalation moves through, in order."""

    OPEN = "open"
    REVIEWED = "reviewed"
    RESOLVED = "resolved"


class ResolutionDecision(str, Enum):
    """What a human reviewer concluded when resolving an escalation."""

    CONFIRMED_ATTACK = "confirmed_attack"
    CLEARED = "cleared"


class EscalationEventKind(str, Enum):
    """Every kind of transition this package's hash-chained log can record."""

    OPENED = "opened"
    REVIEWED = "reviewed"
    RESOLVED = "resolved"
    CIRCUIT_BREAKER_SUSPENDED = "circuit_breaker_suspended"
    CIRCUIT_BREAKER_RESET = "circuit_breaker_reset"


@dataclass(frozen=True)
class EscalationEvent:
    """One append-only log entry: a single transition, with its actor.

    Attributes:
        event_id: Unique identifier for this event.
        escalation_id: The escalation this event belongs to. None for an
            agent-wide circuit-breaker event, which is not about any one
            escalation.
        session_id: The session that triggered the escalation, if this
            event belongs to one.
        agent_id: The agent whose session (or, for a circuit-breaker event,
            whose own suspension state) this event concerns.
        kind: Which transition this event records.
        actor: Who performed it -- `SYSTEM_ACTOR` for an automatic open or
            suspension, a human reviewer identifier for every other kind.
        note: Free-text context (a reviewer's reasoning, the automatic
            open's trigger description). Never parsed, only displayed.
        created_at: UTC time this event occurred.
    """

    event_id: UUID
    escalation_id: UUID | None
    session_id: UUID | None
    agent_id: str
    kind: EscalationEventKind
    actor: str
    note: str
    created_at: datetime


@dataclass(frozen=True)
class Escalation:
    """The current state of one escalation, rebuilt from its event history.

    Attributes:
        escalation_id: Unique identifier for this escalation.
        session_id: The session that triggered it.
        agent_id: The agent that ran the session.
        status: Current lifecycle state.
        reason: Why this was opened (the automatic open event's note).
        opened_at: When the OPENED event was recorded.
        reviewed_at: When the REVIEWED event was recorded, if any.
        reviewed_by: The actor who reviewed it, if any.
        resolved_at: When the RESOLVED event was recorded, if any.
        resolved_by: The actor who resolved it, if any.
        resolution: What the resolution concluded, if resolved.
        events: Every event for this escalation, oldest first.
    """

    escalation_id: UUID
    session_id: UUID
    agent_id: str
    status: EscalationStatus
    reason: str
    opened_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    resolution: ResolutionDecision | None
    events: tuple[EscalationEvent, ...]
