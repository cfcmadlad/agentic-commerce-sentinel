"""The escalation queue: state transitions, replay, and the circuit breaker together.

`EscalationQueue` is the single object that owns both the hash-chained
event log (`escalation/log.py`) and the derived, queryable state
(`escalation.schema.Escalation`) rebuilt from it -- matching the pattern
`detect.baseline.RulesOnlyBaseline` already uses for a stateful ledger
backed by deterministic replay. Every state-changing method appends an
event to the log *before* returning, so the log is always the source of
truth an in-memory index is rebuilt from, never the other way around.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from escalation.circuit_breaker import CircuitBreaker
from escalation.log import EscalationLog
from escalation.schema import (
    SYSTEM_ACTOR,
    Escalation,
    EscalationEvent,
    EscalationEventKind,
    EscalationStatus,
    ResolutionDecision,
)

logger = logging.getLogger(__name__)


class EscalationNotFoundError(KeyError):
    """Raised when an escalation ID has no matching escalation."""


class InvalidTransitionError(ValueError):
    """Raised when a transition is attempted from the wrong status."""


class HumanActionRequiredError(ValueError):
    """Raised when a review, resolution, or circuit-breaker reset claims the system actor.

    These are, by definition, the human-in-the-loop actions this package
    exists to require -- allowing `SYSTEM_ACTOR` through any of them would
    make "human-in-the-loop" a documentation claim instead of an enforced
    one.
    """


def _apply(current: Escalation | None, event: EscalationEvent) -> Escalation:
    """Folds one event into an escalation's state, building it fresh if needed.

    Args:
        current: The escalation's state before this event, or None if this
            is the OPENED event creating it.
        event: The event to apply. Must have a non-None `escalation_id`.

    Returns:
        The escalation's state after this event.

    Raises:
        AssertionError: If `event.escalation_id` is None -- a
            circuit-breaker event, which never belongs to one escalation
            and must never reach this function.
    """
    assert event.escalation_id is not None, "circuit-breaker events do not belong to one escalation"

    if event.kind is EscalationEventKind.OPENED:
        assert event.session_id is not None
        return Escalation(
            escalation_id=event.escalation_id,
            session_id=event.session_id,
            agent_id=event.agent_id,
            status=EscalationStatus.OPEN,
            reason=event.note,
            opened_at=event.created_at,
            reviewed_at=None,
            reviewed_by=None,
            resolved_at=None,
            resolved_by=None,
            resolution=None,
            events=(event,),
        )

    assert current is not None, f"event {event.event_id} references an escalation with no OPENED event"

    if event.kind is EscalationEventKind.REVIEWED:
        return replace(
            current,
            status=EscalationStatus.REVIEWED,
            reviewed_at=event.created_at,
            reviewed_by=event.actor,
            events=(*current.events, event),
        )

    if event.kind is EscalationEventKind.RESOLVED:
        resolution = ResolutionDecision(event.note.split(":", 1)[0])
        return replace(
            current,
            status=EscalationStatus.RESOLVED,
            resolved_at=event.created_at,
            resolved_by=event.actor,
            resolution=resolution,
            events=(*current.events, event),
        )

    raise AssertionError(f"unreachable: {event.kind} does not belong to a single escalation's own transitions")


@dataclass
class EscalationQueue:
    """Owns the escalation log, the circuit breaker, and the derived state built from both.

    Attributes:
        log: The hash-chained event log backing this queue.
        breaker: The per-agent circuit breaker.
        _by_id: In-memory index of current escalation state, rebuilt from
            `log` at construction time and kept current incrementally.
    """

    log: EscalationLog
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    _by_id: dict[UUID, Escalation] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        """Replays every event already in the log to rebuild current state.

        A stored `CIRCUIT_BREAKER_SUSPENDED` event is replayed as a no-op
        here, deliberately: it is a historical record of a suspension that
        an `OPENED` event already re-triggers below (the same call
        `open_escalation` itself makes live), and feeding it into the
        breaker a second time would double-count that escalation toward
        the threshold.
        """
        for event in self.log.read_all():
            if event.kind is EscalationEventKind.CIRCUIT_BREAKER_RESET:
                self.breaker.reset(event.agent_id)
                continue
            if event.kind is EscalationEventKind.CIRCUIT_BREAKER_SUSPENDED:
                continue
            assert event.escalation_id is not None
            self._by_id[event.escalation_id] = _apply(self._by_id.get(event.escalation_id), event)
            if event.kind is EscalationEventKind.OPENED:
                self.breaker.record_escalation(event.agent_id, event.created_at)

    @classmethod
    def from_path(cls, path: Path, breaker: CircuitBreaker | None = None) -> EscalationQueue:
        """Builds a queue backed by a log file, replaying any existing history.

        Args:
            path: File path for the backing `EscalationLog`.
            breaker: The circuit breaker to use. Defaults to a fresh one
                with the module's default thresholds.

        Returns:
            The queue, with in-memory state already replayed from `path`.
        """
        return cls(log=EscalationLog(path), breaker=breaker if breaker is not None else CircuitBreaker())

    def open_escalation(self, session_id: UUID, agent_id: str, reason: str, at: datetime) -> Escalation:
        """Opens a new escalation, automatically -- the system is always the actor here.

        Also records the escalation against the circuit breaker; if this
        trips suspension, a `CIRCUIT_BREAKER_SUSPENDED` event is appended
        immediately after, in the same call, so the log always shows the
        suspension directly following the escalation that caused it.

        Args:
            session_id: The session that triggered this escalation.
            agent_id: The agent that ran the session.
            reason: Why this was opened (e.g. the behavioral score and
                threshold that crossed).
            at: When this occurred -- the session's own timestamp, not the
                wall clock, so this stays reproducible.

        Returns:
            The newly opened escalation.
        """
        escalation_id = uuid4()
        event = EscalationEvent(
            event_id=uuid4(),
            escalation_id=escalation_id,
            session_id=session_id,
            agent_id=agent_id,
            kind=EscalationEventKind.OPENED,
            actor=SYSTEM_ACTOR,
            note=reason,
            created_at=at,
        )
        self.log.append(event)
        escalation = _apply(None, event)
        self._by_id[escalation_id] = escalation

        if self.breaker.record_escalation(agent_id, at):
            suspension_event = EscalationEvent(
                event_id=uuid4(),
                escalation_id=None,
                session_id=session_id,
                agent_id=agent_id,
                kind=EscalationEventKind.CIRCUIT_BREAKER_SUSPENDED,
                actor=SYSTEM_ACTOR,
                note=f"{self.breaker.threshold} escalations within {self.breaker.window}",
                created_at=at,
            )
            self.log.append(suspension_event)

        return escalation

    def review(self, escalation_id: UUID, actor: str, note: str, at: datetime) -> Escalation:
        """Marks an open escalation reviewed.

        Args:
            escalation_id: The escalation to review.
            actor: The reviewing human's identifier. Must not be
                `SYSTEM_ACTOR`.
            note: The reviewer's own notes.
            at: When the review occurred.

        Returns:
            The updated escalation.

        Raises:
            EscalationNotFoundError: If no such escalation exists.
            InvalidTransitionError: If the escalation is not currently OPEN.
            HumanActionRequiredError: If `actor` is `SYSTEM_ACTOR`.
        """
        if actor == SYSTEM_ACTOR:
            raise HumanActionRequiredError("a review must be attributed to a human actor, not the system")
        current = self._by_id.get(escalation_id)
        if current is None:
            raise EscalationNotFoundError(str(escalation_id))
        if current.status is not EscalationStatus.OPEN:
            raise InvalidTransitionError(f"escalation {escalation_id} is {current.status.value}, not open")

        event = EscalationEvent(
            event_id=uuid4(),
            escalation_id=escalation_id,
            session_id=current.session_id,
            agent_id=current.agent_id,
            kind=EscalationEventKind.REVIEWED,
            actor=actor,
            note=note,
            created_at=at,
        )
        self.log.append(event)
        updated = _apply(current, event)
        self._by_id[escalation_id] = updated
        return updated

    def resolve(
        self, escalation_id: UUID, actor: str, note: str, decision: ResolutionDecision, at: datetime
    ) -> Escalation:
        """Resolves a reviewed escalation.

        Args:
            escalation_id: The escalation to resolve.
            actor: The resolving human's identifier. Must not be
                `SYSTEM_ACTOR`.
            note: The reviewer's own closing notes.
            decision: What was concluded.
            at: When the resolution occurred.

        Returns:
            The updated escalation.

        Raises:
            EscalationNotFoundError: If no such escalation exists.
            InvalidTransitionError: If the escalation has not been
                reviewed yet -- resolving straight from OPEN is not a
                shortcut this queue allows.
            HumanActionRequiredError: If `actor` is `SYSTEM_ACTOR`.
        """
        if actor == SYSTEM_ACTOR:
            raise HumanActionRequiredError("a resolution must be attributed to a human actor, not the system")
        current = self._by_id.get(escalation_id)
        if current is None:
            raise EscalationNotFoundError(str(escalation_id))
        if current.status is not EscalationStatus.REVIEWED:
            raise InvalidTransitionError(
                f"escalation {escalation_id} is {current.status.value}, not reviewed -- review it first"
            )

        event = EscalationEvent(
            event_id=uuid4(),
            escalation_id=escalation_id,
            session_id=current.session_id,
            agent_id=current.agent_id,
            kind=EscalationEventKind.RESOLVED,
            actor=actor,
            note=f"{decision.value}: {note}",
            created_at=at,
        )
        self.log.append(event)
        updated = _apply(current, event)
        self._by_id[escalation_id] = updated
        return updated

    def reset_circuit_breaker(self, agent_id: str, actor: str, note: str, at: datetime) -> None:
        """Clears an agent's suspension -- the only way one is ever lifted.

        Args:
            agent_id: The agent to reset.
            actor: The resetting human's identifier. Must not be
                `SYSTEM_ACTOR`.
            note: Why the reset is being made.
            at: When the reset occurred.

        Raises:
            InvalidTransitionError: If the agent is not currently suspended.
            HumanActionRequiredError: If `actor` is `SYSTEM_ACTOR`.
        """
        if actor == SYSTEM_ACTOR:
            raise HumanActionRequiredError("a circuit-breaker reset must be attributed to a human actor")
        if not self.breaker.is_suspended(agent_id):
            raise InvalidTransitionError(f"agent {agent_id} is not currently suspended")

        event = EscalationEvent(
            event_id=uuid4(),
            escalation_id=None,
            session_id=None,
            agent_id=agent_id,
            kind=EscalationEventKind.CIRCUIT_BREAKER_RESET,
            actor=actor,
            note=note,
            created_at=at,
        )
        self.log.append(event)
        self.breaker.reset(agent_id)

    def get(self, escalation_id: UUID) -> Escalation | None:
        """Looks up one escalation's current state.

        Args:
            escalation_id: The escalation to look up.

        Returns:
            The escalation, or None if no such ID exists.
        """
        return self._by_id.get(escalation_id)

    def list_all(
        self, status: EscalationStatus | None = None, agent_id: str | None = None
    ) -> tuple[Escalation, ...]:
        """Lists escalations, optionally filtered.

        Args:
            status: If given, only escalations currently in this status.
            agent_id: If given, only escalations for this agent.

        Returns:
            Matching escalations, in no particular guaranteed order.
        """
        values: Iterable[Escalation] = self._by_id.values()
        if status is not None:
            values = (e for e in values if e.status is status)
        if agent_id is not None:
            values = (e for e in values if e.agent_id == agent_id)
        return tuple(values)

    def is_agent_suspended(self, agent_id: str) -> bool:
        """Checks whether an agent is currently suspended.

        Args:
            agent_id: The agent to check.

        Returns:
            True if suspended.
        """
        return self.breaker.is_suspended(agent_id)
