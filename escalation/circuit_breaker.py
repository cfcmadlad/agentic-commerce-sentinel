"""Deterministic per-agent circuit breaker.

Suspension is a pure function of a recorded sequence of (agent_id,
timestamp) escalation events plus two named constants -- never of wall-clock
time, so it is exactly as reproducible and as testable as everything else
this project's deterministic layers are. Once tripped, suspension is
*sticky*: it does not clear itself when the triggering escalations age out
of the rolling window, and nothing in this class can clear it automatically
-- only `reset`, called by a human action at the service boundary
(`service/main.py`'s circuit-breaker endpoint), can.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Not tuned via search -- a reasonable starting point for a synthetic eval
# harness, matching this project's own convention of naming a constant and
# stating plainly that it is not a fitted parameter (see
# `detect/calibration.py`'s cost-ratio assumption for the same pattern).
DEFAULT_ESCALATION_THRESHOLD = 3
DEFAULT_ROLLING_WINDOW = timedelta(hours=24)


@dataclass
class CircuitBreaker:
    """Tracks escalation history per agent and derives suspension from it.

    Attributes:
        threshold: Escalations within `window` that trip suspension.
        window: The rolling lookback window, ending at the timestamp of
            the escalation being recorded.
        _escalation_times: Per-agent history of escalation timestamps,
            pruned to the current window on each new record for memory,
            but never consulted to *lift* a suspension (see `is_suspended`).
        _suspended: Agents currently suspended. Membership here is the
            only thing `is_suspended` reads -- once added, an agent stays
            until `reset` removes it, never because the window moved on.
    """

    threshold: int = DEFAULT_ESCALATION_THRESHOLD
    window: timedelta = DEFAULT_ROLLING_WINDOW
    _escalation_times: dict[str, list[datetime]] = field(default_factory=dict)
    _suspended: set[str] = field(default_factory=set)

    def record_escalation(self, agent_id: str, at: datetime) -> bool:
        """Records one escalation for an agent and re-evaluates suspension.

        Args:
            agent_id: The agent the escalation concerns.
            at: When the escalation occurred. Injected, not read from the
                system clock, so this stays reproducible from a corpus's
                own session timestamps.

        Returns:
            True if the agent is suspended after this call (whether newly
            tripped by this escalation or already suspended from before).
        """
        times = self._escalation_times.setdefault(agent_id, [])
        times.append(at)
        recent = [t for t in times if at - t <= self.window]
        self._escalation_times[agent_id] = recent
        if len(recent) >= self.threshold and agent_id not in self._suspended:
            self._suspended.add(agent_id)
            logger.warning(
                "agent %s auto-suspended: %d escalations within %s", agent_id, len(recent), self.window
            )
        return agent_id in self._suspended

    def is_suspended(self, agent_id: str) -> bool:
        """Checks whether an agent is currently suspended.

        Args:
            agent_id: The agent to check.

        Returns:
            True if suspended.
        """
        return agent_id in self._suspended

    def reset(self, agent_id: str) -> None:
        """Clears a suspension and its escalation history for an agent.

        The only way suspension is ever lifted -- see the class docstring.
        Clearing history too (not just the suspended flag) means a fresh
        start counts from zero, not from a window that already contains
        the escalations that caused the suspension being reset.

        Args:
            agent_id: The agent to reset.
        """
        self._suspended.discard(agent_id)
        self._escalation_times.pop(agent_id, None)
        logger.info("agent %s circuit breaker reset", agent_id)
