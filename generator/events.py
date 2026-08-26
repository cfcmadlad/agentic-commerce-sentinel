"""Construction of session event sequences, shared across all generators.

Mandate replay and scope violation must produce event sequences that are
*behaviorally indistinguishable* from legitimate ones: those attacks are
defined by the authorization being wrong, not by the session looking odd, and
a detector that separated them on event timing alone would be exploiting a
generator artifact rather than a real signal. Routing every generator through
one builder is how that property is guaranteed rather than hoped for.

The impersonation generator deliberately does not use the default parameters
here; see `generator/attacks/impersonation.py` for what it varies and why.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np

from common.schema import EventType, SessionEvent

# The full lifecycle a well-behaved agent walks through, in order.
LEGITIMATE_LIFECYCLE: tuple[EventType, ...] = (
    EventType.INTENT_CAPTURED,
    EventType.MANDATE_PRESENTED,
    EventType.CATALOG_BROWSE,
    EventType.CART_BUILD,
    EventType.PAYMENT_ATTEMPT,
    EventType.PAYMENT_RESULT,
)


def build_events(
    rng: np.random.Generator,
    started_at: datetime,
    stages: tuple[EventType, ...],
    min_gap_seconds: int,
    max_gap_seconds: int,
) -> tuple[list[SessionEvent], datetime]:
    """Builds a timestamped event sequence with uniform inter-event jitter.

    Args:
        rng: Seeded random generator.
        started_at: Timestamp of the first event.
        stages: Event types to emit, in order. Must be non-empty.
        min_gap_seconds: Inclusive lower bound on the gap between events.
        max_gap_seconds: Inclusive upper bound on the gap between events.

    Returns:
        A tuple of (events, completed_at), where completed_at is the
        timestamp of the final event.

    Raises:
        ValueError: If `stages` is empty or the gap bounds are inverted. A
            zero-event session would fail `SessionTrace` validation further
            downstream with a much less informative message.
    """
    if not stages:
        raise ValueError("stages must be non-empty; a session needs at least one event")
    if max_gap_seconds < min_gap_seconds:
        raise ValueError(
            f"max_gap_seconds ({max_gap_seconds}) precedes min_gap_seconds ({min_gap_seconds})"
        )

    events: list[SessionEvent] = []
    current = started_at
    for stage in stages:
        events.append(SessionEvent(event_type=stage, timestamp=current, payload={}))
        gap = int(rng.integers(min_gap_seconds, max_gap_seconds + 1))
        current = current + timedelta(seconds=gap)
    return events, events[-1].timestamp