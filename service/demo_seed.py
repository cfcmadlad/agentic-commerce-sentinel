"""Replays each demo scenario's warm-up history through the real decide path.

Runs once, at service startup, so a live request against one of the fixed
demo session IDs in `service/demo_scenarios.py` reflects genuine
accumulated agent/mandate history -- exactly what a live production system
would have -- rather than a first-ever call with nothing behind it. Calls
the exact same `service.main.decide` function a live HTTP POST would
invoke, not a separate code path, so the resulting state mutation is
byte-for-byte what those warm-up sessions would produce if a client had
actually POSTed them.
"""

from __future__ import annotations

import logging

from service.demo_scenarios import build_demo_scenarios
from service.state import AppState

logger = logging.getLogger(__name__)


def seed_demo_history(state: AppState) -> None:
    """Replays every demo scenario's warm-up sessions through the real pipeline.

    Args:
        state: The application state to seed. Mutated in place, the same
            way a live request through `service.main.decide` would mutate
            it -- this function calls that handler directly rather than
            re-implementing any part of it.
    """
    from service.main import decide  # local import: avoids a circular import with main

    scenarios = build_demo_scenarios()
    seeded = 0
    for scenario in scenarios.values():
        for request in scenario.warmup:
            decide(request, state)
            seeded += 1
    logger.info("seeded %d warm-up session(s) across %d demo scenarios", seeded, len(scenarios))
