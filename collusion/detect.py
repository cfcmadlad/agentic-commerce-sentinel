"""Orchestrates graph construction, community detection, and scoring into verdicts.

`score_candidates` does the threshold-independent work -- building the agent
graph, running Louvain, and scoring every candidate community -- exactly
once. `detect_rings` is the single-shot convenience entry point a normal
caller uses; a caller evaluating the *same* session stream at several
different thresholds (as `eval/collusion_evaluation.py::sweep_thresholds`
does) should call `score_candidates` once and compare against each threshold
directly, rather than paying for graph construction and Louvain repeatedly
for work that does not depend on the threshold at all.

This module has no learned parameters and touches no ground truth --
everything it consumes is exactly what a real deployment would have
(sessions, and whatever fingerprint data the transport layer observed).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from collusion.community import DEFAULT_COMMUNITY_SEED, MIN_COMMUNITY_SIZE, detect_communities
from collusion.graph import DEFAULT_COORDINATION_WINDOW, GraphBuildConfig, build_agent_graph
from collusion.schema import RingScore, RingVerdict
from collusion.scoring import score_community
from common.schema import SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint

logger = logging.getLogger(__name__)

# The operating threshold `docs/adr/0006` reports: the largest value that
# still catches every planted ring in this layer's own evaluation, minimizing
# false alarms subject to that constraint -- the same
# missing-a-real-ring-costs-more-than-a-false-alarm principle this project
# already applies via detect/calibration.py's cost ratio, stated here
# directly rather than as an invented numeric cost figure there is no data
# to justify.
DEFAULT_RING_THRESHOLD = 0.30


@dataclass(frozen=True)
class ScoredCandidate:
    """One candidate community with its computed risk score, before thresholding.

    Attributes:
        agent_ids: The community's member agents.
        score: The computed risk score.
    """

    agent_ids: frozenset[str]
    score: RingScore


def score_candidates(
    sessions: Sequence[SessionTrace],
    fingerprints: Mapping[UUID, DeviceFingerprint],
    coordination_window: timedelta = DEFAULT_COORDINATION_WINDOW,
    community_seed: int = DEFAULT_COMMUNITY_SEED,
    min_community_size: int = MIN_COMMUNITY_SIZE,
) -> tuple[ScoredCandidate, ...]:
    """Builds the agent graph, detects communities, and scores each one.

    The threshold-independent half of `detect_rings`: nothing here depends
    on an operating threshold, so a caller comparing the same session stream
    against several thresholds should call this once and reuse the result,
    rather than re-running graph construction and Louvain per threshold.

    Args:
        sessions: Every session to consider. Order does not matter.
        fingerprints: Device fingerprint observed for each session, keyed by
            session ID.
        coordination_window: Maximum gap between two sessions with the same
            counterparty (or the window structuring spend is summed inside)
            for them to be considered coordinated.
        community_seed: Seed for Louvain's internal randomized tie-breaking.
        min_community_size: Minimum community size to keep as a candidate.

    Returns:
        One scored candidate per community Louvain surfaced, in no
        particular order. Empty if the graph has no qualifying communities.
    """
    graph = build_agent_graph(
        sessions, fingerprints, GraphBuildConfig(coordination_window=coordination_window)
    )
    communities = detect_communities(graph, seed=community_seed, min_size=min_community_size)

    sessions_by_agent: dict[str, list[SessionTrace]] = defaultdict(list)
    for session in sessions:
        sessions_by_agent[session.agent_id].append(session)

    return tuple(
        ScoredCandidate(
            agent_ids=community,
            score=score_community(community, sessions_by_agent, fingerprints, coordination_window),
        )
        for community in communities
    )


def verdicts_at_threshold(
    candidates: tuple[ScoredCandidate, ...], threshold: float
) -> tuple[RingVerdict, ...]:
    """Applies an operating threshold to already-scored candidates.

    Args:
        candidates: Scored candidates from `score_candidates`.
        threshold: The score at or above which a candidate is flagged.

    Returns:
        One verdict per candidate, in the same order given.
    """
    return tuple(
        RingVerdict(agent_ids=c.agent_ids, score=c.score, flagged=c.score.combined >= threshold)
        for c in candidates
    )


def detect_rings(
    sessions: Sequence[SessionTrace],
    fingerprints: Mapping[UUID, DeviceFingerprint],
    threshold: float = DEFAULT_RING_THRESHOLD,
    coordination_window: timedelta = DEFAULT_COORDINATION_WINDOW,
    community_seed: int = DEFAULT_COMMUNITY_SEED,
    min_community_size: int = MIN_COMMUNITY_SIZE,
) -> tuple[RingVerdict, ...]:
    """Runs the full collusion-detection pipeline over a session stream, at one threshold.

    A convenience wrapper around `score_candidates` plus `verdicts_at_
    threshold` for the common single-threshold case. A caller that needs
    verdicts at several thresholds over the same session stream should call
    `score_candidates` once and pass its result to `verdicts_at_threshold`
    for each threshold instead of calling this function repeatedly.

    Args:
        sessions: Every session to consider. Order does not matter.
        fingerprints: Device fingerprint observed for each session, keyed by
            session ID.
        threshold: The score at or above which a candidate community is
            flagged as a ring.
        coordination_window: Maximum gap between two sessions with the same
            counterparty (or the window structuring spend is summed inside)
            for them to be considered coordinated.
        community_seed: Seed for Louvain's internal randomized tie-breaking.
        min_community_size: Minimum community size to keep as a candidate.

    Returns:
        One verdict per candidate community Louvain surfaced, in no
        particular order. Empty if the graph has no qualifying communities.
    """
    candidates = score_candidates(
        sessions, fingerprints, coordination_window, community_seed, min_community_size
    )
    verdicts = verdicts_at_threshold(candidates, threshold)

    flagged_count = sum(1 for v in verdicts if v.flagged)
    logger.info(
        "collusion detection: %d candidate communities, %d flagged at threshold %.2f",
        len(verdicts), flagged_count, threshold,
    )
    return verdicts
