"""Builds the agent graph: nodes are agents, edges are shared infrastructure.

Two, and only two, ways an edge can form between two distinct agents:

- **Shared fingerprint** -- both agents have at least one session observed
  from the identical device fingerprint. A structural signal, independent of
  timing, and reliable on its own: two independently generated fingerprints
  colliding by chance is negligible.
- **Coordinated counterparty burst** -- both agents appear in the same
  multi-agent burst at one merchant: a maximal chronological cluster of
  same-merchant sessions, every consecutive pair inside
  `coordination_window`, containing at least `min_burst_agents` distinct
  agents. A *pairwise* "these two sessions happen to be close in time" test
  was tried first and rejected during calibration: at realistic traffic
  volume against a small, shared merchant catalog, two
  independent agents landing within any fixed window of each other by pure
  chance turns out to be common, not rare (measured directly, not assumed --
  see `docs/adr/0006`). Requiring a genuine multi-agent burst, not a
  two-agent coincidence, is what keeps agents that happen to shop at the
  same popular merchant at their own unrelated pace from spuriously forming
  a dense, misleading component.

Edge formation is O(n log n) per merchant group and per fingerprint group,
not O(n^2) over the whole session set: sessions are grouped by merchant (for
counterparty edges) or by fingerprint (for fingerprint edges) first, and each
group is walked once in time order.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from itertools import combinations
from uuid import UUID

import networkx as nx  # type: ignore[import-untyped]

from common.schema import SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint

logger = logging.getLogger(__name__)

# Maximum gap between two consecutive same-merchant sessions for them to
# extend the same burst. Narrow enough that a genuinely synchronized burst
# (every archetype in generator/collusion/rings.py places its whole group
# inside a window well under this) stays one cluster, while chance
# convergence at ambient traffic volume is diluted further by the
# min-distinct-agents requirement below -- see the module docstring.
DEFAULT_COORDINATION_WINDOW = timedelta(minutes=10)

# Minimum distinct agents a same-merchant burst must contain to count as
# coordinated. Two or three agents converging by chance on a popular
# merchant turns out to be common at realistic volume, not rare -- measured
# directly during calibration, not assumed, and the reason this constant is
# 4 rather than a smaller value that felt intuitively "enough." See
# `docs/adr/0006`.
DEFAULT_MIN_BURST_AGENTS = 4


@dataclass(frozen=True)
class GraphBuildConfig:
    """Tunable parameters for agent-graph construction.

    Attributes:
        coordination_window: Maximum gap between two consecutive sessions at
            the same merchant for them to extend the same burst.
        min_burst_agents: Minimum distinct agents a burst must contain for
            its members to be linked by an edge.
    """

    coordination_window: timedelta = field(default=DEFAULT_COORDINATION_WINDOW)
    min_burst_agents: int = field(default=DEFAULT_MIN_BURST_AGENTS)


AgentPair = tuple[str, str]

_DEFAULT_GRAPH_BUILD_CONFIG = GraphBuildConfig()


def _ordered_pair(agent_a: str, agent_b: str) -> AgentPair:
    """Orders two agent IDs so the same pair always hashes identically.

    Args:
        agent_a: One agent ID.
        agent_b: The other agent ID.

    Returns:
        The pair, lexicographically ordered.
    """
    return (agent_a, agent_b) if agent_a <= agent_b else (agent_b, agent_a)


def _fingerprint_edges(
    sessions: Sequence[SessionTrace], fingerprints: Mapping[UUID, DeviceFingerprint]
) -> Counter[AgentPair]:
    """Counts, per agent pair, how many shared fingerprints link them.

    Args:
        sessions: Every session in the corpus.
        fingerprints: Device fingerprint observed for each session, keyed by
            session ID. A session with no entry contributes no edges.

    Returns:
        A count of shared-fingerprint observations per agent pair.
    """
    agents_by_fingerprint: dict[DeviceFingerprint, set[str]] = defaultdict(set)
    for session in sessions:
        fingerprint = fingerprints.get(session.session_id)
        if fingerprint is not None:
            agents_by_fingerprint[fingerprint].add(session.agent_id)

    counts: Counter[AgentPair] = Counter()
    for agent_ids in agents_by_fingerprint.values():
        for agent_a, agent_b in combinations(sorted(agent_ids), 2):
            counts[_ordered_pair(agent_a, agent_b)] += 1
    return counts


def _counterparty_edges(
    sessions: Sequence[SessionTrace], coordination_window: timedelta, min_burst_agents: int
) -> Counter[AgentPair]:
    """Counts, per agent pair, how many coordinated counterparty bursts link them.

    A pairwise "these two sessions happen to be close in time" test is not
    enough at realistic traffic volume: with a small agent pool transacting
    repeatedly at a handful of popular merchants, two *independent* agents
    landing within any fixed window of each other by pure chance turns out
    to be common, not rare (confirmed empirically during calibration -- see
    `docs/adr/0006`). The criterion here is a genuine
    multi-agent burst instead: sessions at one merchant are grouped into
    maximal chronological clusters where every consecutive gap is within
    `coordination_window`, and a cluster only counts as coordinated if at
    least `min_burst_agents` *distinct* agents appear in it. Chance
    convergence of two or three agents is not unusual at realistic volume;
    chance convergence of `min_burst_agents` (4) or more, chained closely
    enough in time that every consecutive pair is inside the same short
    window, is much rarer -- while every archetype in
    `generator/collusion/rings.py` that this edge type is meant to catch
    places its whole group inside exactly one such window by construction.

    Args:
        sessions: Every session in the corpus.
        coordination_window: Maximum gap between two consecutive sessions
            (by time, at the same merchant) for them to extend the same
            burst.
        min_burst_agents: Minimum number of distinct agents a burst must
            contain to count as coordinated.

    Returns:
        A count of coordinated-burst co-memberships per agent pair.
    """
    sessions_by_merchant: dict[str, list[SessionTrace]] = defaultdict(list)
    for session in sessions:
        sessions_by_merchant[session.merchant_id].append(session)

    counts: Counter[AgentPair] = Counter()
    for group in sessions_by_merchant.values():
        ordered = sorted(group, key=lambda s: s.started_at)
        burst: list[SessionTrace] = []
        for session in ordered:
            if burst and session.started_at - burst[-1].started_at > coordination_window:
                _count_burst(burst, min_burst_agents, counts)
                burst = []
            burst.append(session)
        _count_burst(burst, min_burst_agents, counts)
    return counts


def _count_burst(
    burst: list[SessionTrace], min_burst_agents: int, counts: Counter[AgentPair]
) -> None:
    """Adds pairwise co-membership counts for one qualifying burst, in place.

    Args:
        burst: Sessions in one chronologically chained cluster, all at the
            same merchant.
        min_burst_agents: Minimum distinct agents required for the burst to
            count.
        counts: Running per-pair counts, updated in place.
    """
    distinct_agents = sorted({session.agent_id for session in burst})
    if len(distinct_agents) < min_burst_agents:
        return
    for agent_a, agent_b in combinations(distinct_agents, 2):
        counts[_ordered_pair(agent_a, agent_b)] += 1


def build_agent_graph(
    sessions: Sequence[SessionTrace],
    fingerprints: Mapping[UUID, DeviceFingerprint],
    config: GraphBuildConfig = _DEFAULT_GRAPH_BUILD_CONFIG,
) -> nx.Graph:
    """Builds the agent graph from shared fingerprints and coordinated counterparty overlap.

    Args:
        sessions: Every session in the corpus. Order does not matter --
            edge formation groups by merchant/fingerprint internally.
        fingerprints: Device fingerprint observed for each session, keyed by
            session ID.
        config: Graph-construction parameters.

    Returns:
        An undirected graph with one node per distinct `agent_id` in
        `sessions` (including agents with no edges at all) and one weighted
        edge per pair of agents linked by at least one fingerprint or
        coordinated-counterparty observation.
    """
    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(sorted({session.agent_id for session in sessions}))

    fingerprint_counts = _fingerprint_edges(sessions, fingerprints)
    counterparty_counts = _counterparty_edges(
        sessions, config.coordination_window, config.min_burst_agents
    )

    for pair in set(fingerprint_counts) | set(counterparty_counts):
        fingerprint_count = fingerprint_counts.get(pair, 0)
        counterparty_count = counterparty_counts.get(pair, 0)
        graph.add_edge(
            pair[0], pair[1],
            fingerprint_count=fingerprint_count,
            counterparty_count=counterparty_count,
            weight=fingerprint_count + counterparty_count,
        )

    logger.info(
        "agent graph: %d nodes, %d edges (%d fingerprint-linked pairs, %d counterparty-linked pairs)",
        graph.number_of_nodes(), graph.number_of_edges(),
        len(fingerprint_counts), len(counterparty_counts),
    )
    return graph
