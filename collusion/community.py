"""Louvain community detection over the agent graph.

A thin, deterministic wrapper around `networkx`'s own Louvain implementation
-- the standard algorithm the brief for this milestone names directly
("Louvain or similar"). Not reimplemented by hand: Louvain's modularity
optimization is well-established and well-tested in `networkx` itself, and
duplicating it would risk a subtly wrong reimplementation without adding
anything this project needs to control.
"""

from __future__ import annotations

import logging

import networkx as nx  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# A community of one agent cannot be a ring by definition -- collusion is a
# relationship between at least two identities.
MIN_COMMUNITY_SIZE = 2

# Louvain's own randomized tie-breaking needs a seed for this project's
# standing reproducibility rule: the same graph must always partition
# identically.
DEFAULT_COMMUNITY_SEED = 42


def detect_communities(
    graph: nx.Graph,
    seed: int = DEFAULT_COMMUNITY_SEED,
    min_size: int = MIN_COMMUNITY_SIZE,
) -> tuple[frozenset[str], ...]:
    """Partitions the agent graph into communities via Louvain, then filters by size.

    Args:
        graph: The agent graph, from `collusion.graph.build_agent_graph`.
        seed: Seed for Louvain's internal randomized tie-breaking; the same
            graph and seed always produce the same partition.
        min_size: Minimum community size to keep as a candidate ring.
            Communities smaller than this are dropped -- a single isolated
            agent, or a graph with no edges at all, produces none.

    Returns:
        Every community at or above `min_size`, each as a frozenset of
        member agent IDs. Empty if the graph has no edges.
    """
    if graph.number_of_edges() == 0:
        return ()

    raw_communities = nx.algorithms.community.louvain_communities(graph, weight="weight", seed=seed)
    candidates = tuple(frozenset(community) for community in raw_communities if len(community) >= min_size)

    logger.info(
        "community detection: %d raw communities, %d candidates at or above size %d",
        len(raw_communities), len(candidates), min_size,
    )
    return candidates
