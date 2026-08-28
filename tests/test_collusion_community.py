"""Tests for `collusion.community`: Louvain partitioning and size filtering."""

from __future__ import annotations

import networkx as nx  # type: ignore[import-untyped]

from collusion.community import detect_communities


def test_empty_graph_produces_no_communities() -> None:
    """A graph with no edges at all has no candidate rings."""
    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(["a", "b", "c"])
    assert detect_communities(graph) == ()


def test_two_separate_cliques_are_detected_as_two_communities() -> None:
    """A clearly separated graph must partition into its obvious components."""
    graph: nx.Graph = nx.Graph()
    graph.add_edge("a", "b", weight=1.0)
    graph.add_edge("b", "c", weight=1.0)
    graph.add_edge("a", "c", weight=1.0)
    graph.add_edge("x", "y", weight=1.0)
    graph.add_edge("y", "z", weight=1.0)
    graph.add_edge("x", "z", weight=1.0)
    communities = detect_communities(graph)
    assert len(communities) == 2
    assert frozenset({"a", "b", "c"}) in communities
    assert frozenset({"x", "y", "z"}) in communities


def test_min_size_filters_out_pairs() -> None:
    """A community below the minimum size must be dropped."""
    graph: nx.Graph = nx.Graph()
    graph.add_edge("a", "b", weight=1.0)
    communities = detect_communities(graph, min_size=3)
    assert communities == ()


def test_isolated_node_never_appears_in_a_community() -> None:
    """A node with no edges at all cannot be part of any candidate ring."""
    graph: nx.Graph = nx.Graph()
    graph.add_edge("a", "b", weight=1.0)
    graph.add_edge("b", "c", weight=1.0)
    graph.add_node("isolated")
    communities = detect_communities(graph)
    for community in communities:
        assert "isolated" not in community


def test_detection_is_reproducible_with_the_same_seed() -> None:
    """The same graph and seed must always partition identically."""
    graph: nx.Graph = nx.Graph()
    for a, b in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a"), ("a", "c")]:
        graph.add_edge(a, b, weight=1.0)
    first = detect_communities(graph, seed=99)
    second = detect_communities(graph, seed=99)
    assert first == second
