"""Tests for `collusion.graph`: edge formation from fingerprints and coordinated bursts."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from collusion.graph import GraphBuildConfig, build_agent_graph
from common.schema import EventType, SessionEvent, SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint
from tests.factories import REFERENCE_NOW


def _session(agent_id: str, merchant_id: str, started_at: datetime, amount: str = "500.00") -> SessionTrace:
    """Builds a minimal session for graph-construction tests.

    Args:
        agent_id: The presenting agent.
        merchant_id: The counterparty.
        started_at: Session start timestamp.
        amount: Transaction amount as a string.

    Returns:
        A valid session trace.
    """
    return SessionTrace(
        session_id=uuid4(),
        agent_id=agent_id,
        user_id=f"user-{agent_id}",
        mandate_id=uuid4(),
        merchant_id=merchant_id,
        merchant_category="grocery",
        item_category="packaged_food",
        amount=Decimal(amount),
        currency="INR",
        events=[SessionEvent(event_type=EventType.PAYMENT_RESULT, timestamp=started_at)],
        started_at=started_at,
        completed_at=started_at,
    )


def test_shared_fingerprint_forms_an_edge_regardless_of_timing() -> None:
    """Two agents sharing a device must be linked even with unrelated timing."""
    fp = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    s1 = _session("agent-a", "merchant-x", REFERENCE_NOW)
    s2 = _session("agent-b", "merchant-y", REFERENCE_NOW + timedelta(days=10))
    graph = build_agent_graph([s1, s2], {s1.session_id: fp, s2.session_id: fp})
    assert graph.has_edge("agent-a", "agent-b")
    assert graph["agent-a"]["agent-b"]["fingerprint_count"] == 1
    assert graph["agent-a"]["agent-b"]["counterparty_count"] == 0


def test_distinct_fingerprints_never_form_an_edge() -> None:
    """Two agents with their own distinct devices, no counterparty overlap, must not be linked."""
    fp1 = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    fp2 = DeviceFingerprint(device_id="d2", ip_address="5.6.7.8")
    s1 = _session("agent-a", "merchant-x", REFERENCE_NOW)
    s2 = _session("agent-b", "merchant-y", REFERENCE_NOW)
    graph = build_agent_graph([s1, s2], {s1.session_id: fp1, s2.session_id: fp2})
    assert not graph.has_edge("agent-a", "agent-b")


def test_two_agent_burst_below_min_size_forms_no_edge() -> None:
    """Two agents converging on one merchant in a tight window, alone, is not enough."""
    fps = {}
    sessions = []
    for i, agent in enumerate(["agent-a", "agent-b"]):
        s = _session(agent, "merchant-x", REFERENCE_NOW + timedelta(minutes=i))
        sessions.append(s)
        fps[s.session_id] = DeviceFingerprint(device_id=f"d{i}", ip_address=f"1.2.3.{i}")
    graph = build_agent_graph(sessions, fps, GraphBuildConfig(min_burst_agents=3))
    assert not graph.has_edge("agent-a", "agent-b")


def test_four_agent_burst_forms_edges_among_all_members() -> None:
    """A genuine multi-agent burst at one merchant must fully connect its members."""
    fps = {}
    sessions = []
    for i, agent in enumerate(["agent-a", "agent-b", "agent-c", "agent-d"]):
        s = _session(agent, "merchant-x", REFERENCE_NOW + timedelta(minutes=i))
        sessions.append(s)
        fps[s.session_id] = DeviceFingerprint(device_id=f"d{i}", ip_address=f"1.2.3.{i}")
    graph = build_agent_graph(sessions, fps, GraphBuildConfig(min_burst_agents=4))
    for a in ["agent-a", "agent-b", "agent-c", "agent-d"]:
        for b in ["agent-a", "agent-b", "agent-c", "agent-d"]:
            if a != b:
                assert graph.has_edge(a, b)


def test_burst_beyond_the_window_is_split_in_two() -> None:
    """A burst chained beyond the coordination window must not link across the gap."""
    fps = {}
    sessions = []
    # Four agents close together (a genuine burst)...
    for i, agent in enumerate(["agent-a", "agent-b", "agent-c", "agent-d"]):
        s = _session(agent, "merchant-x", REFERENCE_NOW + timedelta(minutes=i))
        sessions.append(s)
        fps[s.session_id] = DeviceFingerprint(device_id=f"d{i}", ip_address=f"1.2.3.{i}")
    # ...then one agent well outside the window.
    late = _session("agent-e", "merchant-x", REFERENCE_NOW + timedelta(hours=5))
    sessions.append(late)
    fps[late.session_id] = DeviceFingerprint(device_id="d-late", ip_address="9.9.9.9")

    graph = build_agent_graph(
        sessions, fps, GraphBuildConfig(coordination_window=timedelta(minutes=10), min_burst_agents=4)
    )
    assert not graph.has_edge("agent-a", "agent-e")
    assert not graph.has_edge("agent-e", "agent-b")


def test_agent_with_no_sessions_shares_no_edges_but_still_a_node() -> None:
    """Every distinct agent_id in the input must appear as a node, even if isolated."""
    fp = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    s1 = _session("agent-a", "merchant-x", REFERENCE_NOW)
    graph = build_agent_graph([s1], {s1.session_id: fp})
    assert "agent-a" in graph.nodes
    assert graph.number_of_edges() == 0


def test_missing_fingerprint_entry_contributes_no_fingerprint_edge() -> None:
    """A session absent from the fingerprint mapping must not silently error or link."""
    s1 = _session("agent-a", "merchant-x", REFERENCE_NOW)
    s2 = _session("agent-b", "merchant-y", REFERENCE_NOW)
    graph = build_agent_graph([s1, s2], {})
    assert not graph.has_edge("agent-a", "agent-b")


def test_build_agent_graph_is_pure() -> None:
    """Repeated calls with the same inputs must give the same graph structure."""
    fp = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    s1 = _session("agent-a", "merchant-x", REFERENCE_NOW)
    s2 = _session("agent-b", "merchant-y", REFERENCE_NOW)
    fingerprints = {s1.session_id: fp, s2.session_id: fp}
    g1 = build_agent_graph([s1, s2], fingerprints)
    g2 = build_agent_graph([s1, s2], fingerprints)
    assert sorted(g1.edges()) == sorted(g2.edges())
    assert sorted(g1.nodes()) == sorted(g2.nodes())
