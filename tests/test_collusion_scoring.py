"""Tests for `collusion.scoring`: the fingerprint and structuring signals."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from collusion.graph import DEFAULT_MIN_BURST_AGENTS
from collusion.scoring import FINGERPRINT_SIZE_SATURATION, MIN_STRUCTURING_AGENTS, score_community
from common.schema import EventType, SessionEvent, SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint
from tests.factories import REFERENCE_NOW


def _session(agent_id: str, merchant_id: str, started_at: datetime, amount: str) -> SessionTrace:
    """Builds a minimal session for scoring tests.

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


def test_no_shared_fingerprint_and_no_structuring_scores_zero() -> None:
    """A community with neither signal at all must score exactly zero."""
    sessions_by_agent = {
        "a": [_session("a", "m1", REFERENCE_NOW, "500.00")],
        "b": [_session("b", "m2", REFERENCE_NOW + timedelta(days=5), "600.00")],
    }
    score = score_community(frozenset({"a", "b"}), sessions_by_agent, {}, timedelta(minutes=10))
    assert score.combined == 0.0
    assert score.fingerprint_signal == 0.0
    assert score.structuring_ratio == 0.0


def test_single_agent_large_purchase_is_not_structuring() -> None:
    """One agent's own large session must never register as structuring, regardless of size."""
    huge = _session("a", "m1", REFERENCE_NOW, "100000.00")
    sessions_by_agent = {"a": [huge], "b": [_session("b", "m2", REFERENCE_NOW, "500.00")]}
    score = score_community(frozenset({"a", "b"}), sessions_by_agent, {}, timedelta(minutes=10))
    assert score.structuring_ratio == 0.0


def test_multi_agent_burst_registers_as_structuring() -> None:
    """A genuine multi-agent convergence on one merchant must register nonzero structuring."""
    sessions_by_agent = {}
    for i, agent in enumerate(["a", "b", "c", "d"]):
        sessions_by_agent[agent] = [
            _session(agent, "m1", REFERENCE_NOW + timedelta(minutes=i), "4000.00")
        ]
    score = score_community(
        frozenset(sessions_by_agent), sessions_by_agent, {}, timedelta(minutes=10)
    )
    assert score.structuring_ratio > 0.0


def test_fingerprint_signal_saturates_at_the_configured_group_size() -> None:
    """A fingerprint shared by the saturation count must score exactly 1.0."""
    fp = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    sessions_by_agent = {}
    fingerprints = {}
    for i in range(FINGERPRINT_SIZE_SATURATION):
        agent = f"agent-{i}"
        session = _session(agent, f"m{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions_by_agent[agent] = [session]
        fingerprints[session.session_id] = fp
    score = score_community(frozenset(sessions_by_agent), sessions_by_agent, fingerprints, timedelta(minutes=10))
    assert score.fingerprint_signal == 1.0


def test_fingerprint_signal_below_saturation_is_partial_not_full() -> None:
    """A small shared-device group (household-sized) must score below full saturation."""
    fp = DeviceFingerprint(device_id="d1", ip_address="1.2.3.4")
    sessions_by_agent = {}
    fingerprints = {}
    for i, agent in enumerate(["a", "b", "c"]):
        session = _session(agent, f"m{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions_by_agent[agent] = [session]
        fingerprints[session.session_id] = fp
    score = score_community(frozenset(sessions_by_agent), sessions_by_agent, fingerprints, timedelta(minutes=10))
    assert 0.0 < score.fingerprint_signal < 1.0


def test_structuring_agent_threshold_matches_burst_edge_threshold() -> None:
    """The two 'how many agents makes this coordinated' constants must never drift apart.

    `collusion/scoring.py::MIN_STRUCTURING_AGENTS` is imported from
    `collusion/graph.py::DEFAULT_MIN_BURST_AGENTS`, not independently
    redefined -- otherwise edges could form under one multi-agent threshold
    while structuring scoring evaluates under a different one.
    """
    assert MIN_STRUCTURING_AGENTS == DEFAULT_MIN_BURST_AGENTS


def test_score_community_is_pure() -> None:
    """Repeated calls with the same inputs must give the same score."""
    sessions_by_agent = {"a": [_session("a", "m1", REFERENCE_NOW, "500.00")]}
    first = score_community(frozenset({"a"}), sessions_by_agent, {}, timedelta(minutes=10))
    second = score_community(frozenset({"a"}), sessions_by_agent, {}, timedelta(minutes=10))
    assert first == second
