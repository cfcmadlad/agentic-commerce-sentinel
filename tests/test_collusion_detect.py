"""Tests for `collusion.detect.detect_rings`: the full orchestration."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from collusion.detect import detect_rings, score_candidates, verdicts_at_threshold
from common.schema import EventType, SessionEvent, SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint
from tests.factories import REFERENCE_NOW


def _session(agent_id: str, merchant_id: str, started_at: datetime, amount: str) -> SessionTrace:
    """Builds a minimal session for detection tests.

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


def test_no_sessions_produce_no_verdicts() -> None:
    """An empty session stream has nothing to detect."""
    assert detect_rings([], {}) == ()


def test_fully_independent_agents_produce_no_flagged_verdict() -> None:
    """Agents with distinct fingerprints and no counterparty overlap must never be flagged."""
    sessions = []
    fingerprints = {}
    for i in range(5):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = DeviceFingerprint(device_id=f"d{i}", ip_address=f"1.1.1.{i}")
    verdicts = detect_rings(sessions, fingerprints)
    assert all(not v.flagged for v in verdicts)


def test_a_planted_shared_fingerprint_ring_is_flagged() -> None:
    """Several agents sharing one device with no other signal must still be flagged."""
    fp = DeviceFingerprint(device_id="shared", ip_address="9.9.9.9")
    sessions = []
    fingerprints = {}
    for i in range(6):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = fp
    verdicts = detect_rings(sessions, fingerprints)
    assert len(verdicts) == 1
    assert verdicts[0].flagged
    assert verdicts[0].agent_ids == frozenset(f"agent-{i}" for i in range(6))


def test_a_planted_structuring_burst_is_flagged() -> None:
    """Several agents converging small amounts on one merchant in a tight window must be flagged."""
    sessions = []
    fingerprints = {}
    for i in range(4):
        s = _session("agent-" + str(i), "merchant-shared", REFERENCE_NOW + timedelta(minutes=i), "4000.00")
        sessions.append(s)
        fingerprints[s.session_id] = DeviceFingerprint(device_id=f"d{i}", ip_address=f"2.2.2.{i}")
    verdicts = detect_rings(sessions, fingerprints)
    assert len(verdicts) == 1
    assert verdicts[0].flagged


def test_threshold_controls_flagging() -> None:
    """A threshold above every candidate's score must flag nothing."""
    fp = DeviceFingerprint(device_id="shared", ip_address="9.9.9.9")
    sessions = []
    fingerprints = {}
    for i in range(6):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = fp
    verdicts = detect_rings(sessions, fingerprints, threshold=1.1)
    assert all(not v.flagged for v in verdicts)


def test_detect_rings_is_reproducible() -> None:
    """The same session stream must always produce the same verdicts."""
    fp = DeviceFingerprint(device_id="shared", ip_address="9.9.9.9")
    sessions = []
    fingerprints = {}
    for i in range(6):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = fp
    first = detect_rings(sessions, fingerprints)
    second = detect_rings(sessions, fingerprints)
    assert first == second


def test_score_candidates_plus_verdicts_at_threshold_matches_detect_rings() -> None:
    """The split (threshold-independent scoring, then thresholding) must match the single-shot call.

    This is the regression test for the efficiency fix that lets a caller
    score candidates once and reuse them across several thresholds
    (`eval/collusion_evaluation.py::sweep_thresholds`) instead of rebuilding
    the agent graph and re-running Louvain per threshold: the two code paths
    must be equivalent, not just individually correct.
    """
    fp = DeviceFingerprint(device_id="shared", ip_address="9.9.9.9")
    sessions = []
    fingerprints = {}
    for i in range(6):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = fp

    for threshold in (0.10, 0.30, 0.50, 0.80):
        via_detect_rings = detect_rings(sessions, fingerprints, threshold=threshold)
        candidates = score_candidates(sessions, fingerprints)
        via_split = verdicts_at_threshold(candidates, threshold)
        assert via_detect_rings == via_split


def test_score_candidates_is_reused_without_recomputation() -> None:
    """Scoring once and thresholding twice must not rebuild the graph a second time.

    Confirms `score_candidates` is genuinely threshold-independent: calling
    it once and applying `verdicts_at_threshold` at two different
    thresholds must produce results consistent with each threshold, using
    the identical underlying candidate scores (not two separately computed
    scorings that happen to agree).
    """
    fp = DeviceFingerprint(device_id="shared", ip_address="9.9.9.9")
    sessions = []
    fingerprints = {}
    for i in range(6):
        s = _session(f"agent-{i}", f"merchant-{i}", REFERENCE_NOW + timedelta(days=i), "500.00")
        sessions.append(s)
        fingerprints[s.session_id] = fp

    candidates = score_candidates(sessions, fingerprints)
    low_threshold = verdicts_at_threshold(candidates, 0.10)
    high_threshold = verdicts_at_threshold(candidates, 0.90)

    assert [v.score for v in low_threshold] == [v.score for v in high_threshold]
    assert any(v.flagged for v in low_threshold)
    assert not any(v.flagged for v in high_threshold)
