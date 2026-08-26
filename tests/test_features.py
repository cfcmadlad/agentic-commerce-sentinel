"""Tests for `features.session`: causality, determinism, and label isolation."""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

from common.schema import EventType, SessionEvent, SessionTrace
from features import session as session_features
from features.session import FeatureExtractor, feature_names
from generator.attacks.corpus import build_evaluation_corpus
from tests.factories import REFERENCE_NOW


def _trace(gaps_seconds: list[int], **overrides: object) -> SessionTrace:
    """Builds a trace whose events are separated by the given gaps.

    Args:
        gaps_seconds: Gap in seconds before each event after the first.
        **overrides: Field values to override.

    Returns:
        The session trace.
    """
    stages = [
        EventType.INTENT_CAPTURED,
        EventType.MANDATE_PRESENTED,
        EventType.CATALOG_BROWSE,
        EventType.CART_BUILD,
        EventType.PAYMENT_ATTEMPT,
        EventType.PAYMENT_RESULT,
    ][: len(gaps_seconds) + 1]
    current = REFERENCE_NOW
    events = [SessionEvent(event_type=stages[0], timestamp=current)]
    for stage, gap in zip(stages[1:], gaps_seconds, strict=False):
        current = current + timedelta(seconds=gap)
        events.append(SessionEvent(event_type=stage, timestamp=current))
    defaults: dict[str, object] = {
        "session_id": uuid4(),
        "agent_id": "agent-001",
        "user_id": "user-0001",
        "mandate_id": uuid4(),
        "merchant_id": "bigbasket",
        "merchant_category": "grocery",
        "item_category": "packaged_food",
        "amount": Decimal("450.00"),
        "currency": "INR",
        "events": events,
        "started_at": REFERENCE_NOW,
        "completed_at": events[-1].timestamp,
    }
    defaults.update(overrides)
    return SessionTrace(**defaults)  # type: ignore[arg-type]


def test_feature_keys_match_declared_names() -> None:
    """The declared column order must match what the extractor actually emits."""
    features = FeatureExtractor().extract(_trace([5, 5, 5, 5, 5]))
    assert tuple(sorted(features)) == feature_names()


def test_regular_pacing_yields_low_variation() -> None:
    """A metronomic session must score near zero on the pacing-variation feature."""
    features = FeatureExtractor().extract(_trace([3, 3, 3, 3, 3]))
    assert features["event_gap_cv"] == 0.0


def test_irregular_pacing_yields_higher_variation() -> None:
    """A jittered session must score above a metronomic one on the same feature."""
    regular = FeatureExtractor().extract(_trace([3, 3, 3, 3, 3]))
    jittered = FeatureExtractor().extract(_trace([2, 40, 7, 31, 5]))
    assert jittered["event_gap_cv"] > regular["event_gap_cv"]


def test_missing_browse_stage_is_recorded() -> None:
    """A session with no catalog-browse event must be flagged as such."""
    trace = _trace([4, 4, 4])
    features = FeatureExtractor().extract(trace)
    present = {e.event_type for e in trace.events}
    assert features["has_catalog_browse"] == float(EventType.CATALOG_BROWSE in present)


def test_first_session_uses_the_no_history_sentinel() -> None:
    """An agent's first session must not read as having just acted."""
    features = FeatureExtractor().extract(_trace([5, 5, 5, 5, 5]))
    assert features["agent_prior_session_count"] == 0.0
    assert features["hours_since_agent_last_session"] == (
        session_features.NO_HISTORY_SENTINEL_SECONDS / session_features.SECONDS_PER_HOUR
    )


def test_history_features_are_causal() -> None:
    """A session must see only history that precedes it.

    Feeding the same session first and second must give different history
    features; if it did not, aggregates would be leaking across time.
    """
    extractor = FeatureExtractor()
    mandate_id = uuid4()
    first = _trace([5, 5, 5, 5, 5], mandate_id=mandate_id)
    later_start = REFERENCE_NOW + timedelta(hours=2)
    second = _trace(
        [5, 5, 5, 5, 5],
        mandate_id=mandate_id,
        started_at=later_start,
        completed_at=later_start + timedelta(minutes=1),
        events=[
            SessionEvent(event_type=EventType.INTENT_CAPTURED, timestamp=later_start),
            SessionEvent(
                event_type=EventType.PAYMENT_RESULT, timestamp=later_start + timedelta(minutes=1)
            ),
        ],
    )
    extractor.extract(first)
    features = extractor.extract(second)
    assert features["agent_prior_session_count"] == 1.0
    assert features["mandate_prior_use_count"] == 1.0
    assert features["hours_since_mandate_last_use"] == 2.0


def test_extraction_is_deterministic_over_a_generated_corpus() -> None:
    """Two extractor runs over the same corpus must produce identical matrices."""
    corpus = build_evaluation_corpus(400, seed=5)
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    first = [FeatureExtractor().extract(t) for t in traces]
    second = [FeatureExtractor().extract(t) for t in traces]
    assert first == second


def test_module_never_references_ground_truth() -> None:
    """Anti-rigging, checked mechanically rather than by convention.

    Parsed as code, not grepped as text: this is about what the module can
    actually reach, not which words appear in its prose.
    """
    tree = ast.parse(inspect.getsource(session_features))
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.alias):
            identifiers.add(node.name)
            if node.asname:
                identifiers.add(node.asname)
    forbidden = {"attack_class", "is_attack", "LabeledSession", "AttackClass"}
    assert not (identifiers & forbidden), (
        f"feature module can reach ground truth via {identifiers & forbidden}"
    )