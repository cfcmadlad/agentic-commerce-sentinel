"""Feature extraction over session traces, for the Day 4 behavioral layer.

Anti-rigging enforced structurally: every function takes a `SessionTrace`,
never a `LabeledSession`, so ground truth isn't reachable without a caller
deliberately unwrapping the label object.

Features are computed causally — each session sees only the agent/mandate
history that precedes it. A corpus-wide aggregate (e.g. per-agent mean
amount over the whole dataset) would leak future sessions into earlier ones.

Nothing here is a rule; Layers 1 and 2 own the deterministic verdict.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from common.schema import EventType, SessionTrace

logger = logging.getLogger(__name__)

# Used when a session has no prior history to compare against. Not 0 (reads
# as "just happened") and not NaN (some GBM implementations treat NaN as an
# informative category, turning "first session" into a feature by accident).
NO_HISTORY_SENTINEL_SECONDS = 30.0 * 24 * 3600

SECONDS_PER_HOUR = 3600.0


@dataclass
class _AgentHistory:
    """Running, causal history for one agent.

    Attributes:
        session_count: Sessions seen from this agent so far.
        last_started_at: Start time of the agent's most recent prior session.
        amount_sum: Sum of prior session amounts, for a running mean.
    """

    session_count: int = 0
    last_started_at: datetime | None = None
    amount_sum: float = 0.0


@dataclass
class FeatureExtractor:
    """Extracts causal features from a chronologically ordered session stream.

    Stateful: several features are relative to what the same agent or
    mandate did before. Construct one per run, feed sessions in ascending
    start-time order.

    Attributes:
        _agents: Per-agent running history.
        _mandate_last_used_at: Per-mandate time of most recent prior use.
        _mandate_use_count: Per-mandate count of prior uses.
    """

    _agents: dict[str, _AgentHistory] = field(default_factory=dict)
    _mandate_last_used_at: dict[UUID, datetime] = field(default_factory=dict)
    _mandate_use_count: dict[UUID, int] = field(default_factory=dict)

    def extract(self, trace: SessionTrace) -> dict[str, float]:
        """Computes the feature vector for one session, then absorbs it into history.

        Args:
            trace: The session to featurize, in chronological order relative
                to previous calls.

        Returns:
            Feature name to value. Keys are stable across calls.
        """
        features: dict[str, float] = {}
        features.update(_timing_features(trace))
        features.update(_composition_features(trace))
        features.update(self._history_features(trace))
        self._absorb(trace)
        return features

    def _history_features(self, trace: SessionTrace) -> dict[str, float]:
        """Computes features relative to prior agent and mandate activity.

        Args:
            trace: The session being featurized.

        Returns:
            The history-relative features.
        """
        agent = self._agents.get(trace.agent_id, _AgentHistory())
        seconds_since_agent = (
            (trace.started_at - agent.last_started_at).total_seconds()
            if agent.last_started_at is not None
            else NO_HISTORY_SENTINEL_SECONDS
        )
        prior_mean_amount = agent.amount_sum / agent.session_count if agent.session_count else 0.0
        amount_ratio = float(trace.amount) / prior_mean_amount if prior_mean_amount > 0 else 1.0

        if trace.mandate_id is None:
            seconds_since_mandate = NO_HISTORY_SENTINEL_SECONDS
            mandate_uses = 0
        else:
            last_use = self._mandate_last_used_at.get(trace.mandate_id)
            seconds_since_mandate = (
                (trace.started_at - last_use).total_seconds()
                if last_use is not None
                else NO_HISTORY_SENTINEL_SECONDS
            )
            mandate_uses = self._mandate_use_count.get(trace.mandate_id, 0)

        return {
            "hours_since_agent_last_session": max(seconds_since_agent, 0.0) / SECONDS_PER_HOUR,
            "hours_since_mandate_last_use": max(seconds_since_mandate, 0.0) / SECONDS_PER_HOUR,
            "agent_prior_session_count": float(agent.session_count),
            "mandate_prior_use_count": float(mandate_uses),
            "amount_over_agent_prior_mean": amount_ratio,
        }

    def _absorb(self, trace: SessionTrace) -> None:
        """Folds a session into the running history after featurizing it.

        Args:
            trace: The session to absorb.
        """
        agent = self._agents.setdefault(trace.agent_id, _AgentHistory())
        agent.session_count += 1
        agent.last_started_at = trace.started_at
        agent.amount_sum += float(trace.amount)

        if trace.mandate_id is not None:
            self._mandate_last_used_at[trace.mandate_id] = trace.started_at
            self._mandate_use_count[trace.mandate_id] = (
                self._mandate_use_count.get(trace.mandate_id, 0) + 1
            )


def _timing_features(trace: SessionTrace) -> dict[str, float]:
    """Computes features describing how the session was paced.

    Pacing separates a scripted client driving a genuine mandate from the
    agent it was issued to. Regularity matters as much as speed: a script
    with a fixed sleep is fast *and* metronomic, an agent waiting on real
    responses is neither — hence the coefficient of variation.

    Args:
        trace: The session being featurized.

    Returns:
        The timing features.
    """
    timestamps = [event.timestamp for event in trace.events]
    gaps = [
        (later - earlier).total_seconds()
        for earlier, later in zip(timestamps, timestamps[1:], strict=False)
    ]
    duration = (trace.completed_at - trace.started_at).total_seconds()

    if not gaps:
        return {
            "event_count": float(len(trace.events)),
            "duration_seconds": duration,
            "mean_event_gap_seconds": 0.0,
            "min_event_gap_seconds": 0.0,
            "max_event_gap_seconds": 0.0,
            "event_gap_cv": 0.0,
        }

    mean_gap = sum(gaps) / len(gaps)
    variance = sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)
    coefficient_of_variation = math.sqrt(variance) / mean_gap if mean_gap > 0 else 0.0

    return {
        "event_count": float(len(trace.events)),
        "duration_seconds": duration,
        "mean_event_gap_seconds": mean_gap,
        "min_event_gap_seconds": min(gaps),
        "max_event_gap_seconds": max(gaps),
        "event_gap_cv": coefficient_of_variation,
    }


def _composition_features(trace: SessionTrace) -> dict[str, float]:
    """Computes features describing what the session contained.

    Args:
        trace: The session being featurized.

    Returns:
        The composition features.
    """
    present = {event.event_type for event in trace.events}
    return {
        "has_catalog_browse": float(EventType.CATALOG_BROWSE in present),
        "has_cart_build": float(EventType.CART_BUILD in present),
        "has_mandate_presented": float(EventType.MANDATE_PRESENTED in present),
        "log_amount": math.log1p(float(trace.amount)),
        "hour_of_day": float(trace.started_at.hour),
        "day_of_week": float(trace.started_at.weekday()),
        "presented_a_mandate": float(trace.mandate_id is not None),
    }


def feature_names() -> tuple[str, ...]:
    """Lists the feature keys `FeatureExtractor.extract` produces, in stable order.

    Returns:
        Sorted feature names, so a design matrix has deterministic column
        order across runs and machines.
    """
    return tuple(
        sorted(
            {
                "event_count",
                "duration_seconds",
                "mean_event_gap_seconds",
                "min_event_gap_seconds",
                "max_event_gap_seconds",
                "event_gap_cv",
                "has_catalog_browse",
                "has_cart_build",
                "has_mandate_presented",
                "log_amount",
                "hour_of_day",
                "day_of_week",
                "presented_a_mandate",
                "hours_since_agent_last_session",
                "hours_since_mandate_last_use",
                "agent_prior_session_count",
                "mandate_prior_use_count",
                "amount_over_agent_prior_mean",
            }
        )
    )