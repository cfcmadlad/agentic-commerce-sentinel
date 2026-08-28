"""Risk scoring for one candidate community.

Two signals, combined:

- **Fingerprint signal** -- how many distinct agents in the community share
  one device fingerprint, saturating as that count grows. Deliberately
  *not* just "any two agents share a device": a small household sharing one
  home device is common and legitimate, so the signal is a function of how
  many "independent" identities pile onto one fingerprint, not merely
  whether any do at all.
- **Structuring ratio** -- the largest amount transacted with one shared
  counterparty inside one coordination window, *by multiple distinct
  members of the community* -- moved from `common.schema.SessionTrace`'s
  own amounts, requiring more than one agent's contribution is deliberate:
  without it, one member's own single large purchase (log-normal amounts
  occasionally land well above the median on their own) reads as
  "structuring" even with zero coordination, which is exactly the false
  positive this milestone's brief warns against. Found and fixed during
  this milestone's own calibration -- see `docs/adr/0006`.

Both are computed directly from `SessionTrace` and the session-keyed
fingerprint mapping -- never from ground truth. Weights and saturation
points are named constants, not magic numbers, checked against a real
evaluation sweep rather than asserted correct by inspection, the same way
`detect/calibration.py`'s cost ratio is.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from uuid import UUID

from collusion.graph import DEFAULT_MIN_BURST_AGENTS
from collusion.schema import RingScore
from common.schema import SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint
from generator.config import CATEGORY_CONFIGS

# Relative weight of each signal in the combined score. Equal by default --
# neither signal is treated as inherently more trustworthy than the other,
# since two of the three malicious archetypes this project generates are
# deliberately built so that each signal alone catches a different one of
# them (see generator/collusion/rings.py's own module docstring).
FINGERPRINT_WEIGHT = 0.5
STRUCTURING_WEIGHT = 0.5

# A fingerprint shared by this many or more distinct agents saturates the
# fingerprint signal to 1.0. Two agents sharing one device (the minimum this
# signal registers at all) is treated as the weakest possible reading, not
# the strongest -- a household plausibly reaches 2-3; a cluster of
# "independent" identities piling onto one device well beyond a plausible
# family size is the stronger, size-driven tell.
FINGERPRINT_SIZE_SATURATION = 6

# A structuring_ratio at or above this saturates the normalized structuring
# component to 1.0 -- moving several times a typical single-session amount
# through one counterparty inside one coordination window is already an
# extreme signal; a ratio of 50 is not five times more suspicious than a
# ratio of 5, so the score does not grow unbounded with it.
STRUCTURING_SATURATION_RATIO = 5.0

# Minimum distinct agents that must contribute to one coordinated window for
# it to count as structuring at all. Deliberately the *same* constant as
# `collusion/graph.py::DEFAULT_MIN_BURST_AGENTS`, imported rather than
# redefined, so the two can never silently drift apart: one agent's own
# session, however large, is not structuring by any number of agents'
# definition, and that threshold should mean the same thing wherever this
# package uses it -- edge formation and structuring scoring alike.
MIN_STRUCTURING_AGENTS = DEFAULT_MIN_BURST_AGENTS

# Used only if a merchant is somehow absent from the catalog, which should
# not happen for any merchant this project's own generators produce.
_FALLBACK_REFERENCE_AMOUNT = Decimal("1000.00")

_REFERENCE_AMOUNT_BY_MERCHANT: dict[str, Decimal] = {
    merchant_id: category.amount_median
    for category in CATEGORY_CONFIGS
    for merchant_id in category.merchant_ids
}


def _fingerprint_signal(
    agent_ids: frozenset[str],
    sessions_by_agent: Mapping[str, Sequence[SessionTrace]],
    fingerprints: Mapping[UUID, DeviceFingerprint],
) -> float:
    """Computes how much the community looks like several identities sharing one device.

    Args:
        agent_ids: The community's members.
        sessions_by_agent: Every session, grouped by agent ID.
        fingerprints: Device fingerprint observed for each session.

    Returns:
        0.0 if no fingerprint is shared by at least two community members;
        otherwise a value in (0, 1] driven by the largest number of distinct
        agents sharing any single fingerprint, saturating at
        `FINGERPRINT_SIZE_SATURATION`.
    """
    agents_by_fingerprint: dict[DeviceFingerprint, set[str]] = {}
    for agent_id in agent_ids:
        for session in sessions_by_agent.get(agent_id, ()):
            fingerprint = fingerprints.get(session.session_id)
            if fingerprint is not None:
                agents_by_fingerprint.setdefault(fingerprint, set()).add(agent_id)

    max_shared = max((len(agents) for agents in agents_by_fingerprint.values()), default=0)
    if max_shared < 2:
        return 0.0
    span = FINGERPRINT_SIZE_SATURATION - 1
    return min((max_shared - 1) / span, 1.0) if span > 0 else 1.0


def _peak_coordinated_spend(
    sessions: Sequence[SessionTrace], coordination_window: timedelta, min_agents: int
) -> tuple[Decimal, str | None]:
    """Finds the largest multi-agent amount transacted with one counterparty inside one window.

    Args:
        sessions: Every session belonging to the community's members.
        coordination_window: The window width to sum spend inside.
        min_agents: Minimum distinct agents that must contribute to a
            window for it to be considered -- a window driven by only one
            agent's own sessions is not structuring, however large.

    Returns:
        A tuple of (peak combined amount, the merchant it was transacted
        with) -- `(Decimal("0"), None)` if no qualifying window exists.
    """
    sessions_by_merchant: dict[str, list[SessionTrace]] = {}
    for session in sessions:
        sessions_by_merchant.setdefault(session.merchant_id, []).append(session)

    best_amount = Decimal("0")
    best_merchant: str | None = None
    for merchant_id, group in sessions_by_merchant.items():
        ordered = sorted(group, key=lambda s: s.started_at)
        left = 0
        window_sum = Decimal("0")
        for right in range(len(ordered)):
            window_sum += ordered[right].amount
            while ordered[right].started_at - ordered[left].started_at > coordination_window:
                window_sum -= ordered[left].amount
                left += 1
            distinct_agents = {ordered[k].agent_id for k in range(left, right + 1)}
            if len(distinct_agents) >= min_agents and window_sum > best_amount:
                best_amount = window_sum
                best_merchant = merchant_id
    return best_amount, best_merchant


def score_community(
    agent_ids: frozenset[str],
    sessions_by_agent: Mapping[str, Sequence[SessionTrace]],
    fingerprints: Mapping[UUID, DeviceFingerprint],
    coordination_window: timedelta,
) -> RingScore:
    """Computes the risk score for one candidate community.

    Args:
        agent_ids: The community's members.
        sessions_by_agent: Every session in the corpus, grouped by agent ID.
        fingerprints: Device fingerprint observed for each session.
        coordination_window: The window width the structuring signal sums
            spend inside -- the same window `collusion.graph.build_agent_
            graph` used to form counterparty edges, so the score is
            consistent with why the community was surfaced in the first
            place.

    Returns:
        The computed score.
    """
    fingerprint_signal = _fingerprint_signal(agent_ids, sessions_by_agent, fingerprints)

    community_sessions = [
        session for agent_id in agent_ids for session in sessions_by_agent.get(agent_id, ())
    ]
    peak_amount, peak_merchant = _peak_coordinated_spend(
        community_sessions, coordination_window, MIN_STRUCTURING_AGENTS
    )
    reference = (
        _REFERENCE_AMOUNT_BY_MERCHANT.get(peak_merchant, _FALLBACK_REFERENCE_AMOUNT)
        if peak_merchant is not None
        else _FALLBACK_REFERENCE_AMOUNT
    )
    structuring_ratio = float(peak_amount / reference) if peak_amount > 0 else 0.0
    normalized_structuring = min(structuring_ratio / STRUCTURING_SATURATION_RATIO, 1.0)

    combined = FINGERPRINT_WEIGHT * fingerprint_signal + STRUCTURING_WEIGHT * normalized_structuring
    return RingScore(
        fingerprint_signal=fingerprint_signal,
        structuring_ratio=structuring_ratio,
        combined=combined,
    )
