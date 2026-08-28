"""Shared types for graph-based collusion detection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RingScore:
    """The computed risk score for one candidate community.

    Attributes:
        fingerprint_signal: How much the community looks like several
            identities sharing one device -- 0.0 if no fingerprint is
            shared by at least two members, otherwise a value in (0, 1]
            driven by the largest number of distinct agents sharing any one
            fingerprint, saturating as that count grows past a plausible
            household size (see `collusion/scoring.py::
            FINGERPRINT_SIZE_SATURATION`).
        structuring_ratio: The peak combined amount transacted with one
            shared counterparty inside a single coordination window, *by
            multiple distinct community members*, divided by that
            counterparty's category's typical single-session amount. A
            window driven by only one agent's own sessions never counts,
            however large -- see `collusion/scoring.py::
            MIN_STRUCTURING_AGENTS`. Values well above 1 mean the group
            moved several times a typical single transaction through one
            counterparty in one short window.
        combined: The weighted combination of the two signals above -- what
            `collusion.detect.detect_rings` thresholds against.
    """

    fingerprint_signal: float
    structuring_ratio: float
    combined: float


@dataclass(frozen=True)
class RingVerdict:
    """The detection outcome for one candidate community.

    Attributes:
        agent_ids: The community's member agents.
        score: The computed risk score.
        flagged: True iff `score.combined` reached the operating threshold.
    """

    agent_ids: frozenset[str]
    score: RingScore
    flagged: bool
