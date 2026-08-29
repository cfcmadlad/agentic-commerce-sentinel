"""Evaluates collusion-ring detection: precision/recall on planted rings, false positives on negatives.

Matching a detected community back to ground truth uses two different bars,
deliberately asymmetric:

- A **planted malicious ring** counts as caught if some flagged community
  overlaps more than half of its members -- majority overlap, not exact
  match, so a ring that picked up one extra contaminating agent (or lost one
  to a merge) still counts as detected rather than being penalized twice for
  the same imprecision a precision metric already captures.
- A **legitimate hard-negative group** (household, shared gateway) or a
  **baseline agent** counts as a false positive if it appears in *any*
  flagged community at all, majority or not -- a single innocent agent
  swept into a flagged ring is exactly the cost this evaluation treats as
  first-class, not something a majority-overlap threshold should average
  away.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from collusion.detect import DEFAULT_RING_THRESHOLD, ScoredCandidate, score_candidates, verdicts_at_threshold
from collusion.schema import RingVerdict
from generator.collusion.corpus import CollusionCorpus
from generator.collusion.schema import (
    ARCHETYPE_LEGITIMATE_HOUSEHOLD,
    ARCHETYPE_LEGITIMATE_SHARED_GATEWAY,
    RingGroup,
)

logger = logging.getLogger(__name__)

# A planted ring counts as caught if a flagged community overlaps more than
# this fraction of its members. Strictly more than half, not "any overlap
# at all" -- a community sharing only a small minority of a ring's members
# is closer to coincidence than detection.
RING_MATCH_OVERLAP_FRACTION = 0.5

# Threshold values swept to report precision/recall across the operating
# range, matching detect/calibration.py's own sweep-not-single-point
# convention.
THRESHOLD_SWEEP_POINTS: tuple[float, ...] = (0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80)


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 on an empty denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 when the denominator is zero.
    """
    return numerator / denominator if denominator else 0.0


def _is_ring_caught(group: RingGroup, flagged: tuple[RingVerdict, ...]) -> bool:
    """Checks whether a planted ring is caught by majority-overlap matching.

    Args:
        group: The planted ring's ground truth.
        flagged: Every verdict `detect_rings` flagged.

    Returns:
        True iff some flagged community overlaps more than
        `RING_MATCH_OVERLAP_FRACTION` of the group's members.
    """
    for verdict in flagged:
        overlap = len(verdict.agent_ids & group.agent_ids)
        if overlap / len(group.agent_ids) > RING_MATCH_OVERLAP_FRACTION:
            return True
    return False


def _agents_in_any_flagged_community(flagged: tuple[RingVerdict, ...]) -> frozenset[str]:
    """Collects every agent appearing in any flagged verdict.

    Args:
        flagged: Every verdict `detect_rings` flagged.

    Returns:
        The union of every flagged community's members.
    """
    result: set[str] = set()
    for verdict in flagged:
        result |= verdict.agent_ids
    return frozenset(result)


@dataclass(frozen=True)
class CollusionEvaluationReport:
    """The full collusion-detection evaluation result at one threshold.

    Attributes:
        n_sessions: Total sessions in the evaluated corpus.
        n_malicious_rings: Planted malicious ring groups.
        n_household_negatives: Legitimate household hard-negative groups.
        n_shared_gateway_negatives: Legitimate shared-gateway hard-negative
            groups.
        n_baseline_agents: Ordinary independent legitimate agents.
        threshold: The operating threshold this report was computed at.
        ring_recall: Fraction of planted rings caught (majority-overlap
            matched to a flagged community).
        ring_precision: Fraction of flagged communities that correspond to
            an actual planted ring (majority-overlap matched).
        household_false_positive_rate: Fraction of household hard-negative
            groups with at least one member in a flagged community.
        shared_gateway_false_positive_rate: Fraction of shared-gateway
            hard-negative groups with at least one member in a flagged
            community.
        baseline_false_positive_rate: Fraction of ordinary independent
            baseline agents appearing in a flagged community.
        recall_by_archetype: Per-archetype recall among the three malicious
            archetypes.
    """

    n_sessions: int
    n_malicious_rings: int
    n_household_negatives: int
    n_shared_gateway_negatives: int
    n_baseline_agents: int
    threshold: float
    ring_recall: float
    ring_precision: float
    household_false_positive_rate: float
    shared_gateway_false_positive_rate: float
    baseline_false_positive_rate: float
    recall_by_archetype: dict[str, float]


def run_collusion_evaluation(
    corpus: CollusionCorpus,
    threshold: float = DEFAULT_RING_THRESHOLD,
    candidates: tuple[ScoredCandidate, ...] | None = None,
) -> CollusionEvaluationReport:
    """Runs detection over a collusion corpus and scores it against ground truth.

    Args:
        corpus: The corpus to evaluate, from
            `generator.collusion.corpus.build_collusion_corpus`.
        threshold: The operating threshold candidates are flagged at.
        candidates: Already-scored candidates from `collusion.detect.score_
            candidates`, for a caller evaluating the same corpus at several
            thresholds (see `sweep_thresholds`) that wants to avoid paying
            for graph construction and community detection more than once.
            Computed fresh from `corpus` when omitted.

    Returns:
        The full report.
    """
    if candidates is None:
        candidates = score_candidates(corpus.sessions, corpus.fingerprints)
    verdicts = verdicts_at_threshold(candidates, threshold)
    flagged = tuple(v for v in verdicts if v.flagged)

    malicious_groups = [g for g in corpus.groups if g.is_ring]
    household_groups = [g for g in corpus.groups if g.archetype == ARCHETYPE_LEGITIMATE_HOUSEHOLD]
    gateway_groups = [g for g in corpus.groups if g.archetype == ARCHETYPE_LEGITIMATE_SHARED_GATEWAY]

    caught = [g for g in malicious_groups if _is_ring_caught(g, flagged)]
    ring_recall = _safe_ratio(len(caught), len(malicious_groups))

    true_positive_verdicts = sum(
        1 for v in flagged if any(
            len(v.agent_ids & g.agent_ids) / len(g.agent_ids) > RING_MATCH_OVERLAP_FRACTION
            for g in malicious_groups
        )
    )
    ring_precision = _safe_ratio(true_positive_verdicts, len(flagged))

    flagged_agents = _agents_in_any_flagged_community(flagged)

    household_fp = sum(1 for g in household_groups if g.agent_ids & flagged_agents)
    household_fpr = _safe_ratio(household_fp, len(household_groups))

    gateway_fp = sum(1 for g in gateway_groups if g.agent_ids & flagged_agents)
    gateway_fpr = _safe_ratio(gateway_fp, len(gateway_groups))

    baseline_fp = len(corpus.baseline_agent_ids & flagged_agents)
    baseline_fpr = _safe_ratio(baseline_fp, len(corpus.baseline_agent_ids))

    recall_by_archetype: dict[str, float] = {}
    for archetype in sorted({g.archetype for g in malicious_groups}):
        archetype_groups = [g for g in malicious_groups if g.archetype == archetype]
        archetype_caught = [g for g in archetype_groups if _is_ring_caught(g, flagged)]
        recall_by_archetype[archetype] = _safe_ratio(len(archetype_caught), len(archetype_groups))

    logger.info(
        "collusion evaluation @ threshold=%.2f: ring_recall=%.4f ring_precision=%.4f "
        "household_fpr=%.4f gateway_fpr=%.4f baseline_fpr=%.4f",
        threshold, ring_recall, ring_precision, household_fpr, gateway_fpr, baseline_fpr,
    )

    return CollusionEvaluationReport(
        n_sessions=len(corpus.sessions),
        n_malicious_rings=len(malicious_groups),
        n_household_negatives=len(household_groups),
        n_shared_gateway_negatives=len(gateway_groups),
        n_baseline_agents=len(corpus.baseline_agent_ids),
        threshold=threshold,
        ring_recall=ring_recall,
        ring_precision=ring_precision,
        household_false_positive_rate=household_fpr,
        shared_gateway_false_positive_rate=gateway_fpr,
        baseline_false_positive_rate=baseline_fpr,
        recall_by_archetype=recall_by_archetype,
    )


def sweep_thresholds(
    corpus: CollusionCorpus, thresholds: tuple[float, ...] = THRESHOLD_SWEEP_POINTS
) -> tuple[CollusionEvaluationReport, ...]:
    """Evaluates the same corpus across a range of operating thresholds.

    Graph construction and community detection do not depend on the
    threshold at all -- only the final score comparison does -- so
    candidates are scored once and reused across every threshold point,
    rather than rebuilding the agent graph and re-running Louvain community
    detection once per threshold for work whose result cannot change.

    Args:
        corpus: The corpus to evaluate.
        thresholds: Threshold values to evaluate at.

    Returns:
        One report per threshold, in the given order.
    """
    candidates = score_candidates(corpus.sessions, corpus.fingerprints)
    return tuple(run_collusion_evaluation(corpus, threshold=t, candidates=candidates) for t in thresholds)


def format_collusion_report(report: CollusionEvaluationReport) -> str:
    """Renders one evaluation report as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        f"  threshold={report.threshold:.2f}",
        f"    ring recall              {report.ring_recall:.4f}  ({report.n_malicious_rings} planted rings)",
        f"    ring precision           {report.ring_precision:.4f}",
        f"    household FPR            {report.household_false_positive_rate:.4f}  "
        f"({report.n_household_negatives} groups)",
        f"    shared-gateway FPR       {report.shared_gateway_false_positive_rate:.4f}  "
        f"({report.n_shared_gateway_negatives} groups)",
        f"    baseline agent FPR       {report.baseline_false_positive_rate:.4f}  "
        f"({report.n_baseline_agents} agents)",
    ]
    if report.recall_by_archetype:
        lines.append("    recall by archetype:")
        for archetype, recall in sorted(report.recall_by_archetype.items()):
            lines.append(f"      {archetype:<28} {recall:.4f}")
    return "\n".join(lines)
