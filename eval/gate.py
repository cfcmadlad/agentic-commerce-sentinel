"""Evaluation of the rules-only baseline (Layer 1 + Layer 2), no ML.

Answers one question: are the generated attacks separable enough by rules
alone that a model would add nothing, or hard enough that a model has room
to earn its place. The full evaluation apparatus (AUC-PR, bootstrap CIs,
DeLong, McNemar, calibration, cost sweep) lives elsewhere in /eval; a rules
engine has one operating point, so a threshold sweep here would be theatre.

The metric that actually matters isn't aggregate recall — it's recall on the
rules-invisible variants (rapid-reuse replay, behavioral-only impersonation).
Those should sit near zero for a correct baseline; if they're high, something
is leaking.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from uuid import UUID

from common.schema import AttackClass, LabeledSession
from detect.baseline import BaselineDecision, RulesOnlyBaseline
from generator.attacks.corpus import EvaluationCorpus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClassBreakdown:
    """Detection outcome for one ground-truth attack class.

    Attributes:
        attack_class: The class described.
        total: Sessions of this class in the corpus.
        caught: How many the baseline blocked.
        recall: `caught / total`.
        recall_by_variant: Per-variant recall within the class — a class
            average hides exactly what matters here.
    """

    attack_class: AttackClass
    total: int
    caught: int
    recall: float
    recall_by_variant: dict[str, float]


@dataclass(frozen=True)
class GateReport:
    """Full precision/recall summary of the rules-only baseline over a corpus.

    Attributes:
        n_sessions: Corpus size.
        attack_base_rate: Realized fraction of attack sessions.
        true_positives: Attacks blocked.
        false_positives: Legitimate sessions blocked.
        true_negatives: Legitimate sessions allowed.
        false_negatives: Attacks allowed.
        precision: Of everything blocked, the fraction that was an attack.
        recall: Of every attack, the fraction blocked.
        per_class: Breakdown by ground-truth attack class.
        fired_rule_counts: How often each named rule fired.
        false_positive_rules: Rules that fired on legitimate sessions — where
            a rules bug shows up first.
    """

    n_sessions: int
    attack_base_rate: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    per_class: tuple[ClassBreakdown, ...]
    fired_rule_counts: dict[str, int]
    false_positive_rules: dict[str, int]


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 rather than raising on a zero denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 if `denominator` is zero.
    """
    return numerator / denominator if denominator else 0.0


def _breakdown(
    attack_class: AttackClass,
    sessions: list[LabeledSession],
    blocked: dict[str, bool],
    variant_by_session: dict[UUID, str],
) -> ClassBreakdown:
    """Builds the per-class and per-variant detection breakdown.

    Args:
        attack_class: The class being summarized.
        sessions: Sessions of that class.
        blocked: Session ID string to whether the baseline blocked it.
        variant_by_session: Session ID to attack sub-variant.

    Returns:
        The breakdown.
    """
    caught = sum(1 for s in sessions if blocked[str(s.trace.session_id)])
    variant_total: Counter[str] = Counter()
    variant_caught: Counter[str] = Counter()
    for session in sessions:
        variant = variant_by_session.get(session.trace.session_id, "unknown")
        variant_total[variant] += 1
        if blocked[str(session.trace.session_id)]:
            variant_caught[variant] += 1

    return ClassBreakdown(
        attack_class=attack_class,
        total=len(sessions),
        caught=caught,
        recall=_safe_ratio(caught, len(sessions)),
        recall_by_variant={
            variant: _safe_ratio(variant_caught[variant], total)
            for variant, total in sorted(variant_total.items())
        },
    )


def run_gate_evaluation(corpus: EvaluationCorpus) -> GateReport:
    """Runs the rules-only baseline over a corpus and summarizes the outcome.

    Args:
        corpus: A chronologically ordered mixed corpus.

    Returns:
        The report.

    Raises:
        ValueError: If the corpus contains no sessions.
    """
    if not corpus.labeled_sessions:
        raise ValueError("cannot evaluate an empty corpus")

    baseline = RulesOnlyBaseline(corpus.registry, corpus.resolver)
    decisions: tuple[BaselineDecision, ...] = baseline.decide_all(
        labeled.trace for labeled in corpus.labeled_sessions
    )
    blocked = {str(d.session_id): d.blocked for d in decisions}

    fired: Counter[str] = Counter()
    false_positive_rules: Counter[str] = Counter()
    by_id = {str(s.trace.session_id): s for s in corpus.labeled_sessions}
    for decision in decisions:
        for rule in decision.fired_rules:
            fired[rule] += 1
            if not by_id[str(decision.session_id)].is_attack:
                false_positive_rules[rule] += 1

    true_positives = sum(
        1 for s in corpus.labeled_sessions if s.is_attack and blocked[str(s.trace.session_id)]
    )
    false_negatives = sum(
        1 for s in corpus.labeled_sessions if s.is_attack and not blocked[str(s.trace.session_id)]
    )
    false_positives = sum(
        1 for s in corpus.labeled_sessions if not s.is_attack and blocked[str(s.trace.session_id)]
    )
    true_negatives = sum(
        1
        for s in corpus.labeled_sessions
        if not s.is_attack and not blocked[str(s.trace.session_id)]
    )

    per_class = tuple(
        _breakdown(
            attack_class,
            [s for s in corpus.labeled_sessions if s.attack_class is attack_class],
            blocked,
            corpus.variant_by_session,
        )
        for attack_class in (
            AttackClass.MANDATE_REPLAY,
            AttackClass.SCOPE_VIOLATION,
            AttackClass.AGENT_IMPERSONATION,
        )
    )

    report = GateReport(
        n_sessions=len(corpus.labeled_sessions),
        attack_base_rate=corpus.attack_base_rate,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        precision=_safe_ratio(true_positives, true_positives + false_positives),
        recall=_safe_ratio(true_positives, true_positives + false_negatives),
        per_class=per_class,
        fired_rule_counts=dict(sorted(fired.items())),
        false_positive_rules=dict(sorted(false_positive_rules.items())),
    )
    logger.info(
        "baseline eval: precision=%.4f recall=%.4f fp=%d fn=%d",
        report.precision, report.recall, report.false_positives, report.false_negatives,
    )
    return report


def format_gate_report(report: GateReport) -> str:
    """Renders a report as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        "Rules-only baseline (Layer 1 + Layer 2)",
        f"  sessions            {report.n_sessions}",
        f"  attack base rate    {report.attack_base_rate:.4f}",
        f"  precision           {report.precision:.4f}",
        f"  recall              {report.recall:.4f}",
        f"  TP/FP/TN/FN         {report.true_positives}/{report.false_positives}/"
        f"{report.true_negatives}/{report.false_negatives}",
        "",
        "Per attack class:",
    ]
    for breakdown in report.per_class:
        lines.append(
            f"  {breakdown.attack_class.value:<22} recall {breakdown.recall:.4f} "
            f"({breakdown.caught}/{breakdown.total})"
        )
        for variant, recall in breakdown.recall_by_variant.items():
            lines.append(f"      {variant:<26} {recall:.4f}")
    lines.append("")
    lines.append("Rules fired:")
    for rule, count in report.fired_rule_counts.items():
        lines.append(f"  {rule:<44} {count}")
    if report.false_positive_rules:
        lines.append("")
        lines.append("Rules fired on LEGITIMATE sessions (investigate every one):")
        for rule, count in report.false_positive_rules.items():
            lines.append(f"  {rule:<44} {count}")
    return "\n".join(lines)