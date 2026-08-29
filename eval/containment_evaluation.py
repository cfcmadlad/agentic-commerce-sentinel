"""One-shot evaluation of Layer 2.5 (containment) against the held-out class.

Mirrors `eval/held_out_evaluation.py` exactly in evaluation discipline -- same
frozen `PipelineFit`, same held-out corpus, evaluated once, nothing retrained
or recalibrated in response to the result -- but inserts the new containment
gate between Layer 1/2 and Layer 3, so three block sources are measured on
the same held-out sessions: rules alone (Layer 1+2, exactly the held-out
evaluation's own number, for direct comparison), rules plus containment
(Layer 1+2+2.5, the new layer's own contribution with the learned layer held
out), and the full stack (Layer 1+2+2.5+3, the number this layer's headline
recall is drawn from).

Standing constraint, restated because it is easy to violate by reflex: the
result this module produces must not be used to change `detect/`, `features/`,
`generator/` tuning, or the containment rules themselves. See
`docs/adr/0004-delegation-chain-containment.md`.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

import numpy as np

from containment.gate import ContainmentGate
from containment.store import build_store_from_signed_mandates
from detect.baseline import RulesOnlyBaseline
from detect.ensemble import ensemble_decide
from eval.pipeline import PipelineFit, extract_features_causally
from generator.attacks.corpus import EvaluationCorpus
from mandate.schema import SignedMandate

logger = logging.getLogger(__name__)


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Divides two counts, returning 0.0 on an empty denominator.

    Args:
        numerator: The numerator count.
        denominator: The denominator count.

    Returns:
        The ratio, or 0.0 when the denominator is zero.
    """
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True)
class ContainmentVariantResult:
    """Detection outcome for one mandate-chaining sub-variant, across three block sources.

    Attributes:
        variant: The sub-variant name.
        total: Attack sessions of this variant in the held-out corpus.
        rules_recall: Layer 1+2 alone.
        rules_containment_recall: Layer 1+2 plus Layer 2.5, no learned layer.
        full_recall: Layer 1+2+2.5 plus Layer 3 -- the deployed stack.
    """

    variant: str
    total: int
    rules_recall: float
    rules_containment_recall: float
    full_recall: float


@dataclass(frozen=True)
class ContainmentEvaluationReport:
    """The full one-shot Layer 2.5 evaluation result.

    Attributes:
        n_sessions: Held-out corpus size.
        n_attacks: Mandate-chaining sessions in the held-out corpus.
        rules_recall: Overall Layer 1+2 recall (matches docs/adr/0003).
        rules_containment_recall: Overall Layer 1+2+2.5 recall, learned layer
            held out.
        full_recall: Overall Layer 1+2+2.5+3 recall -- the headline number.
        variant_results: Per-variant breakdown across all three sources.
        containment_reason_counts: How often each `ContainmentViolationReason`
            fired, across every attack session containment blocked.
        containment_false_positives: Legitimate sessions containment blocked.
            Expected to be exactly zero: containment only ever fires on a
            mandate that declares a `parent_mandate_id`, and no legitimate
            mandate in this project's generator ever does -- reported as a
            measured count, not asserted, so the claim is falsifiable.
    """

    n_sessions: int
    n_attacks: int
    rules_recall: float
    rules_containment_recall: float
    full_recall: float
    variant_results: tuple[ContainmentVariantResult, ...]
    containment_reason_counts: dict[str, int]
    containment_false_positives: int


def run_containment_evaluation(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus
) -> ContainmentEvaluationReport:
    """Scores the held-out corpus with rules, containment, and the frozen Layer 3.

    Args:
        fit: A `PipelineFit` already produced by `eval.pipeline.fit_pipeline`
            against the ordinary three-class corpus -- the same frozen fit
            `eval.held_out_evaluation.run_held_out_evaluation` uses. Its
            `model` and `threshold` are applied as-is; nothing here retrains
            or recalibrates them.
        held_out_corpus: The held-out corpus, from
            `generator.attacks.held_out.build_held_out_corpus`.

    Returns:
        The full report.

    Raises:
        ValueError: If `held_out_corpus` contains no attack sessions.
    """
    sessions = held_out_corpus.labeled_sessions
    labels = np.array([s.is_attack for s in sessions])
    if not labels.any():
        raise ValueError("held-out corpus contains no attack sessions to evaluate against")

    baseline = RulesOnlyBaseline(held_out_corpus.registry, held_out_corpus.resolver)
    decisions = baseline.decide_all(s.trace for s in sessions)
    rules_blocked = np.array([d.blocked for d in decisions])

    all_signed: list[SignedMandate] = []
    for session in sessions:
        signed = held_out_corpus.resolver.resolve(session.trace.session_id)
        if signed is not None:
            all_signed.append(signed)
    store = build_store_from_signed_mandates(all_signed)
    gate = ContainmentGate(store)

    # Containment runs in the same chronological order the corpus is already
    # sorted in: the sibling-cap rule reads a running per-parent total, so
    # processing out of order would check a sibling against a total from the
    # future. Only rules-allowed sessions reach it -- an already-blocked
    # session adds nothing by also being containment-checked, matching how
    # Layer 3 is skipped for the same reason elsewhere in this pipeline.
    containment_blocked = np.zeros(len(sessions), dtype=bool)
    reason_counts: Counter[str] = Counter()
    for i, session in enumerate(sessions):
        if rules_blocked[i]:
            continue
        signed = held_out_corpus.resolver.resolve(session.trace.session_id)
        if signed is None:
            continue
        result = gate.decide(signed.mandate)
        containment_blocked[i] = not result.in_bounds
        if not result.in_bounds:
            for reason in result.reasons:
                reason_counts[reason.value] += 1

    rules_or_containment_blocked = rules_blocked | containment_blocked

    features = extract_features_causally(sessions)
    behavioral_score = fit.model.predict_proba(features)

    full_blocked = np.zeros(len(sessions), dtype=bool)
    for i, decision in enumerate(decisions):
        blocked_upstream = decision.blocked or containment_blocked[i]
        if blocked_upstream:
            full_blocked[i] = True
        else:
            score = float(behavioral_score[i])
            full_blocked[i] = ensemble_decide(decision, score, fit.threshold).blocked

    attack_mask = labels
    rules_recall = _safe_ratio(int(np.sum(rules_blocked & attack_mask)), int(np.sum(attack_mask)))
    rules_containment_recall = _safe_ratio(
        int(np.sum(rules_or_containment_blocked & attack_mask)), int(np.sum(attack_mask))
    )
    full_recall = _safe_ratio(int(np.sum(full_blocked & attack_mask)), int(np.sum(attack_mask)))
    containment_false_positives = int(np.sum(containment_blocked & ~attack_mask))

    variant_totals: Counter[str] = Counter()
    variant_rules: Counter[str] = Counter()
    variant_rules_containment: Counter[str] = Counter()
    variant_full: Counter[str] = Counter()
    for i, session in enumerate(sessions):
        if not session.is_attack:
            continue
        variant = held_out_corpus.variant_by_session.get(session.trace.session_id, "unknown")
        variant_totals[variant] += 1
        if rules_blocked[i]:
            variant_rules[variant] += 1
        if rules_or_containment_blocked[i]:
            variant_rules_containment[variant] += 1
        if full_blocked[i]:
            variant_full[variant] += 1

    variant_results = tuple(
        ContainmentVariantResult(
            variant=variant,
            total=total,
            rules_recall=_safe_ratio(variant_rules[variant], total),
            rules_containment_recall=_safe_ratio(variant_rules_containment[variant], total),
            full_recall=_safe_ratio(variant_full[variant], total),
        )
        for variant, total in sorted(variant_totals.items())
    )

    logger.info(
        "containment evaluation: rules_recall=%.4f rules_containment_recall=%.4f full_recall=%.4f "
        "false_positives=%d",
        rules_recall, rules_containment_recall, full_recall, containment_false_positives,
    )

    return ContainmentEvaluationReport(
        n_sessions=len(sessions),
        n_attacks=int(np.sum(attack_mask)),
        rules_recall=rules_recall,
        rules_containment_recall=rules_containment_recall,
        full_recall=full_recall,
        variant_results=variant_results,
        containment_reason_counts=dict(reason_counts),
        containment_false_positives=containment_false_positives,
    )


def format_containment_report(report: ContainmentEvaluationReport) -> str:
    """Renders the containment evaluation as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        "Layer 2.5 (containment) evaluation: mandate chaining / privilege escalation",
        "(evaluated once, against the frozen Layers 1-3 pipeline plus the new containment "
        "gate; see docs/adr/0004)",
        "",
        f"  held-out sessions      {report.n_sessions}",
        f"  held-out attacks       {report.n_attacks}",
        "",
        f"  rules-only recall (Layer 1+2, matches docs/adr/0003)      {report.rules_recall:.4f}",
        f"  rules+containment recall (Layer 1+2+2.5, no learned layer) {report.rules_containment_recall:.4f}",
        f"  full stack recall (Layer 1+2+2.5+3)                       {report.full_recall:.4f}",
        f"  containment false positives on legitimate traffic          {report.containment_false_positives}",
        "",
        "Per-variant recall (rules -> rules+containment -> full stack):",
    ]
    for v in report.variant_results:
        lines.append(
            f"  {v.variant:<28} n={v.total:<4} "
            f"{v.rules_recall:.4f} -> {v.rules_containment_recall:.4f} -> {v.full_recall:.4f}"
        )
    lines.append("")
    lines.append("Containment violation reasons fired (across all sessions containment blocked):")
    if report.containment_reason_counts:
        for reason, count in sorted(report.containment_reason_counts.items()):
            lines.append(f"  {reason:<40} {count}")
    else:
        lines.append("  (none fired)")
    return "\n".join(lines)
