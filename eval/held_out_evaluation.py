"""One-shot evaluation of the frozen detection stack against the held-out class.

This module answers exactly one question, exactly once: how does the
already-frozen Layers 1-3 pipeline -- trained and calibrated on the three
known attack classes, with the threshold already committed by the full evaluation --
perform against mandate chaining / privilege escalation, a class it has
never seen in training, calibration, or tuning?

The scoring model is never retrained here. `run_held_out_evaluation` takes an
already-`fit_pipeline`'d `PipelineFit` (fit against the ordinary three-class
corpus, exactly as the full evaluation did) and applies its frozen `model` and
`threshold` to a `EvaluationCorpus` built by
`generator.attacks.held_out.build_held_out_corpus`. Only the deterministic
rules layers (Layer 1/2) and feature extraction run fresh against the
held-out corpus's own session stream -- neither of those involves any
learned parameter, so re-running them is not retraining.

Standing constraint, restated because it is easy to violate by reflex: the
result this module produces must not be used to change `detect/`,
`features/`, or the generator's attack-side tuning. See
`docs/adr/0003-held-out-class-evaluation.md`.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

import numpy as np

from detect.baseline import RulesOnlyBaseline
from detect.ensemble import ensemble_decide
from eval.pipeline import PipelineFit, extract_features_causally
from generator.attacks.corpus import EvaluationCorpus

logger = logging.getLogger(__name__)

# A missed session's score below half the operating threshold is treated as
# indistinguishable from ordinary legitimate traffic to the model; at or
# above half, the model registered some elevated signal that still fell
# short. This is a score-relative-to-threshold split, not a subjective
# per-session judgment -- the same kind of raw-score inspection
# docs/adr/0001 already relies on for the leak-check discipline.
NEAR_MISS_THRESHOLD_FRACTION = 0.5

BUCKET_CAUGHT = "caught"
BUCKET_BEHAVIORALLY_ORDINARY = "behaviorally_ordinary"
BUCKET_ELEVATED_BUT_INSUFFICIENT = "elevated_but_insufficient"


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
class HeldOutVariantResult:
    """Detection outcome for one mandate-chaining sub-variant.

    Attributes:
        variant: The sub-variant name.
        total: Attack sessions of this variant in the held-out corpus.
        rules_caught: How many Layer 1/2 blocked.
        ensemble_caught: How many the full ensemble blocked.
        rules_recall: `rules_caught / total`.
        ensemble_recall: `ensemble_caught / total`.
        failure_buckets: Count of missed sessions (ensemble did not block)
            in each failure bucket, keyed by `BUCKET_*` constants.
    """

    variant: str
    total: int
    rules_caught: int
    ensemble_caught: int
    rules_recall: float
    ensemble_recall: float
    failure_buckets: dict[str, int]


@dataclass(frozen=True)
class HeldOutReport:
    """The full one-shot held-out evaluation result.

    Attributes:
        n_sessions: Held-out corpus size.
        n_attacks: Mandate-chaining sessions in the held-out corpus.
        attack_base_rate: Realized attack fraction.
        seed: Held-out corpus seed.
        threshold: The frozen operating threshold applied (never recalibrated
            here).
        in_distribution_ensemble_recall: The frozen fit's own ensemble recall
            on its own held-out test block (the full evaluation's headline number),
            for direct comparison against the number below.
        baseline_recall: Rules-only (Layer 1+2) recall on the held-out class,
            overall.
        ensemble_recall: Full ensemble recall on the held-out class, overall.
        variant_results: Per-variant breakdown.
        failure_buckets: Overall failure-bucket counts across every missed
            session, regardless of variant.
    """

    n_sessions: int
    n_attacks: int
    attack_base_rate: float
    seed: int
    threshold: float
    in_distribution_ensemble_recall: float
    baseline_recall: float
    ensemble_recall: float
    variant_results: tuple[HeldOutVariantResult, ...]
    failure_buckets: dict[str, int]

    @property
    def recall_degradation(self) -> float:
        """How much recall drops moving from the known classes to the held-out one.

        Returns:
            `in_distribution_ensemble_recall - ensemble_recall`. Positive
            means the held-out class is harder, as expected; reported
            regardless of sign or magnitude.
        """
        return self.in_distribution_ensemble_recall - self.ensemble_recall


def _bucket_for_score(score: float, threshold: float) -> str:
    """Classifies one missed session's score into a failure bucket.

    Args:
        score: The Layer 3 score the session received.
        threshold: The frozen operating threshold.

    Returns:
        One of the `BUCKET_*` constants.
    """
    if score >= threshold * NEAR_MISS_THRESHOLD_FRACTION:
        return BUCKET_ELEVATED_BUT_INSUFFICIENT
    return BUCKET_BEHAVIORALLY_ORDINARY


def run_held_out_evaluation(fit: PipelineFit, held_out_corpus: EvaluationCorpus) -> HeldOutReport:
    """Scores the held-out corpus with the frozen pipeline and reports the result.

    Args:
        fit: A `PipelineFit` already produced by `eval.pipeline.fit_pipeline`
            against the ordinary three-class corpus. Its `model` and
            `threshold` are applied as-is; nothing here retrains or
            recalibrates them.
        held_out_corpus: The held-out corpus to evaluate, from
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
    baseline_blocked = np.array([d.blocked for d in decisions])

    features = extract_features_causally(sessions)
    behavioral_score = fit.model.predict_proba(features)

    ensemble_blocked = np.zeros(len(sessions), dtype=bool)
    for i, decision in enumerate(decisions):
        score = None if decision.blocked else float(behavioral_score[i])
        ensemble_blocked[i] = ensemble_decide(decision, score, fit.threshold).blocked

    attack_mask = labels
    baseline_recall = _safe_ratio(
        int(np.sum(baseline_blocked & attack_mask)), int(np.sum(attack_mask))
    )
    ensemble_recall = _safe_ratio(
        int(np.sum(ensemble_blocked & attack_mask)), int(np.sum(attack_mask))
    )

    overall_buckets: Counter[str] = Counter()
    variant_totals: Counter[str] = Counter()
    variant_rules_caught: Counter[str] = Counter()
    variant_ensemble_caught: Counter[str] = Counter()
    variant_buckets: dict[str, Counter[str]] = {}

    for i, session in enumerate(sessions):
        if not session.is_attack:
            continue
        variant = held_out_corpus.variant_by_session.get(session.trace.session_id, "unknown")
        variant_totals[variant] += 1
        if baseline_blocked[i]:
            variant_rules_caught[variant] += 1
        if ensemble_blocked[i]:
            variant_ensemble_caught[variant] += 1
            continue
        bucket = _bucket_for_score(float(behavioral_score[i]), fit.threshold)
        overall_buckets[bucket] += 1
        variant_buckets.setdefault(variant, Counter())[bucket] += 1

    variant_results = tuple(
        HeldOutVariantResult(
            variant=variant,
            total=total,
            rules_caught=variant_rules_caught[variant],
            ensemble_caught=variant_ensemble_caught[variant],
            rules_recall=_safe_ratio(variant_rules_caught[variant], total),
            ensemble_recall=_safe_ratio(variant_ensemble_caught[variant], total),
            failure_buckets=dict(variant_buckets.get(variant, Counter())),
        )
        for variant, total in sorted(variant_totals.items())
    )

    in_distribution_labels, _, in_distribution_ensemble_score = fit.test_slice()
    in_distribution_ensemble_blocked = in_distribution_ensemble_score >= fit.threshold
    in_distribution_recall = _safe_ratio(
        int(np.sum(in_distribution_ensemble_blocked & in_distribution_labels)),
        int(np.sum(in_distribution_labels)),
    )

    logger.info(
        "held-out evaluation: baseline_recall=%.4f ensemble_recall=%.4f "
        "in_distribution_recall=%.4f degradation=%.4f",
        baseline_recall, ensemble_recall, in_distribution_recall,
        in_distribution_recall - ensemble_recall,
    )

    return HeldOutReport(
        n_sessions=len(sessions),
        n_attacks=int(np.sum(attack_mask)),
        attack_base_rate=held_out_corpus.attack_base_rate,
        seed=held_out_corpus.seed,
        threshold=fit.threshold,
        in_distribution_ensemble_recall=in_distribution_recall,
        baseline_recall=baseline_recall,
        ensemble_recall=ensemble_recall,
        variant_results=variant_results,
        failure_buckets=dict(overall_buckets),
    )


def format_held_out_report(report: HeldOutReport) -> str:
    """Renders the held-out evaluation as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        "Held-out evaluation: mandate chaining / privilege escalation",
        "(evaluated once, against the already-frozen Layers 1-3 pipeline; see docs/adr/0003)",
        "",
        f"  held-out sessions      {report.n_sessions}",
        f"  held-out attacks       {report.n_attacks}",
        f"  attack base rate       {report.attack_base_rate:.4f}",
        f"  frozen threshold       {report.threshold:.4f}",
        "",
        f"  {'in-distribution ensemble recall (full-eval test block)':<57} "
        f"{report.in_distribution_ensemble_recall:.4f}",
        f"  {'held-out rules-only (Layer 1+2) recall':<57} {report.baseline_recall:.4f}",
        f"  {'held-out ensemble recall':<57} {report.ensemble_recall:.4f}",
        f"  {'recall degradation (in-distribution minus held-out)':<57} "
        f"{report.recall_degradation:+.4f}",
        "",
        "Per-variant recall (rules-only -> ensemble):",
    ]
    for v in report.variant_results:
        lines.append(
            f"  {v.variant:<28} n={v.total:<4} {v.rules_recall:.4f} -> {v.ensemble_recall:.4f}"
        )
        if v.failure_buckets:
            bucket_str = ", ".join(f"{k}={n}" for k, n in sorted(v.failure_buckets.items()))
            lines.append(f"      missed-session buckets: {bucket_str}")

    lines.append("")
    lines.append("Overall failure-bucket counts across every missed session:")
    if report.failure_buckets:
        for bucket, count in sorted(report.failure_buckets.items()):
            lines.append(f"  {bucket:<28} {count}")
    else:
        lines.append("  (no misses)")
    return "\n".join(lines)
