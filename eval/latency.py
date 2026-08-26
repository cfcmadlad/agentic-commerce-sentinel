"""End-to-end per-decision latency measurement for the full detection path.

What is measured is one session's complete journey: mandate resolution, Layer
1 verification, Layer 2 scope enforcement, Layer 3 feature extraction and
scoring, and the ensemble combination that produces the final verdict. That is
the quantity a deployment cares about, because it is what sits between a
payment request arriving and a decision coming back.

The timing lives here rather than inside the layer modules on purpose. A
detector that measures itself carries measurement code into production, and
every layer would need its own clock handling, its own accumulator, and its
own opinion about what counts as "the work" -- none of which is that layer's
job. Wrapping the composed path from outside keeps the layers unaware they are
being timed and keeps the definition of a decision in one place.

Latency is reported as percentiles, never as a mean. A mean over a heavy right
tail says almost nothing useful: the number a payments team needs is the p99,
because that is the fraction of traffic that would breach a timeout, and a mean
can look healthy while the tail does not. The percentiles are computed with
linear interpolation between order statistics, matching numpy's default and
stated here so the figures are comparable with anything computed elsewhere.

These numbers describe this implementation on the machine that ran it: pure
Python, single-threaded, in-process, over a synthetic corpus with an in-memory
mandate resolver. A real deployment adds network hops, a real mandate store,
and serialisation, so treat these as a floor on achievable latency rather than
as a prediction of production latency.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from common.schema import SessionTrace
from detect.baseline import RulesOnlyBaseline
from detect.behavioral import BehavioralModel
from detect.ensemble import EnsembleDecision, ensemble_decide
from features.session import FeatureExtractor, feature_names

logger = logging.getLogger(__name__)

DEFAULT_PERCENTILES: tuple[float, ...] = (50.0, 95.0, 99.0)

NANOSECONDS_PER_MILLISECOND = 1_000_000.0

# Sessions timed before measurement begins, so the reported percentiles are not
# dominated by first-call costs -- lazy imports, scikit-learn's first predict
# path, and cold branch prediction -- that a warm service would never pay.
DEFAULT_WARMUP_SESSIONS = 50


@dataclass(frozen=True)
class LatencyReport:
    """Per-decision latency distribution over one timed run.

    Attributes:
        n_decisions: Sessions timed, excluding warm-up.
        n_warmup: Sessions run before measurement started.
        percentiles: Requested percentile to its latency in milliseconds.
        minimum_ms: Fastest timed decision, in milliseconds.
        maximum_ms: Slowest timed decision, in milliseconds.
        mean_ms: Arithmetic mean, in milliseconds. Reported only so a reader
            can see how far it sits from the median; the percentiles are the
            figures that matter.
    """

    n_decisions: int
    n_warmup: int
    percentiles: dict[float, float]
    minimum_ms: float
    maximum_ms: float
    mean_ms: float


class TimedDecisionPipeline:
    """Composes the full detection path and times each end-to-end decision.

    Stateful in exactly the ways the underlying layers are: the baseline's
    mandate ledger and the feature extractor's per-agent history both advance
    as sessions are fed through, so sessions must arrive in chronological order
    and one pipeline must be constructed per run.
    """

    def __init__(
        self,
        baseline: RulesOnlyBaseline,
        model: BehavioralModel,
        threshold: float,
        extractor: FeatureExtractor | None = None,
    ) -> None:
        """Initialises the pipeline with its injected collaborators.

        Args:
            baseline: A fresh rules-only baseline supplying Layers 1 and 2.
            model: The trained Layer 3 model.
            threshold: The calibrated cutoff at or above which the behavioral
                score alone blocks a session.
            extractor: Feature extractor carrying agent and mandate history.
                A fresh one is created when omitted; pass an existing one to
                continue a history built up over earlier traffic, which is
                what makes the timed sessions see realistic history depth
                rather than an empty cache.
        """
        self._baseline = baseline
        self._model = model
        self._threshold = threshold
        self._extractor = FeatureExtractor() if extractor is None else extractor
        self._feature_names = feature_names()

    @property
    def model(self) -> BehavioralModel:
        """Exposes the Layer 3 model this pipeline scores with.

        Returns:
            The fitted model, so a caller can reproduce the pipeline's own
            scores without reaching into its internals.
        """
        return self._model

    def decide(self, trace: SessionTrace) -> EnsembleDecision:
        """Runs one session through every layer and returns the final verdict.

        Args:
            trace: The session to decide on, in chronological order relative
                to previous calls.

        Returns:
            The ensemble decision.
        """
        decision = self._baseline.decide(trace)
        features = self._extractor.extract(trace)
        # Scored even when the rules already blocked: the ensemble ignores the
        # score in that case, but a deployment that skipped scoring would have
        # a bimodal latency profile, and timing only the cheap path would
        # understate the p99 this measurement exists to establish.
        row = np.array([[features[name] for name in self._feature_names]])
        score = float(self._model.predict_proba(row)[0])
        return ensemble_decide(decision, score, self._threshold)

    def time_decision(self, trace: SessionTrace) -> tuple[EnsembleDecision, int]:
        """Runs one decision and reports how long it took.

        Args:
            trace: The session to decide on.

        Returns:
            A tuple of (decision, elapsed nanoseconds).
        """
        started = time.perf_counter_ns()
        decision = self.decide(trace)
        return decision, time.perf_counter_ns() - started


def measure_latency(
    pipeline: TimedDecisionPipeline,
    traces: Sequence[SessionTrace],
    percentiles: tuple[float, ...] = DEFAULT_PERCENTILES,
    n_warmup: int = DEFAULT_WARMUP_SESSIONS,
) -> LatencyReport:
    """Times a chronological stream of decisions and summarises the distribution.

    Args:
        pipeline: The composed pipeline to time. Consumed statefully; do not
            reuse one across two measurements.
        traces: Sessions in ascending `started_at` order.
        percentiles: Percentiles to report, each in (0, 100].
        n_warmup: Leading sessions to run before measurement begins. Their
            decisions still advance pipeline state, they are simply not timed.

    Returns:
        The latency report.

    Raises:
        ValueError: If `traces` is empty, if `n_warmup` is negative or leaves
            no session to time, or if any requested percentile is outside
            (0, 100].
    """
    if not traces:
        raise ValueError("cannot measure latency over zero sessions")
    if n_warmup < 0:
        raise ValueError(f"n_warmup must not be negative, got {n_warmup}")
    if n_warmup >= len(traces):
        raise ValueError(
            f"n_warmup of {n_warmup} leaves no sessions to time out of {len(traces)}; "
            f"supply more traces or reduce the warm-up"
        )
    if not percentiles:
        raise ValueError("percentiles must be non-empty")
    for percentile in percentiles:
        if not 0.0 < percentile <= 100.0:
            raise ValueError(f"percentile must be in (0, 100], got {percentile}")

    for trace in traces[:n_warmup]:
        pipeline.decide(trace)

    elapsed_ns = np.array(
        [pipeline.time_decision(trace)[1] for trace in traces[n_warmup:]], dtype=np.float64
    )
    elapsed_ms = elapsed_ns / NANOSECONDS_PER_MILLISECOND

    report = LatencyReport(
        n_decisions=int(elapsed_ms.size),
        n_warmup=n_warmup,
        percentiles={
            percentile: float(np.percentile(elapsed_ms, percentile))
            for percentile in percentiles
        },
        minimum_ms=float(elapsed_ms.min()),
        maximum_ms=float(elapsed_ms.max()),
        mean_ms=float(elapsed_ms.mean()),
    )
    logger.info(
        "latency over %d decisions: p50=%.3fms p95=%.3fms p99=%.3fms",
        report.n_decisions,
        report.percentiles.get(50.0, float("nan")),
        report.percentiles.get(95.0, float("nan")),
        report.percentiles.get(99.0, float("nan")),
    )
    return report


def format_latency_report(report: LatencyReport) -> str:
    """Renders a latency report as plain text.

    Args:
        report: The report to render.

    Returns:
        A human-readable multi-line summary.
    """
    lines = [
        f"End-to-end decision latency ({report.n_decisions} decisions, "
        f"{report.n_warmup} warm-up sessions excluded):",
    ]
    for percentile in sorted(report.percentiles):
        lines.append(f"  p{percentile:<5g} {report.percentiles[percentile]:>8.3f} ms")
    lines.append(f"  min   {report.minimum_ms:>8.3f} ms")
    lines.append(f"  max   {report.maximum_ms:>8.3f} ms")
    lines.append(f"  mean  {report.mean_ms:>8.3f} ms  (shown for tail comparison only)")
    return "\n".join(lines)
