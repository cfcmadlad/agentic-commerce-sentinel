"""Tests for the end-to-end decision latency instrumentation.

Timing code is easy to write and easy to get subtly wrong, and a wrong latency
figure is one nobody catches by reading it. The checks that matter here are
that the wrapper produces the same verdicts as the unwrapped pipeline (so the
instrumentation is not changing what it measures), that the percentiles are
computed over the right rows, and that warm-up sessions advance state without
entering the sample.
"""

from __future__ import annotations

import numpy as np
import pytest

from detect.baseline import RulesOnlyBaseline
from detect.behavioral import train_behavioral_model
from detect.ensemble import ensemble_decide
from eval.latency import (
    DEFAULT_PERCENTILES,
    TimedDecisionPipeline,
    format_latency_report,
    measure_latency,
)
from features.session import FeatureExtractor, feature_names
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus

_CORPUS_SESSIONS = 900
_CORPUS_SEED = 42


def _corpus() -> EvaluationCorpus:
    """Builds a small corpus large enough to train on and time over.

    Returns:
        The corpus.
    """
    return build_evaluation_corpus(_CORPUS_SESSIONS, seed=_CORPUS_SEED)


def _trained_pipeline(corpus: EvaluationCorpus, threshold: float) -> TimedDecisionPipeline:
    """Trains a Layer 3 model on the corpus and wires up a timed pipeline.

    Args:
        corpus: The corpus to train against.
        threshold: Ensemble cutoff for the behavioral score.

    Returns:
        A pipeline with a fresh baseline and feature extractor.
    """
    names = feature_names()
    extractor = FeatureExtractor()
    features = np.array(
        [
            [extractor.extract(labeled.trace)[name] for name in names]
            for labeled in corpus.labeled_sessions
        ]
    )
    labels = np.array([labeled.is_attack for labeled in corpus.labeled_sessions])
    model = train_behavioral_model(features, labels, names)

    return TimedDecisionPipeline(
        baseline=RulesOnlyBaseline(corpus.registry, corpus.resolver),
        model=model,
        threshold=threshold,
    )


def test_reports_the_requested_percentiles() -> None:
    """Every requested percentile must appear in the report."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    report = measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=50)

    assert set(report.percentiles) == set(DEFAULT_PERCENTILES)
    assert DEFAULT_PERCENTILES == (50.0, 95.0, 99.0)
    assert all(value > 0.0 for value in report.percentiles.values())


def test_percentiles_are_ordered_and_bracketed_by_the_extremes() -> None:
    """p50 <= p95 <= p99, and every percentile inside [min, max]."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    report = measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=50)

    assert report.percentiles[50.0] <= report.percentiles[95.0] <= report.percentiles[99.0]
    assert report.minimum_ms <= report.percentiles[50.0]
    assert report.percentiles[99.0] <= report.maximum_ms
    assert report.minimum_ms <= report.mean_ms <= report.maximum_ms


def test_warmup_sessions_are_excluded_from_the_sample() -> None:
    """Warm-up must advance state without being timed."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    warmup = 100
    report = measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=warmup)

    assert report.n_warmup == warmup
    assert report.n_decisions == len(traces) - warmup


def test_timing_does_not_change_the_verdicts() -> None:
    """The instrumented path must decide exactly as an uninstrumented one does.

    If wrapping the pipeline changed a verdict, the latency figure would
    describe a system nobody is evaluating.
    """
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    threshold = 0.4

    timed = _trained_pipeline(corpus, threshold)
    timed_verdicts = [timed.time_decision(trace)[0].blocked for trace in traces]

    reference_pipeline = _trained_pipeline(corpus, threshold)
    reference_verdicts = [reference_pipeline.decide(trace).blocked for trace in traces]

    assert timed_verdicts == reference_verdicts


def test_pipeline_verdicts_match_the_layers_composed_by_hand() -> None:
    """The wrapper must not have its own opinion about how layers combine."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions][:200]
    threshold = 0.4

    pipeline = _trained_pipeline(corpus, threshold)
    wrapped = [pipeline.decide(trace) for trace in traces]

    names = feature_names()
    manual_baseline = RulesOnlyBaseline(corpus.registry, corpus.resolver)
    manual_extractor = FeatureExtractor()
    # Reuses the pipeline's own model so only the composition differs.
    manual = []
    for trace in traces:
        decision = manual_baseline.decide(trace)
        row = np.array([[manual_extractor.extract(trace)[name] for name in names]])
        score = float(pipeline.model.predict_proba(row)[0])
        manual.append(ensemble_decide(decision, score, threshold))

    assert [d.blocked for d in wrapped] == [d.blocked for d in manual]
    assert [d.source for d in wrapped] == [d.source for d in manual]


def test_measured_latency_is_plausible_for_an_in_process_pipeline() -> None:
    """A per-decision median in the tens of milliseconds would signal a defect.

    Loose bound on purpose: this asserts the measurement is of one decision
    rather than of the whole batch, not that the machine is fast.
    """
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    report = measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=50)
    assert 0.0 < report.percentiles[50.0] < 50.0


def test_custom_percentiles_are_honoured() -> None:
    """A caller asking for other percentiles must get those, not the defaults."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    report = measure_latency(
        _trained_pipeline(corpus, 0.5), traces, percentiles=(25.0, 75.0), n_warmup=20
    )
    assert set(report.percentiles) == {25.0, 75.0}


def test_formatting_names_every_percentile() -> None:
    """The rendered report must show each percentile it measured."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]
    rendered = format_latency_report(
        measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=50)
    )
    for label in ("p50", "p95", "p99", "min", "max", "mean"):
        assert label in rendered


def test_rejects_invalid_measurement_arguments() -> None:
    """Bad arguments must fail loudly rather than silently reshape the sample."""
    corpus = _corpus()
    traces = [labeled.trace for labeled in corpus.labeled_sessions]

    with pytest.raises(ValueError, match="zero sessions"):
        measure_latency(_trained_pipeline(corpus, 0.5), [])
    with pytest.raises(ValueError, match="leaves no sessions to time"):
        measure_latency(_trained_pipeline(corpus, 0.5), traces[:10], n_warmup=10)
    with pytest.raises(ValueError, match="must not be negative"):
        measure_latency(_trained_pipeline(corpus, 0.5), traces, n_warmup=-1)
    with pytest.raises(ValueError, match="percentile must be in"):
        measure_latency(_trained_pipeline(corpus, 0.5), traces, percentiles=(0.0,), n_warmup=5)
    with pytest.raises(ValueError, match="percentiles must be non-empty"):
        measure_latency(_trained_pipeline(corpus, 0.5), traces, percentiles=(), n_warmup=5)
