"""Tests for the static-dashboard JSON export.

The dashboard renders whatever this module writes with no further
validation on the frontend side, so the contract that matters is: every
field the dashboard reads must be present, JSON-round-trippable, and use
plain types (no enums, no numpy scalars, no None where the dashboard
expects a number).
"""

from __future__ import annotations

import json

from eval.full_evaluation import run_full_evaluation
from eval.report_json import full_evaluation_report_to_dict
from generator.attacks.corpus import build_evaluation_corpus

_CORPUS_SESSIONS = 2500
_CORPUS_SEED = 42


def _report_dict() -> dict[str, object]:
    """Builds a small report and serializes it, once per test run.

    Returns:
        The serialized report.
    """
    corpus = build_evaluation_corpus(_CORPUS_SESSIONS, seed=_CORPUS_SEED)
    report = run_full_evaluation(
        corpus,
        n_resamples=60,
        latency_sessions=200,
        sensitivity_sessions=800,
        run_sensitivity=False,
    )
    return full_evaluation_report_to_dict(report)


def test_output_is_valid_json() -> None:
    """The export must round-trip through json.dumps/json.loads with no encoder."""
    payload = _report_dict()
    round_tripped = json.loads(json.dumps(payload))
    assert round_tripped["n_sessions"] == payload["n_sessions"]


def test_every_top_level_key_the_dashboard_needs_is_present() -> None:
    """A key the frontend reads and doesn't find fails silently in the browser."""
    payload = _report_dict()
    expected_keys = {
        "n_sessions", "n_test", "attack_base_rate", "params_digest", "threshold",
        "baseline_precision", "baseline_recall", "ensemble_precision", "ensemble_recall",
        "baseline_scores", "ensemble_scores", "layer3_scores", "calibration",
        "baseline_class_breakdown", "ensemble_class_breakdown", "variant_comparison",
        "cost_sweeps", "cost_ratio", "latency", "sensitivity", "gate",
        "top_attribution_features",
    }
    assert expected_keys <= payload.keys()


def test_sensitivity_is_null_when_skipped() -> None:
    """The dashboard must render 'not run', not a fabricated empty grid."""
    payload = _report_dict()
    assert payload["sensitivity"] is None


def test_attack_class_enum_is_exported_as_plain_string() -> None:
    """An AttackClass leaking through unconverted would fail json.dumps outright."""
    payload = _report_dict()
    breakdown = payload["baseline_class_breakdown"]
    assert isinstance(breakdown, list)
    assert all(isinstance(entry["attack_class"], str) for entry in breakdown)


def test_gate_carries_its_significance_tests() -> None:
    """The gate's mcnemar/delong results must serialize, since the dashboard headlines them."""
    payload = _report_dict()
    gate = payload["gate"]
    assert isinstance(gate, dict)
    assert gate["mcnemar"] is not None
    assert isinstance(gate["mcnemar"]["p_value"], float)
    assert gate["delong"] is not None
    assert isinstance(gate["delong"]["p_value"], float)


def test_cost_sweep_always_includes_the_minimum_cost_point() -> None:
    """Downsampling must never drop the one point the dashboard highlights."""
    payload = _report_dict()
    sweeps = payload["cost_sweeps"]
    assert isinstance(sweeps, list)
    for sweep in sweeps:
        minimum_threshold = sweep["minimum_cost_point"]["threshold"]
        sampled_thresholds = {point["threshold"] for point in sweep["points"]}
        assert minimum_threshold in sampled_thresholds


def test_latency_percentile_keys_are_strings() -> None:
    """JSON object keys must be strings; a float key would fail to serialize."""
    payload = _report_dict()
    latency = payload["latency"]
    assert isinstance(latency, dict)
    assert all(isinstance(key, str) for key in latency["percentiles"])
    assert "50.0" in latency["percentiles"]
