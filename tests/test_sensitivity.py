"""Tests for the generator sensitivity grid.

The grid is only a robustness check if its perturbations genuinely reach the
generator. Most of these tests exist to make sure a factor named in the grid
actually changes the data, rather than being threaded into a config field that
nothing reads -- a failure mode that would produce reassuringly stable numbers
for entirely the wrong reason.
"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import numpy as np
import pytest

from common.schema import EventType
from eval.sensitivity import (
    BASELINE_POINT_NAME,
    GridOutcome,
    GridPoint,
    SensitivityReport,
    build_grid,
    evaluate_grid,
    format_sensitivity_report,
    rebalance_mix,
    rules_invisible_recall,
    scale_category_amounts,
    summarize_variant_counts,
)
from generator.attack_config import DEFAULT_ATTACK_CONFIG
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus
from generator.config import DEFAULT_GENERATOR_CONFIG


def _outcome(point: GridPoint, auc_pr: float, beats: bool = True) -> GridOutcome:
    """Builds a synthetic grid outcome for report-level tests.

    Args:
        point: The grid point described.
        auc_pr: Ensemble AUC-PR to record.
        beats: Whether the ensemble beat the baseline at this point.

    Returns:
        The outcome.
    """
    return GridOutcome(
        point=point,
        params_digest="digest",
        n_sessions=100,
        attack_base_rate=0.04,
        baseline_precision=1.0,
        baseline_recall=0.8,
        ensemble_precision=0.97,
        ensemble_recall=0.99,
        ensemble_auc_pr=auc_pr,
        baseline_auc_pr=0.8,
        rules_invisible_recall=0.9,
        threshold=0.2,
        beats_baseline=beats,
    )


def test_grid_starts_at_the_established_setting() -> None:
    """The reference point must come first, since every delta is measured from it."""
    grid = build_grid()
    assert grid[0].name == BASELINE_POINT_NAME
    assert grid[0].generator_config == DEFAULT_GENERATOR_CONFIG
    assert grid[0].attack_config == DEFAULT_ATTACK_CONFIG


def test_grid_covers_every_named_factor_at_two_levels() -> None:
    """Six factors at two perturbations each, plus the reference: thirteen points."""
    grid = build_grid()
    factors = {point.factor for point in grid} - {"none"}
    assert factors == {
        "amount_median",
        "amount_sigma",
        "rapid_reuse_mix",
        "behavioral_only_mix",
        "scripted_pacing",
        "skip_browse",
    }
    assert len(grid) == 13
    assert len({point.name for point in grid}) == 13


def test_every_perturbation_differs_from_the_reference() -> None:
    """A grid point identical to the reference would silently test nothing."""
    grid = build_grid()
    reference = grid[0]
    for point in grid[1:]:
        assert (point.generator_config, point.attack_config) != (
            reference.generator_config,
            reference.attack_config,
        )


def test_every_grid_point_has_a_distinct_parameter_digest() -> None:
    """No two grid points may be the same parameter set wearing two names."""
    digests = {
        point.name: build_evaluation_corpus(
            600, seed=5, generator_config=point.generator_config,
            attack_config=point.attack_config,
        ).params_digest
        for point in build_grid()
    }
    assert len(set(digests.values())) == len(digests)


def _corpus_for(name: str, n_legitimate: int, seed: int) -> EvaluationCorpus:
    """Builds the corpus for one named grid point.

    Args:
        name: Grid point name.
        n_legitimate: Legitimate sessions to generate.
        seed: Corpus seed.

    Returns:
        The corpus.
    """
    point = next(p for p in build_grid() if p.name == name)
    return build_evaluation_corpus(
        n_legitimate, seed=seed,
        generator_config=point.generator_config, attack_config=point.attack_config,
    )


def test_amount_factors_move_the_generated_amounts() -> None:
    """The amount grid points must change what the generator actually draws."""
    reference = _corpus_for(BASELINE_POINT_NAME, 1500, 5)
    halved = _corpus_for("amount_median_x0.5", 1500, 5)
    doubled = _corpus_for("amount_median_x2", 1500, 5)

    def median_amount(corpus: EvaluationCorpus) -> float:
        """Median legitimate transaction amount in a corpus."""
        return float(
            np.median([float(s.trace.amount) for s in corpus.labeled_sessions if not s.is_attack])
        )

    assert median_amount(halved) < median_amount(reference) < median_amount(doubled)


def test_amount_sigma_factor_moves_the_spread() -> None:
    """The spread grid points must widen and narrow the amount distribution."""
    def spread(name: str) -> float:
        """Interquartile range of legitimate log-amounts under a grid point."""
        corpus = _corpus_for(name, 1500, 5)
        amounts = np.log([float(s.trace.amount) for s in corpus.labeled_sessions if not s.is_attack])
        return float(np.percentile(amounts, 75) - np.percentile(amounts, 25))

    assert spread("amount_sigma_x0.7") < spread(BASELINE_POINT_NAME) < spread("amount_sigma_x1.4")


def test_scripted_pacing_factor_moves_impersonation_event_timing() -> None:
    """Widening the scripted pacing bound must slow behavioral-only sessions."""
    def mean_gap(name: str) -> float:
        """Mean inter-event gap across behavioral-only impersonation sessions."""
        corpus = _corpus_for(name, 4000, 5)
        gaps: list[float] = []
        for session in corpus.labeled_sessions:
            if corpus.variant_by_session.get(session.trace.session_id) != "behavioral_only":
                continue
            stamps = [event.timestamp for event in session.trace.events]
            gaps.extend(
                (later - earlier).total_seconds()
                for earlier, later in zip(stamps, stamps[1:], strict=False)
            )
        return float(np.mean(gaps))

    assert mean_gap("scripted_pacing_max10") < mean_gap("scripted_pacing_max35")


def test_skip_browse_factor_moves_the_browse_skip_rate() -> None:
    """The browse-skip grid points must change how often the stage is omitted."""
    def skip_rate(name: str) -> float:
        """Fraction of behavioral-only sessions that omit the catalog browse."""
        corpus = _corpus_for(name, 4000, 5)
        sessions = [
            session
            for session in corpus.labeled_sessions
            if corpus.variant_by_session.get(session.trace.session_id) == "behavioral_only"
        ]
        skipped = sum(
            1
            for session in sessions
            if not any(
                event.event_type is EventType.CATALOG_BROWSE for event in session.trace.events
            )
        )
        return skipped / len(sessions)

    assert skip_rate("skip_browse_p0.1") < skip_rate("skip_browse_p0.6")


def test_scale_category_amounts_preserves_relative_ordering() -> None:
    """Rescaling must move every category together, not reshuffle them."""
    original = DEFAULT_GENERATOR_CONFIG.categories
    scaled = scale_category_amounts(original, 2.0, 0.5)

    assert [c.name for c in scaled] == [c.name for c in original]
    for before, after in zip(original, scaled, strict=True):
        assert after.amount_median == (before.amount_median * Decimal("2")).quantize(
            Decimal("0.01")
        )
        assert after.amount_sigma == pytest.approx(before.amount_sigma * 0.5)

    ranking_before = [c.name for c in sorted(original, key=lambda c: c.amount_median)]
    ranking_after = [c.name for c in sorted(scaled, key=lambda c: c.amount_median)]
    assert ranking_before == ranking_after


def test_scale_category_amounts_rejects_non_positive_scales() -> None:
    """A zero or negative scale would make the amount distribution undefined."""
    with pytest.raises(ValueError, match="scales must be positive"):
        scale_category_amounts(DEFAULT_GENERATOR_CONFIG.categories, 0.0, 1.0)


def test_rebalance_mix_sets_the_target_and_preserves_the_total() -> None:
    """Raising one weight must come proportionally out of the others."""
    mix = {"a": 0.3, "b": 0.3, "c": 0.4}
    rebalanced = rebalance_mix(mix, "c", 0.6)

    assert rebalanced["c"] == pytest.approx(0.6)
    assert sum(rebalanced.values()) == pytest.approx(sum(mix.values()))
    # a and b were equal before, so they must stay equal after.
    assert rebalanced["a"] == pytest.approx(rebalanced["b"])


def test_rebalance_mix_keeps_the_ratio_between_untouched_weights() -> None:
    """The perturbation must change one variant's share, not the others' ratio."""
    mix = {"a": 0.1, "b": 0.3, "c": 0.6}
    rebalanced = rebalance_mix(mix, "c", 0.2)
    assert rebalanced["b"] / rebalanced["a"] == pytest.approx(mix["b"] / mix["a"])


def test_rebalance_mix_rejects_impossible_targets() -> None:
    """A target that leaves nothing for the others must fail loudly."""
    mix = {"a": 0.5, "b": 0.5}
    with pytest.raises(ValueError, match="is not in the mix"):
        rebalance_mix(mix, "missing", 0.3)
    with pytest.raises(ValueError, match="must not be negative"):
        rebalance_mix(mix, "a", -0.1)
    with pytest.raises(ValueError, match="exceeds the mix total"):
        rebalance_mix(mix, "a", 2.0)
    with pytest.raises(ValueError, match="no other weight to absorb"):
        rebalance_mix({"a": 1.0}, "a", 0.5)


def test_variant_mix_grid_points_reach_the_generated_traffic() -> None:
    """Changing a variant weight must change that variant's share of the corpus."""
    grid = {point.name: point for point in build_grid()}
    shares = {}
    for name in ("rapid_reuse_w0.2", "rapid_reuse_w0.6"):
        point = grid[name]
        corpus = build_evaluation_corpus(
            4000, seed=9, generator_config=point.generator_config,
            attack_config=point.attack_config,
        )
        variants = list(corpus.variant_by_session.values())
        shares[name] = variants.count("rapid_reuse") / len(variants)

    assert shares["rapid_reuse_w0.2"] < shares["rapid_reuse_w0.6"]


def test_rules_invisible_recall_uses_only_the_two_invisible_variants() -> None:
    """Rules-visible variants must not dilute the number Layer 3 is judged on."""
    counts = {
        "rapid_reuse": (8, 10),
        "behavioral_only": (6, 10),
        "expired": (0, 100),
        "amount_over_ceiling": (0, 100),
    }
    assert rules_invisible_recall(counts) == pytest.approx(14 / 20)


def test_rules_invisible_recall_is_zero_when_none_were_generated() -> None:
    """An absent variant must not produce a division by zero."""
    assert rules_invisible_recall({"expired": (5, 5)}) == 0.0


def test_summarize_variant_counts_tallies_correctly() -> None:
    """Caught and total counts must line up with the input rows."""
    caught = np.array([True, False, True, True])
    variants = ["rapid_reuse", "rapid_reuse", "expired", "expired"]
    assert summarize_variant_counts(caught, variants) == {
        "rapid_reuse": (1, 2),
        "expired": (2, 2),
    }


def test_summarize_variant_counts_rejects_misaligned_inputs() -> None:
    """Misaligned arrays would attribute catches to the wrong variant."""
    with pytest.raises(ValueError, match="rows but variants has"):
        summarize_variant_counts(np.array([True, False]), ["only_one"])


def test_evaluate_grid_calls_the_evaluator_for_every_point() -> None:
    """Every grid point must be evaluated, not sampled."""
    grid = build_grid()
    seen: list[str] = []

    def evaluator(point: GridPoint) -> GridOutcome:
        """Records the point and returns a stub outcome."""
        seen.append(point.name)
        return _outcome(point, 0.9)

    report = evaluate_grid(1000, 42, evaluator, grid=grid)
    assert seen == [point.name for point in grid]
    assert report.baseline_outcome.point.name == BASELINE_POINT_NAME
    assert len(report.outcomes) == len(grid) - 1


def test_evaluate_grid_rejects_a_grid_without_the_reference_point() -> None:
    """Deltas are meaningless without the reference the grid is measured against."""
    perturbed = build_grid()[1:]
    with pytest.raises(ValueError, match="must begin with"):
        evaluate_grid(100, 1, lambda point: _outcome(point, 0.9), grid=perturbed)
    with pytest.raises(ValueError, match="must be non-empty"):
        evaluate_grid(100, 1, lambda point: _outcome(point, 0.9), grid=())


def test_worst_case_includes_the_reference_point() -> None:
    """A grid whose perturbations all improve must still report a real worst case."""
    grid = build_grid()
    report = SensitivityReport(
        baseline_outcome=_outcome(grid[0], 0.50),
        outcomes=tuple(_outcome(point, 0.90) for point in grid[1:]),
    )
    assert report.worst_case.point.name == BASELINE_POINT_NAME
    assert report.auc_pr_range == (0.50, 0.90)


def test_worst_case_finds_a_genuine_degradation() -> None:
    """A perturbation that hurts must be the one surfaced."""
    grid = build_grid()
    outcomes = [_outcome(point, 0.90) for point in grid[1:]]
    outcomes[3] = _outcome(grid[4], 0.31)
    report = SensitivityReport(baseline_outcome=_outcome(grid[0], 0.95), outcomes=tuple(outcomes))

    assert report.worst_case.ensemble_auc_pr == pytest.approx(0.31)
    assert report.delta_auc_pr(report.worst_case) == pytest.approx(-0.64)


def test_holds_everywhere_is_false_if_any_point_fails() -> None:
    """One grid point where Layer 3 loses must break the claim."""
    grid = build_grid()
    outcomes = [_outcome(point, 0.9) for point in grid[1:]]
    assert SensitivityReport(_outcome(grid[0], 0.9), tuple(outcomes)).holds_everywhere is True

    outcomes[2] = _outcome(grid[3], 0.9, beats=False)
    assert SensitivityReport(_outcome(grid[0], 0.9), tuple(outcomes)).holds_everywhere is False


def test_formatted_report_names_the_worst_case() -> None:
    """A robustness report that buried its worst result would be useless."""
    grid = build_grid()
    outcomes = [_outcome(point, 0.9) for point in grid[1:]]
    outcomes[1] = _outcome(grid[2], 0.42)
    rendered = format_sensitivity_report(
        SensitivityReport(_outcome(grid[0], 0.95), tuple(outcomes))
    )

    assert "Worst case" in rendered
    assert grid[2].name in rendered
    assert "0.4200" in rendered


def test_grid_points_are_frozen() -> None:
    """A grid point must not be mutated between construction and evaluation."""
    point = build_grid()[1]
    with pytest.raises(AttributeError):
        point.name = "changed"  # type: ignore[misc]
    # `replace` is the supported way to derive a variant of one.
    assert replace(point, name="derived").name == "derived"
