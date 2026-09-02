"""Tests for the one-shot Layer 2.5 evaluation against the held-out corpus.

The property that matters most, matching `tests/test_held_out_evaluation.py`,
is that this module never retrains or recalibrates the frozen `PipelineFit`
it is handed. Everything else checks the reported numbers are arithmetically
consistent with an independent hand count, and that the specific per-variant
story `docs/adr/0004` reports (full recall on the scope/expiry-violating
variants, partial recall on fan-out structuring, zero on subdelegation) is
what this module actually measures rather than an assumption.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from eval.containment_evaluation import format_containment_report, run_containment_evaluation
from eval.pipeline import PipelineFit, fit_pipeline
from generator.attacks.corpus import build_evaluation_corpus
from generator.attacks.held_out import build_held_out_corpus

_TRAIN_CORPUS_SESSIONS = 3000
_TRAIN_SEED = 42
_HELD_OUT_SESSIONS = 3000
_HELD_OUT_SEED = 90205


@pytest.fixture(scope="module")
def fit() -> PipelineFit:
    """Fits the ordinary three-class pipeline once, shared read-only.

    Returns:
        The fit.
    """
    corpus = build_evaluation_corpus(_TRAIN_CORPUS_SESSIONS, seed=_TRAIN_SEED)
    return fit_pipeline(corpus)


def test_rules_containment_recall_is_never_below_rules_only(fit: PipelineFit) -> None:
    """Containment only ever adds blocks on top of the rules, never removes one."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    assert report.rules_containment_recall >= report.rules_recall - 1e-12


def test_full_recall_is_never_below_rules_containment_recall(fit: PipelineFit) -> None:
    """Layer 3 only ever adds blocks on top of rules+containment, never removes one."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    assert report.full_recall >= report.rules_containment_recall - 1e-12


def test_containment_never_blocks_legitimate_traffic(fit: PipelineFit) -> None:
    """No legitimate mandate in this generator declares a parent, so containment cannot fire."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    assert report.containment_false_positives == 0


def test_variant_totals_sum_to_n_attacks(fit: PipelineFit) -> None:
    """Per-variant totals must partition every attack session exactly once."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    assert sum(v.total for v in report.variant_results) == report.n_attacks


def test_budget_escalation_is_fully_caught_by_containment(fit: PipelineFit) -> None:
    """An inflated child ceiling is exactly what the amount-subset rule targets."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    variant = next(v for v in report.variant_results if v.variant == "budget_escalation")
    assert variant.rules_containment_recall == pytest.approx(1.0)


def test_unauthorized_subdelegation_is_mostly_not_caught_by_containment(fit: PipelineFit) -> None:
    """Containment checks authority width, not agent identity continuity -- an honest gap.

    A small nonzero fraction is expected, not a bug: a subdelegation child's
    own scope faithfully matches its parent's, so none of the dedicated
    scope/expiry rules fire on it -- but the sibling-cap ledger tracks total
    committed capacity per parent across every child regardless of which
    variant it belongs to, so a subdelegation child occasionally gets caught
    purely because it happens to share a parent with an unrelated,
    already-committed over-cap sibling. See docs/adr/0004.
    """
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    variant = next(v for v in report.variant_results if v.variant == "unauthorized_subdelegation")
    assert variant.rules_containment_recall < 0.10


def test_fanout_structuring_is_partially_caught(fit: PipelineFit) -> None:
    """The sibling-cap rule should catch some but not all of a fan-out group."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    variant = next(v for v in report.variant_results if v.variant == "fanout_structuring")
    assert 0.0 < variant.rules_containment_recall < 1.0


def test_result_is_reproducible(fit: PipelineFit) -> None:
    """The same fit and held-out corpus must produce the same report twice."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    first = run_containment_evaluation(fit, held_out)
    second = run_containment_evaluation(fit, held_out)
    assert first.full_recall == second.full_recall
    assert first.rules_containment_recall == second.rules_containment_recall


def test_model_object_identity_is_unchanged(fit: PipelineFit) -> None:
    """Running the evaluation must not mutate or replace the frozen model."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    model_before = fit.model
    run_containment_evaluation(fit, held_out)
    assert fit.model is model_before


def test_rejects_a_held_out_corpus_with_no_attacks(fit: PipelineFit) -> None:
    """An all-legitimate corpus has nothing to evaluate recall over."""
    corpus = build_held_out_corpus(300, seed=90206)
    all_legitimate = replace(
        corpus, labeled_sessions=tuple(s for s in corpus.labeled_sessions if not s.is_attack)
    )
    with pytest.raises(ValueError, match="no attack sessions"):
        run_containment_evaluation(fit, all_legitimate)


def test_formatted_report_states_the_one_shot_framing(fit: PipelineFit) -> None:
    """The report must be legible about what it is and isn't, without external context."""
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED)
    report = run_containment_evaluation(fit, held_out)
    rendered = format_containment_report(report)
    assert "evaluated once" in rendered.lower()
    assert "containment" in rendered.lower()


def test_legitimate_delegation_gives_a_real_nonvacuous_fp_measurement(fit: PipelineFit) -> None:
    """With `n_legitimate_delegation` set, the FP count is a real measurement, not a non-event.

    Unlike `test_containment_never_blocks_legitimate_traffic` above (which
    covers the default corpus, where no legitimate session ever declares a
    `parent_mandate_id` and the zero is structural), this corpus adds
    genuinely in-bounds delegated mandates from `generator.attacks.
    legitimate_delegation` -- see that module's own zero-false-positive
    claim in isolation, tested directly in
    `tests/test_legitimate_delegation.py`. Mixed into this held-out corpus
    alongside the mandate-chaining attack class, a low, nonzero, and fully
    explained false-positive count is expected: the two generators
    independently draw from the same eligible-parent pool, and an
    accepted `fanout_structuring` attack sibling can (correctly) consume
    real parent budget a legitimate sibling then finds itself short of --
    see docs/adr/0004's addendum. Every false positive here must trace to
    that one already-disclosed mechanism (`sibling_cap_exceeds_parent_
    remaining`), never to one of the four scope/expiry-subset rules -- if
    the merchant-ID or any other subset rule ever contributes here, that is
    a real bug, not the known/disclosed effect.
    """
    n_delegation = 200
    held_out = build_held_out_corpus(_HELD_OUT_SESSIONS, seed=_HELD_OUT_SEED, n_legitimate_delegation=n_delegation)
    report = run_containment_evaluation(fit, held_out)

    # Sibling-fanout groups can push the realized count above the target --
    # see generate_legitimate_delegation_sessions's own docstring.
    assert report.n_legitimate_delegation >= n_delegation
    total_fp = sum(v.false_positives for v in report.legitimate_delegation_variant_results)
    assert total_fp == report.containment_false_positives
    # Generously bounded, not asserted exactly, since it depends on how many
    # fanout_structuring first-siblings happen to land on a shared parent.
    assert total_fp / report.n_legitimate_delegation < 0.10
    assert set(report.legitimate_delegation_reason_counts) <= {"sibling_cap_exceeds_parent_remaining"}
