"""Tests for corpus assembly and the rules-baseline evaluation."""

from __future__ import annotations

import pytest

from common.schema import AttackClass
from eval.gate import format_gate_report, run_gate_evaluation
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus
from generator.attacks.impersonation import VARIANT_BEHAVIORAL_ONLY
from generator.attacks.replay import VARIANT_RAPID_REUSE

N_LEGIT = 2000
SEED = 42


@pytest.fixture(scope="module")
def corpus() -> EvaluationCorpus:
    """Builds one shared evaluation corpus for the module.

    Returns:
        The mixed corpus.
    """
    return build_evaluation_corpus(N_LEGIT, seed=SEED)


def test_corpus_is_chronologically_ordered(corpus: EvaluationCorpus) -> None:
    """The budget rule is stateful, so ordering is a correctness property."""
    starts = [s.trace.started_at for s in corpus.labeled_sessions]
    assert starts == sorted(starts)


def test_corpus_hits_the_configured_base_rate(corpus: EvaluationCorpus) -> None:
    """The realized base rate must be close to the configured target."""
    assert 0.03 <= corpus.attack_base_rate <= 0.05


def test_corpus_contains_all_three_training_classes(corpus: EvaluationCorpus) -> None:
    """All three attack classes must be represented alongside legitimate traffic."""
    classes = {s.attack_class for s in corpus.labeled_sessions}
    assert classes == {
        AttackClass.LEGITIMATE,
        AttackClass.MANDATE_REPLAY,
        AttackClass.SCOPE_VIOLATION,
        AttackClass.AGENT_IMPERSONATION,
    }


def test_corpus_never_contains_the_held_out_class(corpus: EvaluationCorpus) -> None:
    """The held-out class must never appear in a training or tuning corpus.

    This is the mechanical guarantee behind that commitment, so it doesn't
    rest on remembering to keep it by hand.
    """
    assert all(s.attack_class is not AttackClass.MANDATE_CHAINING for s in corpus.labeled_sessions)


def test_corpus_is_reproducible() -> None:
    """The same seed must produce the same corpus, labels included."""
    a = build_evaluation_corpus(500, seed=3)
    b = build_evaluation_corpus(500, seed=3)
    assert [s.model_dump() for s in a.labeled_sessions] == [s.model_dump() for s in b.labeled_sessions]


def test_rejects_invalid_base_rate() -> None:
    """A base rate outside (0, 1) is a caller error."""
    with pytest.raises(ValueError, match="attack_base_rate"):
        build_evaluation_corpus(500, seed=3, attack_base_rate=1.5)


def test_rejects_base_rate_that_empties_a_class() -> None:
    """A corpus with an empty attack class would yield an unreadable per-class recall."""
    with pytest.raises(ValueError, match="leaves these classes empty"):
        build_evaluation_corpus(10, seed=3, attack_base_rate=0.01)


def test_every_session_resolves_to_the_mandate_it_presented(corpus: EvaluationCorpus) -> None:
    """Session-keyed resolution must not let a forged document displace a genuine one."""
    for labeled in corpus.labeled_sessions:
        assert corpus.resolver.resolve(labeled.trace.session_id) is not None


def test_baseline_produces_no_false_positives(corpus: EvaluationCorpus) -> None:
    """Any legitimate session the rules block is a scope-engine bug, not a judgement call.

    The legitimate generator constructs every session inside its own
    mandate's scope, so a false positive here can only mean the scope
    engine and the generator disagree about what the mandate says.
    """
    report = run_gate_evaluation(corpus)
    assert report.false_positives == 0, report.false_positive_rules


def test_rules_baseline_leaves_headroom_for_a_behavioral_layer(corpus: EvaluationCorpus) -> None:
    """Rules alone must not catch everything.

    If this fails, the attacks have become trivially separable and the
    generator needs hardening before any model is worth training.
    """
    report = run_gate_evaluation(corpus)
    assert report.recall < 0.95


def test_rules_invisible_variants_are_invisible_to_the_rules(corpus: EvaluationCorpus) -> None:
    """Rapid reuse and behavioral-only impersonation must survive both deterministic layers.

    These two variants define the space a behavioral model has to earn.
    Non-zero recall here would mean a deterministic rule is picking up a
    signal it was never designed to see, making the numbers misleading.
    """
    report = run_gate_evaluation(corpus)
    by_class = {b.attack_class: b for b in report.per_class}
    assert by_class[AttackClass.MANDATE_REPLAY].recall_by_variant[VARIANT_RAPID_REUSE] == 0.0
    assert by_class[AttackClass.AGENT_IMPERSONATION].recall_by_variant[VARIANT_BEHAVIORAL_ONLY] == 0.0


def test_gate_report_renders(corpus: EvaluationCorpus) -> None:
    """The report must render without error and name every class."""
    text = format_gate_report(run_gate_evaluation(corpus))
    for attack_class in (
        AttackClass.MANDATE_REPLAY,
        AttackClass.SCOPE_VIOLATION,
        AttackClass.AGENT_IMPERSONATION,
    ):
        assert attack_class.value in text