"""Tests for the held-out mandate-chaining corpus builder.

The one property that matters most here is negative: `build_held_out_corpus`
must be the only path that can ever produce a `MANDATE_CHAINING` session, and
`build_evaluation_corpus` (the training/tuning path) must remain completely
unaware this module exists.
"""

from __future__ import annotations

import pytest

import generator.attacks.corpus as training_corpus
from common.schema import AttackClass
from generator.attacks.held_out import build_held_out_corpus


def test_every_session_is_labeled_correctly() -> None:
    """Only legitimate and mandate-chaining labels may appear."""
    corpus = build_held_out_corpus(600, seed=90101)
    labels = {s.attack_class for s in corpus.labeled_sessions}
    assert labels <= {AttackClass.LEGITIMATE, AttackClass.MANDATE_CHAINING}
    assert AttackClass.MANDATE_CHAINING in labels


def test_realized_base_rate_is_close_to_target() -> None:
    """The realized rate must track the requested one, within rounding."""
    corpus = build_held_out_corpus(2000, seed=90102, attack_base_rate=0.2)
    assert corpus.attack_base_rate == pytest.approx(0.2, abs=0.02)


def test_sessions_are_chronologically_ordered() -> None:
    """The evaluation harness's stateful layers require ascending start times."""
    corpus = build_held_out_corpus(600, seed=90103)
    starts = [s.trace.started_at for s in corpus.labeled_sessions]
    assert starts == sorted(starts)


def test_variant_by_session_covers_every_attack() -> None:
    """Every attack session must have a recorded sub-variant."""
    corpus = build_held_out_corpus(600, seed=90104)
    for session in corpus.labeled_sessions:
        if session.is_attack:
            assert session.trace.session_id in corpus.variant_by_session


def test_resolver_can_resolve_every_presented_mandate() -> None:
    """Every session with a mandate_id must resolve to a signed mandate."""
    corpus = build_held_out_corpus(600, seed=90105)
    for session in corpus.labeled_sessions:
        if session.trace.mandate_id is not None:
            assert corpus.resolver.resolve(session.trace.session_id) is not None


def test_reproducible_for_fixed_seed() -> None:
    """The same (n_legitimate, seed) must reproduce byte-identically."""
    first = build_held_out_corpus(600, seed=90106)
    second = build_held_out_corpus(600, seed=90106)
    assert [s.trace.session_id for s in first.labeled_sessions] == [
        s.trace.session_id for s in second.labeled_sessions
    ]


def test_rejects_non_positive_n_legitimate() -> None:
    """A non-positive corpus size has nothing to build from."""
    with pytest.raises(ValueError, match="n_legitimate"):
        build_held_out_corpus(0, seed=1)


def test_rejects_out_of_range_attack_base_rate() -> None:
    """The base rate must be a genuine fraction."""
    with pytest.raises(ValueError, match="attack_base_rate"):
        build_held_out_corpus(600, seed=1, attack_base_rate=1.5)


def test_training_corpus_module_never_imports_the_held_out_path() -> None:
    """The training/tuning corpus builder must stay structurally unaware of chaining.

    This is the guarantee the whole held-out methodology rests on: it is
    enforced here as an import-graph check, not just documentation, so a
    future edit that wires the two together fails a test immediately rather
    than silently leaking the held-out class into a training run. Checks
    actual import statements, not any textual mention -- the module's own
    docstring names `AttackClass.MANDATE_CHAINING` precisely to document
    that it is absent, and that mention must not itself trip this guard.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(training_corpus))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)

    assert "generator.attacks.chaining" not in imported_modules
    assert "generator.attacks.held_out" not in imported_modules
