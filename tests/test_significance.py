"""Tests for `eval.significance`: paired McNemar testing."""

from __future__ import annotations

import numpy as np
import pytest

from eval.significance import mcnemar_test


def test_challenger_strictly_better_is_significant_and_favored() -> None:
    """A one-sided, large, consistent improvement must register as significant."""
    baseline_correct = np.array([True] * 20 + [False] * 30)
    challenger_correct = np.array([True] * 20 + [True] * 25 + [False] * 5)
    result = mcnemar_test(baseline_correct, challenger_correct)
    assert result.significant
    assert result.favors_challenger


def test_identical_performance_on_discordant_pairs_is_not_significant() -> None:
    """A even split of disagreements must not be called significant."""
    baseline_correct = np.array([True, False] * 20)
    challenger_correct = np.array([False, True] * 20)
    result = mcnemar_test(baseline_correct, challenger_correct)
    assert not result.significant
    assert not result.favors_challenger


def test_baseline_better_is_not_reported_as_favoring_challenger() -> None:
    """A significant result favoring the baseline must not be mislabeled."""
    baseline_correct = np.array([True] * 25 + [False] * 5)
    challenger_correct = np.array([False] * 25 + [False] * 5)
    result = mcnemar_test(baseline_correct, challenger_correct)
    assert result.significant
    assert not result.favors_challenger


def test_rejects_mismatched_lengths() -> None:
    """The two arrays must describe the same paired sessions."""
    with pytest.raises(ValueError, match="rows"):
        mcnemar_test(np.array([True, False]), np.array([True]))


def test_rejects_zero_discordant_pairs() -> None:
    """Perfect agreement leaves nothing for the test to compare."""
    same = np.array([True, False, True, True])
    with pytest.raises(ValueError, match="discordant"):
        mcnemar_test(same, same)