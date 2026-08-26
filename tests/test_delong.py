"""Correctness tests for the hand-rolled DeLong estimator.

A hand-rolled significance test that is merely exercised is worse than no test
at all: it produces p-values that look authoritative and may be wrong. This
module checks the implementation four independent ways.

1. The structural components are verified element by element against a
   four-row case whose placement values are computed by hand from the
   definition, and the fast midrank path is checked against a brute-force
   O(n_pos * n_neg) comparison on random data containing ties.
2. The AUC the estimator derives is checked against two independent
   implementations, `eval.metrics.roc_auc` and scikit-learn's.
3. The closed-form variance is checked against a hand-computed reference. The
   construction that makes this possible is a constant baseline score: its
   placement values are identically 0.5, so its variance and its covariance
   with any challenger are exactly zero, and the variance of the difference
   collapses to the variance of the challenger's own AUC -- a quantity small
   enough to compute on paper.
4. The same closed-form standard error is checked against a bootstrap
   estimate of the standard deviation of the AUC difference on a realistically
   sized dataset. The two are derived by completely different routes and agree
   to within sampling error.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score  # type: ignore[import-untyped]

from eval.delong import DeLongResult, delong_test, structural_components
from eval.metrics import roc_auc

# A four-row case small enough to compute every placement value by hand.
#
#   positives: 0.9, 0.4        negatives: 0.6, 0.4
#
#   V10 (fraction of negatives each positive outranks, ties at 0.5):
#     0.9 beats 0.6 and 0.4                  -> 2.0 / 2 = 1.00
#     0.4 loses to 0.6, ties 0.4             -> 0.5 / 2 = 0.25
#   V01 (fraction of positives outranking each negative, ties at 0.5):
#     0.6 is beaten by 0.9 only              -> 1.0 / 2 = 0.50
#     0.4 is beaten by 0.9, tied by 0.4      -> 1.5 / 2 = 0.75
#
#   AUC = mean(V10) = mean(V01) = 0.625
_HAND_LABELS = np.array([True, True, False, False])
_HAND_SCORES = np.array([0.9, 0.4, 0.6, 0.4])
_HAND_POSITIVE_COMPONENTS = np.array([1.00, 0.25])
_HAND_NEGATIVE_COMPONENTS = np.array([0.50, 0.75])
_HAND_AUC = 0.625

# Var(AUC) = Var(V10)/n_pos + Var(V01)/n_neg, sample variance with ddof=1:
#   Var(V10) = (0.375^2 + 0.375^2) / 1 = 0.28125
#   Var(V01) = (0.125^2 + 0.125^2) / 1 = 0.03125
#   Var(AUC) = 0.28125 / 2 + 0.03125 / 2 = 0.15625
_HAND_AUC_VARIANCE = 0.15625


def _brute_force_components(
    positive_scores: np.ndarray, negative_scores: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """Computes placement values straight from the definition, pair by pair.

    Deliberately the slow, obvious implementation: it is the reference the
    midrank shortcut is checked against.

    Args:
        positive_scores: Scores of the rows labelled attack.
        negative_scores: Scores of the rows labelled legitimate.

    Returns:
        A tuple of (positive components, negative components).
    """
    kernel = np.where(
        positive_scores[:, None] > negative_scores[None, :],
        1.0,
        np.where(positive_scores[:, None] == negative_scores[None, :], 0.5, 0.0),
    )
    return kernel.mean(axis=1), kernel.mean(axis=0)


def test_structural_components_match_the_hand_computed_case() -> None:
    """Placement values must match the definition on a case computed on paper."""
    positive, negative = structural_components(_HAND_SCORES[:2], _HAND_SCORES[2:])
    np.testing.assert_allclose(positive, _HAND_POSITIVE_COMPONENTS)
    np.testing.assert_allclose(negative, _HAND_NEGATIVE_COMPONENTS)


def test_component_means_both_equal_the_auc() -> None:
    """Both placement-value means must equal the AUC, as the estimator assumes."""
    positive, negative = structural_components(_HAND_SCORES[:2], _HAND_SCORES[2:])
    assert positive.mean() == pytest.approx(_HAND_AUC)
    assert negative.mean() == pytest.approx(_HAND_AUC)
    assert roc_auc(_HAND_LABELS, _HAND_SCORES) == pytest.approx(_HAND_AUC)
    assert float(roc_auc_score(_HAND_LABELS, _HAND_SCORES)) == pytest.approx(_HAND_AUC)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_midrank_components_match_brute_force_with_ties(seed: int) -> None:
    """The fast midrank path must equal the pairwise definition, ties included."""
    rng = np.random.default_rng(seed)
    # Coarsely quantised scores guarantee heavy tying, which is the case the
    # midrank shortcut has to get right.
    positive_scores = rng.integers(0, 5, size=40).astype(np.float64)
    negative_scores = rng.integers(0, 5, size=90).astype(np.float64)

    fast_positive, fast_negative = structural_components(positive_scores, negative_scores)
    slow_positive, slow_negative = _brute_force_components(positive_scores, negative_scores)

    np.testing.assert_allclose(fast_positive, slow_positive)
    np.testing.assert_allclose(fast_negative, slow_negative)


def test_variance_matches_the_hand_computed_reference() -> None:
    """The closed-form variance must reproduce a value computed by hand.

    A constant baseline has zero-variance placement values and zero covariance
    with anything, so `Var(challenger - baseline)` reduces exactly to
    `Var(challenger)`, which the module header computes on paper.
    """
    constant_baseline = np.full(_HAND_LABELS.size, 0.5)
    result = delong_test(_HAND_LABELS, constant_baseline, _HAND_SCORES)

    assert result.standard_error**2 == pytest.approx(_HAND_AUC_VARIANCE, rel=1e-12)
    assert result.challenger_auc == pytest.approx(_HAND_AUC)
    assert result.baseline_auc == pytest.approx(0.5)
    assert result.baseline_is_degenerate is True


def test_standard_error_agrees_with_a_bootstrap_estimate() -> None:
    """The closed form must match a bootstrap of the same quantity.

    This is the check that the variance estimator is right rather than merely
    self-consistent: the bootstrap arrives at the standard deviation of the AUC
    difference by resampling, sharing no algebra with the closed form.
    """
    rng = np.random.default_rng(2024)
    n = 4000
    labels = rng.random(n) < 0.12
    baseline = np.clip(rng.normal(loc=labels * 0.6, scale=1.0), -4, 4)
    # Correlated with the baseline on purpose: an uncorrelated pair would not
    # exercise the covariance terms that are the whole point of DeLong.
    challenger = baseline * 0.7 + rng.normal(loc=labels * 0.9, scale=0.6)

    closed_form = delong_test(labels, baseline, challenger).standard_error

    positive_indices = np.flatnonzero(labels)
    negative_indices = np.flatnonzero(~labels)
    resample_rng = np.random.default_rng(99)
    differences = []
    for _ in range(600):
        drawn = np.concatenate(
            [
                resample_rng.choice(positive_indices, positive_indices.size, replace=True),
                resample_rng.choice(negative_indices, negative_indices.size, replace=True),
            ]
        )
        resampled_labels = labels[drawn]
        differences.append(
            roc_auc(resampled_labels, challenger[drawn])
            - roc_auc(resampled_labels, baseline[drawn])
        )

    bootstrap_standard_error = float(np.std(differences, ddof=1))
    assert closed_form == pytest.approx(bootstrap_standard_error, rel=0.12)


def test_auc_fields_match_independent_implementations() -> None:
    """Both reported AUCs must agree with scikit-learn."""
    rng = np.random.default_rng(31)
    labels = rng.random(1200) < 0.2
    baseline = rng.random(1200)
    challenger = np.clip(rng.normal(loc=labels * 0.7, scale=0.4), 0.0, 1.0)

    result = delong_test(labels, baseline, challenger)
    assert result.baseline_auc == pytest.approx(float(roc_auc_score(labels, baseline)))
    assert result.challenger_auc == pytest.approx(float(roc_auc_score(labels, challenger)))
    assert result.auc_difference == pytest.approx(result.challenger_auc - result.baseline_auc)


def test_detects_a_genuinely_better_challenger() -> None:
    """A clearly stronger score must come out significant and in the right direction."""
    rng = np.random.default_rng(5)
    labels = rng.random(3000) < 0.15
    baseline = rng.random(3000)
    challenger = np.clip(rng.normal(loc=labels * 1.5, scale=0.5), -3, 3)

    result = delong_test(labels, baseline, challenger)
    assert result.challenger_auc > result.baseline_auc
    assert result.p_value < 0.001
    assert result.significant is True
    assert result.favors_challenger is True


def test_does_not_favor_a_challenger_that_is_merely_noise() -> None:
    """Two independent random scores must not produce a significant result."""
    rng = np.random.default_rng(6)
    labels = rng.random(3000) < 0.15
    result = delong_test(labels, rng.random(3000), rng.random(3000))
    assert result.favors_challenger is False


def test_favors_challenger_is_false_when_the_baseline_wins() -> None:
    """Significance alone must not be reported as favouring the challenger."""
    rng = np.random.default_rng(8)
    labels = rng.random(3000) < 0.15
    strong = np.clip(rng.normal(loc=labels * 1.5, scale=0.5), -3, 3)
    weak = rng.random(3000)

    result = delong_test(labels, strong, weak)
    assert result.significant is True
    assert result.auc_difference < 0
    assert result.favors_challenger is False


def test_flags_a_binary_baseline_as_degenerate() -> None:
    """A block/allow baseline must be marked so a report cannot omit the caveat."""
    rng = np.random.default_rng(41)
    labels = rng.random(1000) < 0.2
    binary = (rng.random(1000) < np.where(labels, 0.7, 0.05)).astype(np.float64)
    continuous = np.clip(rng.normal(loc=labels * 0.8, scale=0.4), 0.0, 1.0)

    assert delong_test(labels, binary, continuous).baseline_is_degenerate is True
    assert delong_test(labels, continuous, binary).baseline_is_degenerate is False


def test_rejects_identical_scores() -> None:
    """Identical rankings give a zero variance, which is not infinite confidence."""
    rng = np.random.default_rng(12)
    labels = rng.random(400) < 0.3
    scores = rng.random(400)
    with pytest.raises(ValueError, match="variance of the AUC difference is zero"):
        delong_test(labels, scores, scores)


def test_rejects_a_single_class() -> None:
    """AUC needs both classes present."""
    with pytest.raises(ValueError, match="needs both classes"):
        delong_test(np.array([True, True]), np.array([0.1, 0.2]), np.array([0.3, 0.4]))


def test_rejects_mismatched_shapes() -> None:
    """Mismatched inputs are a caller bug and must fail loudly."""
    with pytest.raises(ValueError, match="mismatched shapes"):
        delong_test(np.array([True, False]), np.array([0.1, 0.2]), np.array([0.3]))


def test_rejects_non_finite_scores() -> None:
    """A NaN score would silently corrupt the ranking."""
    with pytest.raises(ValueError, match="non-finite"):
        delong_test(
            np.array([True, False, True, False]),
            np.array([0.1, np.inf, 0.3, 0.4]),
            np.array([0.2, 0.3, 0.4, 0.5]),
        )


def test_structural_components_reject_an_absent_class() -> None:
    """A placement value is a fraction of a class that has to exist."""
    with pytest.raises(ValueError, match="need both classes"):
        structural_components(np.array([0.5]), np.array([]))


def test_result_is_frozen() -> None:
    """A reported test result must not be editable after the fact."""
    rng = np.random.default_rng(3)
    labels = rng.random(500) < 0.2
    result = delong_test(labels, rng.random(500), rng.random(500))
    assert isinstance(result, DeLongResult)
    with pytest.raises(AttributeError):
        result.p_value = 0.0  # type: ignore[misc]
