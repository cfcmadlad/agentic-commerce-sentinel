"""Paired significance testing for comparing two classifiers on the same sessions.

McNemar's test is the right tool here rather than comparing two accuracy
numbers directly: the rules-only baseline and the ensemble are evaluated on
the identical set of sessions, so their errors are paired, not independent.
The test only looks at sessions where the two classifiers disagree — one
correct and the other not — and asks whether that disagreement is skewed
toward the ensemble being right significantly more often than chance.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import binomtest  # type: ignore[import-untyped]

DEFAULT_ALPHA = 0.05


@dataclass(frozen=True)
class McNemarResult:
    """Outcome of a paired McNemar test between two classifiers.

    Attributes:
        baseline_only_correct: Sessions the baseline got right and the
            challenger got wrong.
        challenger_only_correct: Sessions the challenger got right and the
            baseline got wrong. The count that matters: this is where the
            ensemble is earning its keep.
        p_value: Two-sided exact binomial p-value on the discordant pairs.
        significant: Whether `p_value` is below `alpha`, favoring whichever
            side has the larger count.
        favors_challenger: True if the challenger significantly outperforms
            the baseline; False if the reverse or the result is not
            significant.
    """

    baseline_only_correct: int
    challenger_only_correct: int
    p_value: float
    significant: bool
    favors_challenger: bool


def mcnemar_test(
    baseline_correct: np.ndarray,
    challenger_correct: np.ndarray,
    alpha: float = DEFAULT_ALPHA,
) -> McNemarResult:
    """Runs an exact two-sided McNemar test on paired correctness arrays.

    Args:
        baseline_correct: Per-session boolean: did the baseline classify
            this session correctly.
        challenger_correct: Per-session boolean: did the challenger classify
            this session correctly, over the same sessions in the same
            order.
        alpha: Significance threshold.

    Returns:
        The test result.

    Raises:
        ValueError: If the two arrays have mismatched lengths, or if there
            are zero discordant pairs (the two classifiers agree on every
            session, so no directional claim can be tested).
    """
    if len(baseline_correct) != len(challenger_correct):
        raise ValueError(
            f"baseline_correct has {len(baseline_correct)} rows but "
            f"challenger_correct has {len(challenger_correct)}"
        )
    baseline_correct = np.asarray(baseline_correct, dtype=bool)
    challenger_correct = np.asarray(challenger_correct, dtype=bool)

    baseline_only = int(np.sum(baseline_correct & ~challenger_correct))
    challenger_only = int(np.sum(~baseline_correct & challenger_correct))
    discordant = baseline_only + challenger_only
    if discordant == 0:
        raise ValueError(
            "baseline and challenger agree on every session; McNemar's test is undefined "
            "with zero discordant pairs"
        )

    # scipy's .pvalue is numpy.float64; cast before comparing so `significant`
    # is a plain Python bool rather than numpy.bool_, which `and` would then
    # propagate unconverted into `favors_challenger` on the False branch.
    p_value = float(binomtest(challenger_only, discordant, p=0.5, alternative="two-sided").pvalue)
    significant = p_value < alpha
    favors_challenger = significant and challenger_only > baseline_only

    return McNemarResult(
        baseline_only_correct=baseline_only,
        challenger_only_correct=challenger_only,
        p_value=p_value,
        significant=significant,
        favors_challenger=favors_challenger,
    )