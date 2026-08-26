"""Bootstrap confidence intervals for the ranking metrics.

A single AUC-PR figure says nothing about how much of it is sampling noise. On
a corpus where attacks sit at a low single-digit base rate, the positive class
in a held-out test block is small enough that the interval is wide enough to
matter, and reporting the point estimate alone would overstate what the
evaluation actually establishes.

The resampling is stratified: each resample draws the positive rows and the
negative rows separately, with replacement, preserving the original class
counts. Unstratified resampling of a rare-positive dataset produces occasional
resamples with very few or zero attacks, where AUC-PR is unstable or undefined
-- discarding those biases the interval, and keeping them makes it meaningless.
Stratification also matches the question being asked, which is how much the
metric moves given this much attack traffic, not how much it moves if the base
rate itself were resampled.

Intervals are percentile intervals. BCa would be a defensible refinement but
needs an acceleration estimate from a jackknife over the whole dataset, and on
a metric this smooth the correction is small relative to the interval width;
the percentile form is stated here rather than left implicit.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_RESAMPLES = 1000
DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_BOOTSTRAP_SEED = 42

# A resample that loses an entire class makes most metrics undefined. Under
# stratified resampling this can only happen when a class is a single row, so a
# run that trips this ceiling has a corpus problem, not a resampling problem.
MAX_DEGENERATE_RESAMPLE_FRACTION = 0.01

MetricFn = Callable[[np.ndarray, np.ndarray], float]


@dataclass(frozen=True)
class BootstrapInterval:
    """A point estimate with its bootstrap percentile confidence interval.

    Attributes:
        point_estimate: The metric computed on the original sample.
        lower: Lower percentile bound.
        upper: Upper percentile bound.
        confidence_level: The nominal coverage, e.g. 0.95.
        n_resamples: How many resamples the interval was built from.
        standard_error: Standard deviation of the resampled metric values, a
            useful companion to the interval when comparing two runs.
    """

    point_estimate: float
    lower: float
    upper: float
    confidence_level: float
    n_resamples: int
    standard_error: float

    @property
    def width(self) -> float:
        """Width of the interval.

        Returns:
            `upper - lower`.
        """
        return self.upper - self.lower


def bootstrap_metric(
    y_true: np.ndarray,
    y_score: np.ndarray,
    metric: MetricFn,
    n_resamples: int = DEFAULT_RESAMPLES,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> BootstrapInterval:
    """Builds a stratified bootstrap percentile interval for one metric.

    Args:
        y_true: Ground-truth `is_attack` labels.
        y_score: Per-row scores, higher meaning more attack-like.
        metric: A function of (labels, scores) returning a scalar. Called once
            on the original sample and once per resample, so an expensive
            metric makes this expensive.
        n_resamples: Number of bootstrap resamples. Must be positive.
        confidence_level: Nominal coverage, in (0, 1).
        seed: Seed for the resampling generator, so an interval reproduces
            exactly from a clean clone rather than only approximately.

    Returns:
        The point estimate and its interval.

    Raises:
        ValueError: If the arrays are mismatched or empty, if `n_resamples` is
            not positive, if `confidence_level` is outside (0, 1), if either
            class is absent, or if too many resamples produced an undefined
            metric value. The last case is reported rather than silently
            dropped: an interval built from a filtered subset of resamples is
            not the interval it claims to be.
    """
    labels = np.asarray(y_true, dtype=bool)
    scores = np.asarray(y_score, dtype=np.float64)
    if labels.shape != scores.shape:
        raise ValueError(f"y_true has shape {labels.shape} but y_score has {scores.shape}")
    if labels.size == 0:
        raise ValueError("cannot bootstrap over zero rows")
    if n_resamples <= 0:
        raise ValueError(f"n_resamples must be positive, got {n_resamples}")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError(f"confidence_level must be in (0, 1), got {confidence_level}")

    positive_indices = np.flatnonzero(labels)
    negative_indices = np.flatnonzero(~labels)
    if positive_indices.size == 0 or negative_indices.size == 0:
        raise ValueError(
            f"stratified bootstrap needs both classes, got {positive_indices.size} positive "
            f"and {negative_indices.size} negative rows"
        )

    point_estimate = float(metric(labels, scores))

    rng = np.random.default_rng(seed)
    samples: list[float] = []
    degenerate = 0
    for _ in range(n_resamples):
        drawn = np.concatenate(
            [
                rng.choice(positive_indices, size=positive_indices.size, replace=True),
                rng.choice(negative_indices, size=negative_indices.size, replace=True),
            ]
        )
        resampled_labels = labels[drawn]
        try:
            samples.append(float(metric(resampled_labels, scores[drawn])))
        except ValueError:
            # The metric itself declared the resample undefined; counted rather
            # than swallowed, and the count is checked below.
            degenerate += 1

    if degenerate > n_resamples * MAX_DEGENERATE_RESAMPLE_FRACTION:
        raise ValueError(
            f"{degenerate} of {n_resamples} resamples produced an undefined metric; the "
            f"sample is too small or too imbalanced for a meaningful interval"
        )

    resampled = np.array(samples, dtype=np.float64)
    tail = (1.0 - confidence_level) / 2.0
    lower, upper = np.quantile(resampled, [tail, 1.0 - tail])

    interval = BootstrapInterval(
        point_estimate=point_estimate,
        lower=float(lower),
        upper=float(upper),
        confidence_level=confidence_level,
        n_resamples=resampled.size,
        standard_error=float(resampled.std(ddof=1)),
    )
    logger.info(
        "bootstrap: estimate=%.4f ci=[%.4f, %.4f] over %d resamples",
        interval.point_estimate,
        interval.lower,
        interval.upper,
        interval.n_resamples,
    )
    return interval
