"""Layer 3: gradient-boosted behavioral model over the rules-allowed residual.

Layers 1 and 2 are exact and deterministic; they catch every session where
authorization itself is wrong. What remains after they run — the residual —
is, by construction, cryptographically genuine and in-scope. Any signal left
to find there is behavioral: how a session was paced, whether it looks like
the same agent's usual pattern. This module trains a classifier on exactly
that residual, so its reported performance is not inflated by re-catching
attacks the rules already catch.

The model is deterministic given its inputs (fixed random_state), and it
produces a score, not a verdict — `detect/ensemble.py` turns the score into a
decision using a calibrated threshold. The LLM reasoning layer that narrates
decisions elsewhere in this project reads this score but never sets it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Not tuned via search; a reasonable starting configuration for a small,
# high-class-imbalance tabular problem. Revisit if the ensemble evaluation's
# own diagnostics (train/val gap, calibration curve) suggest under- or overfit.
DEFAULT_RANDOM_STATE = 42
DEFAULT_MAX_ITER = 200
DEFAULT_MAX_DEPTH = 4
DEFAULT_LEARNING_RATE = 0.08
DEFAULT_L2_REGULARIZATION = 1.0
DEFAULT_EARLY_STOPPING_ROUNDS = 20

MIN_TRAINING_ROWS = 50
MIN_POSITIVE_CLASS_ROWS = 5


@dataclass(frozen=True)
class ChronologicalSplit:
    """Boolean row masks for a chronologically ordered dataset.

    Attributes:
        train: Rows used for model fitting.
        validation: Rows held out for threshold calibration.
        test: Rows held out for final, one-time evaluation.
    """

    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray


def chronological_split(n_rows: int, train_fraction: float, validation_fraction: float) -> ChronologicalSplit:
    """Splits row indices into ordered train/validation/test blocks by position.

    Args:
        n_rows: Total number of rows, already in chronological order.
        train_fraction: Fraction of rows assigned to train. Must be in (0, 1).
        validation_fraction: Fraction assigned to validation. Must be in
            (0, 1), and `train_fraction + validation_fraction` must be < 1
            so a non-empty test block remains.

    Returns:
        Boolean masks for each split, summing to `n_rows`.

    Raises:
        ValueError: If `n_rows` is not positive, if either fraction is
            outside (0, 1), or if the fractions leave no room for a test
            split.
    """
    if n_rows <= 0:
        raise ValueError(f"n_rows must be positive, got {n_rows}")
    if not 0.0 < train_fraction < 1.0 or not 0.0 < validation_fraction < 1.0:
        raise ValueError("train_fraction and validation_fraction must each be in (0, 1)")
    if train_fraction + validation_fraction >= 1.0:
        raise ValueError("train_fraction + validation_fraction must leave a non-empty test split")

    train_end = int(n_rows * train_fraction)
    validation_end = train_end + int(n_rows * validation_fraction)

    train = np.zeros(n_rows, dtype=bool)
    validation = np.zeros(n_rows, dtype=bool)
    test = np.zeros(n_rows, dtype=bool)
    train[:train_end] = True
    validation[train_end:validation_end] = True
    test[validation_end:] = True
    return ChronologicalSplit(train=train, validation=validation, test=test)


@dataclass(frozen=True)
class BehavioralModel:
    """A fitted Layer 3 classifier plus the feature contract it was trained on.

    Attributes:
        classifier: The fitted scikit-learn estimator.
        feature_names: Column order the classifier expects. Any caller
            building a design matrix for this model must match this order.
        random_state: The seed the classifier was fitted with, recorded for
            the reproducibility record rather than re-derived from the
            classifier internals.
    """

    classifier: HistGradientBoostingClassifier
    feature_names: tuple[str, ...]
    random_state: int

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """Scores rows with the probability of being an attack.

        Args:
            features: A design matrix with columns in `feature_names` order.

        Returns:
            One score per row, in [0, 1].

        Raises:
            ValueError: If `features` does not have `len(feature_names)`
                columns.
        """
        if features.ndim != 2 or features.shape[1] != len(self.feature_names):
            raise ValueError(
                f"expected features with {len(self.feature_names)} columns "
                f"matching {self.feature_names}, got shape {features.shape}"
            )
        return np.asarray(self.classifier.predict_proba(features)[:, 1], dtype=np.float64)


def train_behavioral_model(
    features: np.ndarray,
    labels: np.ndarray,
    feature_names: tuple[str, ...],
    random_state: int = DEFAULT_RANDOM_STATE,
) -> BehavioralModel:
    """Fits the Layer 3 classifier on the rules-allowed residual training set.

    Args:
        features: Training design matrix, rows already restricted by the
            caller to rules-allowed (residual) sessions.
        labels: Ground-truth `is_attack` labels, one per row.
        feature_names: Column order of `features`, recorded on the returned
            model so callers cannot silently misalign columns later.
        random_state: Seed controlling the classifier's internal randomness,
            for reproducibility.

    Returns:
        The fitted model.

    Raises:
        ValueError: If `features` and `labels` have mismatched lengths, if
            there are too few rows to fit meaningfully, or if the positive
            class is too sparse for a stable fit. These are gate conditions,
            not tuning knobs: a corpus too small to satisfy them needs to be
            regenerated larger, not silently fit anyway.
    """
    if len(features) != len(labels):
        raise ValueError(f"features has {len(features)} rows but labels has {len(labels)}")
    if len(features) < MIN_TRAINING_ROWS:
        raise ValueError(f"need at least {MIN_TRAINING_ROWS} training rows, got {len(features)}")
    n_positive = int(labels.sum())
    if n_positive < MIN_POSITIVE_CLASS_ROWS:
        raise ValueError(
            f"need at least {MIN_POSITIVE_CLASS_ROWS} positive (attack) training rows, "
            f"got {n_positive}; the residual set is too sparse to fit against"
        )

    classifier = HistGradientBoostingClassifier(
        max_iter=DEFAULT_MAX_ITER,
        max_depth=DEFAULT_MAX_DEPTH,
        learning_rate=DEFAULT_LEARNING_RATE,
        l2_regularization=DEFAULT_L2_REGULARIZATION,
        early_stopping=True,
        n_iter_no_change=DEFAULT_EARLY_STOPPING_ROUNDS,
        validation_fraction=0.15,
        random_state=random_state,
    )
    classifier.fit(features, labels)
    logger.info(
        "behavioral model fit: %d rows, %d positive, %d boosting iterations used",
        len(features),
        n_positive,
        classifier.n_iter_,
    )
    return BehavioralModel(classifier=classifier, feature_names=feature_names, random_state=random_state)