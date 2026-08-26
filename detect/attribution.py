"""SHAP feature attribution for the Layer 3 behavioral model.

This module explains what the model learned; it does not change what the
model decides. Attribution runs after training and calibration, over rows
the model has already scored, and produces two things: a global ranking (on
average, which features move the score most) and a per-session breakdown
(for one session, which features pushed its score up or down). The reasoning
layer that narrates individual decisions elsewhere in this project is the
intended consumer of the per-session breakdown; this module only computes
the numbers, it does not phrase them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
import shap  # type: ignore[import-untyped]

from detect.behavioral import BehavioralModel

logger = logging.getLogger(__name__)

DEFAULT_TOP_N = 10


@dataclass(frozen=True)
class AttributionResult:
    """SHAP attribution over a scored dataset.

    Attributes:
        feature_names: Column order matching `shap_values`.
        shap_values: Per-row, per-feature attribution. Shape
            (n_rows, n_features). A positive value pushed that row's score
            toward "attack"; negative pushed it toward "legitimate".
        mean_abs_shap: Global importance per feature: the mean absolute
            attribution across all rows, in `feature_names` order.
    """

    feature_names: tuple[str, ...]
    shap_values: np.ndarray
    mean_abs_shap: tuple[float, ...]


def compute_attribution(model: BehavioralModel, features: np.ndarray) -> AttributionResult:
    """Computes SHAP attribution for a model over a design matrix.

    Args:
        model: The fitted behavioral model to explain.
        features: Rows to explain, with columns in `model.feature_names`
            order. Typically a validation or test slice, not the full
            corpus — attribution cost scales with row count.

    Returns:
        The attribution result.

    Raises:
        ValueError: If `features` does not have `len(model.feature_names)`
            columns, or has zero rows.
    """
    if features.ndim != 2 or features.shape[1] != len(model.feature_names):
        raise ValueError(
            f"expected features with {len(model.feature_names)} columns "
            f"matching {model.feature_names}, got shape {features.shape}"
        )
    if features.shape[0] == 0:
        raise ValueError("cannot compute attribution over zero rows")

    explainer = shap.TreeExplainer(model.classifier)
    shap_values = np.asarray(explainer.shap_values(features))
    mean_abs = tuple(float(v) for v in np.mean(np.abs(shap_values), axis=0))

    logger.info("attribution computed over %d rows, %d features", features.shape[0], features.shape[1])
    return AttributionResult(feature_names=model.feature_names, shap_values=shap_values, mean_abs_shap=mean_abs)


def top_features(attribution: AttributionResult, top_n: int = DEFAULT_TOP_N) -> tuple[tuple[str, float], ...]:
    """Ranks features by global importance.

    Args:
        attribution: The attribution result to rank.
        top_n: Maximum number of features to return.

    Returns:
        (feature name, mean absolute SHAP value) pairs, most important
        first, at most `top_n` long.

    Raises:
        ValueError: If `top_n` is not positive.
    """
    if top_n <= 0:
        raise ValueError(f"top_n must be positive, got {top_n}")
    ranked = sorted(
        zip(attribution.feature_names, attribution.mean_abs_shap, strict=True), key=lambda pair: -pair[1]
    )
    return tuple(ranked[:top_n])


def explain_row(
    attribution: AttributionResult, row_index: int, top_n: int = DEFAULT_TOP_N
) -> tuple[tuple[str, float], ...]:
    """Ranks the features that most influenced one row's score.

    Intended for the reasoning layer: given a specific flagged session, this
    answers "what drove this particular score" rather than "what matters on
    average across the dataset."

    Args:
        attribution: The attribution result containing `row_index`.
        row_index: Row to explain, indexing into `attribution.shap_values`.
        top_n: Maximum number of features to return.

    Returns:
        (feature name, signed SHAP value) pairs, largest absolute
        contribution first, at most `top_n` long. A positive value pushed
        the score toward "attack"; negative pushed toward "legitimate".

    Raises:
        ValueError: If `row_index` is out of range or `top_n` is not
            positive.
    """
    if top_n <= 0:
        raise ValueError(f"top_n must be positive, got {top_n}")
    if not 0 <= row_index < attribution.shap_values.shape[0]:
        raise ValueError(f"row_index {row_index} out of range for {attribution.shap_values.shape[0]} rows")

    row = attribution.shap_values[row_index]
    ranked = sorted(zip(attribution.feature_names, row, strict=True), key=lambda pair: -abs(pair[1]))
    return tuple((name, float(value)) for name, value in ranked[:top_n])