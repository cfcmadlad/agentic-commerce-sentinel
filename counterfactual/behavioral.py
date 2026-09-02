"""Minimal-edit counterfactual for a Layer 3 (behavioral) block.

Layer 3 has no closed-form encoding to consult -- `formal/__init__.py`
states why it is never Z3-encoded. This module instead searches the real
fitted model directly: bisection against `BehavioralModel.predict_proba`,
one feature at a time, prioritized by that session's own SHAP attribution.

This is a heuristic, not an exhaustive search of the model's decision
surface. Two things it is deliberately not:

- Not a claim of the smallest possible perturbation in any global sense --
  only the smallest this greedy, single-feature-at-a-time search found
  among the session's top contributing features, holding every other
  feature fixed. A smaller multi-feature perturbation, or one along a
  feature outside the search order, may exist and go unreported.
- Not assumed monotonic by direction. A prior version of this design
  assumed "reduce every suspicious feature toward zero," which is wrong for
  at least one real feature this project ships: a *low*
  `hours_since_agent_last_session` (rapid reuse) is the suspicious
  direction, so *increasing* it, not decreasing it, is what would need to
  happen. This module never assumes a direction -- it bisects toward
  whichever side of each feature's real value the model's own output
  actually moves the score down, discovered by calling `predict_proba`,
  never guessed from the feature's name or its SHAP sign.

Two feature classes are excluded from the search entirely, not merely
deprioritized: `hour_of_day` and `day_of_week` (this project's standing
rule against day/calendar framing in anything that ships applies here --
"the score would drop if this had happened at a different hour" is exactly
that framing, whether or not the model in fact benefited from those
features). `has_catalog_browse`, `has_cart_build`, `has_mandate_presented`,
and `presented_a_mandate` are boolean flags, tested only as a single flip
(0 to 1 or the reverse), never bisected as if a fractional value between
them meant anything.

Why this is defense-only, stated explicitly rather than left implicit
(this project's own stated disqualification criterion is anything
offense-capable, so this needs to hold up to direct scrutiny). This
module does three things a genuinely offense-capable tool would not:

1. It only ever operates on a session that has already been decided, by
   the real pipeline, in the caller's own process -- never a live query
   against a running detector it does not already have the verdict for.
   There is no code path from here back into the attack generator
   (`generator/attacks/`), and no path that takes attacker-chosen input
   and asks "would this evade detection" before a real decision exists.
2. `bisect_search` (below) explores exactly one already-flagged session's
   own feature vector, one feature at a time, to explain that specific
   verdict to a human reviewer -- it is not a general search for evasive
   parameter regions across the model's input space, and produces nothing
   reusable against a session it was not given.
3. `service/main.py::decide()` deliberately never calls this module (see
   the comment at its own counterfactual-assembly call site) -- the one
   thing that WOULD make this offense-capable is handing a live "how to
   evade" recipe back to the same caller whose session was just blocked,
   over the one HTTP surface that caller can reach. Library-only, for a
   human reviewer working from an already-recorded audit entry, is the
   only use this module is wired for today.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

from detect.attribution import AttributionResult, explain_row
from detect.behavioral import BehavioralModel

logger = logging.getLogger(__name__)

DEFAULT_MAX_FEATURES = 5  # matches reasoning.narrate.DEFAULT_NARRATION_TOP_N
DEFAULT_BISECTION_ITERATIONS = 30
DEFAULT_UPWARD_SEARCH_MULTIPLIER = 5.0
DEFAULT_UPWARD_SEARCH_FLOOR = 1.0  # span used when a feature's real value is exactly 0

_EXCLUDED_FEATURES = frozenset({"hour_of_day", "day_of_week"})
_BINARY_FEATURES = frozenset(
    {"has_catalog_browse", "has_cart_build", "has_mandate_presented", "presented_a_mandate"}
)


@dataclass(frozen=True)
class BehavioralFieldEdit:
    """One feature this counterfactual changes, real value to suggested value.

    Attributes:
        feature: The feature name, from `features.session.feature_names`.
        real_value: The feature's actual value in the flagged session.
        suggested_value: The value that would need to hold instead.
        shap_contribution: This feature's signed SHAP contribution in the
            real session, for context on why it was chosen.
    """

    feature: str
    real_value: float
    suggested_value: float
    shap_contribution: float


@dataclass(frozen=True)
class BehavioralCounterfactual:
    """Layer 3's counterfactual explanation for a behaviorally blocked session.

    Attributes:
        feasible: True if an edit within this search's scope brought the
            score below the threshold.
        edits: The features changed and their suggested values, in the
            order they were applied. May be non-empty even when `feasible`
            is False -- partial progress toward, but not across, the
            threshold.
        resulting_score: The model's score after applying every edit in
            `edits`.
        explanation: A plain-language sentence stating the edit and this
            method's own limits, or why no crossing was found.
    """

    feasible: bool
    edits: tuple[BehavioralFieldEdit, ...]
    resulting_score: float
    explanation: str


def _score_with(model: BehavioralModel, row: np.ndarray, index: int, value: float) -> float:
    """Scores a row with one feature temporarily overridden.

    Args:
        model: The fitted model to score with.
        row: The design-matrix row, shape (1, n_features). Mutated
            temporarily and restored before returning.
        index: Column index of the feature to override.
        value: The value to substitute.

    Returns:
        The model's score with that one substitution in effect.
    """
    saved = row[0, index]
    row[0, index] = value
    score = float(model.predict_proba(row)[0])
    row[0, index] = saved
    return score


def _find_boundary(
    model: BehavioralModel,
    row: np.ndarray,
    index: int,
    real_value: float,
    threshold: float,
    far_value: float,
    iterations: int,
) -> float | None:
    """Bisects for the value closest to `real_value`, toward `far_value`, that clears the threshold.

    Args:
        model: The fitted model to search against.
        row: The current working row (every other feature already at its
            chosen value). Not mutated on return.
        index: Column index of the feature being searched.
        real_value: The feature's current value in `row`, one endpoint of
            the search.
        threshold: The score cutoff to clear (strictly below it).
        far_value: The other endpoint of the search -- the direction being
            tried (below or above `real_value`).
        iterations: Number of bisection steps.

    Returns:
        The boundary value if `far_value` clears the threshold, else None
        (this direction does not help within the tried span).
    """
    if _score_with(model, row, index, far_value) >= threshold:
        return None

    infeasible, feasible = real_value, far_value
    for _ in range(iterations):
        midpoint = (infeasible + feasible) / 2.0
        if _score_with(model, row, index, midpoint) < threshold:
            feasible = midpoint
        else:
            infeasible = midpoint
    return feasible


def behavioral_counterfactual(
    model: BehavioralModel,
    row: np.ndarray,
    attribution: AttributionResult,
    row_index: int,
    threshold: float,
    max_features: int = DEFAULT_MAX_FEATURES,
) -> BehavioralCounterfactual | None:
    """Searches for the smallest feature edit that clears a blocked session's threshold.

    Args:
        model: The fitted Layer 3 model.
        row: The session's design-matrix row, shape (1, n_features). Not
            mutated -- a working copy is made internally.
        attribution: SHAP attribution containing this session's row, used
            only to prioritize search order, never to decide direction.
        row_index: This session's row index into `attribution`.
        threshold: The calibrated operating threshold.
        max_features: Maximum number of top-contributing features to try,
            in descending order of `|SHAP value|`.

    Returns:
        None if the session's score is already below the threshold
        (nothing to explain). Otherwise the counterfactual -- `feasible`
        states whether the search actually crossed the threshold within
        its scope; see the module docstring for what this search does and
        does not claim.

    Raises:
        ValueError: If `row` is not a single-row design matrix matching
            `model.feature_names`, or `max_features` is not positive.
    """
    if row.ndim != 2 or row.shape[0] != 1 or row.shape[1] != len(model.feature_names):
        raise ValueError(
            f"expected a single row with {len(model.feature_names)} columns matching "
            f"{model.feature_names}, got shape {row.shape}"
        )
    if max_features <= 0:
        raise ValueError(f"max_features must be positive, got {max_features}")

    working = row.copy()
    original_score = float(model.predict_proba(working)[0])
    if original_score < threshold:
        return None

    ranked = explain_row(attribution, row_index, top_n=len(model.feature_names))
    candidates = [(name, contribution) for name, contribution in ranked if name not in _EXCLUDED_FEATURES]
    feature_index = {name: i for i, name in enumerate(model.feature_names)}

    edits: list[BehavioralFieldEdit] = []
    for name, contribution in candidates[:max_features]:
        if float(model.predict_proba(working)[0]) < threshold:
            break

        index = feature_index[name]
        real_value = float(working[0, index])

        if name in _BINARY_FEATURES:
            flipped = 1.0 - real_value
            if _score_with(model, working, index, flipped) < threshold:
                working[0, index] = flipped
                edits.append(BehavioralFieldEdit(name, real_value, flipped, contribution))
            continue

        downward = _find_boundary(
            model, working, index, real_value, threshold, far_value=0.0, iterations=DEFAULT_BISECTION_ITERATIONS
        )
        upward_span = max(real_value, DEFAULT_UPWARD_SEARCH_FLOOR) * DEFAULT_UPWARD_SEARCH_MULTIPLIER
        upward = _find_boundary(
            model,
            working,
            index,
            real_value,
            threshold,
            far_value=real_value + upward_span,
            iterations=DEFAULT_BISECTION_ITERATIONS,
        )
        found = [v for v in (downward, upward) if v is not None]
        if not found:
            continue

        best = min(found, key=lambda v: abs(v - real_value))
        working[0, index] = best
        edits.append(BehavioralFieldEdit(name, real_value, best, contribution))

    final_score = float(model.predict_proba(working)[0])
    feasible = final_score < threshold
    explanation = _explain(edits, feasible, final_score, threshold)
    logger.info(
        "behavioral_counterfactual: %d field(s) edited, feasible=%s, score %.4f -> %.4f",
        len(edits),
        feasible,
        original_score,
        final_score,
    )
    return BehavioralCounterfactual(
        feasible=feasible, edits=tuple(edits), resulting_score=final_score, explanation=explanation
    )


def _explain(edits: list[BehavioralFieldEdit], feasible: bool, final_score: float, threshold: float) -> str:
    """Renders the counterfactual result as one plain-language sentence.

    Args:
        edits: The edits found, in application order.
        feasible: Whether the edits crossed the threshold.
        final_score: The score after applying every edit.
        threshold: The calibrated operating threshold.

    Returns:
        The explanation text.
    """
    method_note = (
        "This is a greedy search along the top contributing features, holding every other "
        "feature fixed -- not an exhaustive search of the model's decision surface."
    )
    if not edits:
        return (
            "No behavioral counterfactual is available: no edit to this session's top "
            f"contributing features, within this search's scope, moves the score ({final_score:.4f}) "
            f"below the {threshold:.4f} threshold. {method_note}"
        )
    clauses = ", ".join(
        f"{edit.feature} were {edit.suggested_value:.4f} (currently {edit.real_value:.4f})" for edit in edits
    )
    if feasible:
        return (
            f"The score would drop to {final_score:.4f}, below the {threshold:.4f} threshold, "
            f"if {clauses}. {method_note}"
        )
    return (
        f"Even with {clauses}, the score ({final_score:.4f}) does not drop below the "
        f"{threshold:.4f} threshold within this search's scope. {method_note}"
    )
