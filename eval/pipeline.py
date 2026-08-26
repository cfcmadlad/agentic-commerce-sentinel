"""One shared fit of the full detection stack, reusable by any evaluation.

`eval/milestone_a.py` performs this fit inline and reduces it immediately to a
precision/recall comparison. The fuller evaluation needs the same fit but keeps
the intermediate products -- the trained model, the per-row scores, the split
masks -- because AUC-PR, calibration, bootstrap intervals, DeLong and the cost
sweep are all computed from them. Rather than restating that sequence a second
time and risking two evaluation paths that quietly disagree, the sequence lives
here once and `tests/test_pipeline.py` asserts that the numbers it produces
match `run_milestone_a`'s on the same corpus.

The scoring convention, which every metric downstream depends on
----------------------------------------------------------------
The ensemble's decision rule is "block if the rules blocked, or if the
behavioral score reaches the threshold". An equivalent scalar score is
therefore `max(rules_blocked, behavioral_score)`, and since a behavioral score
never exceeds 1.0, that is exactly 1.0 for a rules-blocked session and the
behavioral score otherwise. Thresholding this score reproduces the ensemble's
verdict exactly at every threshold, which is what makes a threshold-free
ranking metric over it a statement about the deployed system rather than about
a component of it.

The rules-only baseline is scored 1.0 when it blocks and 0.0 when it allows.
That is the honest representation of what a rules engine emits -- a verdict,
not a ranking -- and it is the whole of the information the baseline provides.
Its consequences for AUC are spelled out in `eval/delong.py`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

from common.schema import LabeledSession
from detect.baseline import BaselineDecision, RulesOnlyBaseline
from detect.behavioral import (
    BehavioralModel,
    ChronologicalSplit,
    chronological_split,
    train_behavioral_model,
)
from detect.calibration import (
    DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    CalibrationResult,
    calibrate_threshold,
    sensitivity_sweep,
)
from features.session import FeatureExtractor, feature_names
from generator.attacks.corpus import EvaluationCorpus

logger = logging.getLogger(__name__)

DEFAULT_TRAIN_FRACTION = 0.6
DEFAULT_VALIDATION_FRACTION = 0.2
DEFAULT_RANDOM_STATE = 42

# Score assigned to a session the deterministic layers blocked. Layer 3 can
# never unblock one, so its decision is certain and its score saturates.
RULES_BLOCKED_SCORE = 1.0
RULES_ALLOWED_SCORE = 0.0


@dataclass(frozen=True)
class PipelineFit:
    """Everything one fit of the detection stack produced, on one corpus.

    Attributes:
        corpus: The corpus this fit was produced from.
        labels: Ground-truth `is_attack` per session, in corpus order.
        baseline_blocked: Rules-only block/allow per session.
        features: Design matrix in `features.session.feature_names()` order.
        split: Chronological train/validation/test masks.
        residual: Rules-allowed mask; the rows Layer 3 can act on.
        model: The fitted Layer 3 model.
        chosen_calibration: Calibration at the chosen cost ratio, from the
            validation residual.
        calibration_sweep: Calibration across the cost-ratio range.
        behavioral_score: Layer 3 score per session. Rules-blocked sessions
            are scored too, so the ensemble score is defined everywhere and
            the latency measurement reflects a uniform code path.
        ensemble_score: The deployed system's scalar score per session; see
            the module docstring for why it is defined this way.
        baseline_score: The rules-only baseline as a binary score.
    """

    corpus: EvaluationCorpus
    labels: np.ndarray
    baseline_blocked: np.ndarray
    features: np.ndarray
    split: ChronologicalSplit
    residual: np.ndarray
    model: BehavioralModel
    chosen_calibration: CalibrationResult
    calibration_sweep: tuple[CalibrationResult, ...]
    behavioral_score: np.ndarray
    ensemble_score: np.ndarray
    baseline_score: np.ndarray

    @property
    def threshold(self) -> float:
        """The calibrated operating threshold.

        Returns:
            The score cutoff at or above which Layer 3 alone blocks.
        """
        return self.chosen_calibration.threshold

    @property
    def ensemble_blocked(self) -> np.ndarray:
        """The ensemble's verdict per session at the calibrated threshold.

        Returns:
            A boolean block/allow array over the whole corpus.
        """
        return self.ensemble_score >= self.threshold

    def test_slice(self) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Extracts the held-out test block's labels and both scores.

        The whole test block, not just its rules-allowed residual: the
        question every reported metric answers is whether adding Layer 3
        improves detection over all traffic a deployment would see, not over
        the subset already selected to favour it.

        Returns:
            A tuple of (labels, baseline scores, ensemble scores) for the
            test block.
        """
        mask = self.split.test
        return self.labels[mask], self.baseline_score[mask], self.ensemble_score[mask]


def extract_features_causally(sessions: tuple[LabeledSession, ...]) -> np.ndarray:
    """Extracts the feature matrix over a chronologically ordered stream.

    A single extractor absorbs every session in order, legitimate and attack,
    blocked and allowed alike, matching a real feature store that logs every
    attempt regardless of downstream outcome. No feature depends on whether the
    current session was blocked, so this does not leak the target.

    Args:
        sessions: Sessions in ascending `started_at` order.

    Returns:
        A design matrix with columns in `feature_names()` order.

    Raises:
        ValueError: If `sessions` is empty.
    """
    if not sessions:
        raise ValueError("cannot extract features from zero sessions")
    names = feature_names()
    extractor = FeatureExtractor()
    rows = [extractor.extract(labeled.trace) for labeled in sessions]
    return np.array([[row[name] for name in names] for row in rows])


def fit_pipeline(
    corpus: EvaluationCorpus,
    train_fraction: float = DEFAULT_TRAIN_FRACTION,
    validation_fraction: float = DEFAULT_VALIDATION_FRACTION,
    cost_ratio: float = DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> PipelineFit:
    """Runs the rules layers, trains Layer 3, and calibrates a threshold.

    The training set is the training block's rules-allowed residual, so the
    model's reported performance is not inflated by re-catching attacks the
    deterministic layers already catch. The threshold is calibrated on the
    validation block's residual, never on the test block.

    Args:
        corpus: A chronologically ordered mixed corpus.
        train_fraction: Fraction of the corpus, by chronological position,
            used for model training.
        validation_fraction: Fraction used for threshold calibration.
        cost_ratio: False-negative-to-false-positive cost ratio driving the
            chosen threshold. An assumption; see `detect/calibration.py`.
        random_state: Seed for the model's internal randomness.

    Returns:
        The fit, with every intermediate product the evaluation needs.

    Raises:
        ValueError: If the corpus is empty, or as propagated from the split,
            training, or calibration steps when the corpus is too small or too
            sparse to support them. A corpus that trips those needs to be
            regenerated larger, not silently downgraded.
    """
    if not corpus.labeled_sessions:
        raise ValueError("cannot fit the pipeline over an empty corpus")

    sessions = corpus.labeled_sessions
    n_sessions = len(sessions)

    baseline = RulesOnlyBaseline(corpus.registry, corpus.resolver)
    decisions: tuple[BaselineDecision, ...] = baseline.decide_all(s.trace for s in sessions)
    baseline_blocked = np.array([decision.blocked for decision in decisions])

    features = extract_features_causally(sessions)
    labels = np.array([session.is_attack for session in sessions])

    split = chronological_split(n_sessions, train_fraction, validation_fraction)
    residual = ~baseline_blocked

    train_residual = split.train & residual
    validation_residual = split.validation & residual

    model = train_behavioral_model(
        features[train_residual],
        labels[train_residual],
        feature_names(),
        random_state=random_state,
    )

    validation_scores = model.predict_proba(features[validation_residual])
    calibration_sweep = sensitivity_sweep(labels[validation_residual], validation_scores)
    chosen = calibrate_threshold(
        labels[validation_residual], validation_scores, cost_ratio=cost_ratio
    )

    behavioral_score = model.predict_proba(features)
    ensemble_score = np.where(baseline_blocked, RULES_BLOCKED_SCORE, behavioral_score)
    baseline_score = np.where(baseline_blocked, RULES_BLOCKED_SCORE, RULES_ALLOWED_SCORE)

    logger.info(
        "pipeline fit: %d sessions, %d train residual rows, threshold=%.4f",
        n_sessions,
        int(train_residual.sum()),
        chosen.threshold,
    )
    return PipelineFit(
        corpus=corpus,
        labels=labels,
        baseline_blocked=baseline_blocked,
        features=features,
        split=split,
        residual=residual,
        model=model,
        chosen_calibration=chosen,
        calibration_sweep=calibration_sweep,
        behavioral_score=behavioral_score,
        ensemble_score=ensemble_score,
        baseline_score=baseline_score,
    )


def precision_recall(predicted_block: np.ndarray, truth: np.ndarray) -> tuple[float, float]:
    """Computes precision and recall for a block/allow prediction array.

    Args:
        predicted_block: Per-row block/allow prediction.
        truth: Per-row ground-truth `is_attack` labels.

    Returns:
        A (precision, recall) tuple. Either is 0.0 when its denominator is
        empty.
    """
    true_positives = int(np.sum(predicted_block & truth))
    false_positives = int(np.sum(predicted_block & ~truth))
    false_negatives = int(np.sum(~predicted_block & truth))
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    return (
        true_positives / precision_denominator if precision_denominator else 0.0,
        true_positives / recall_denominator if recall_denominator else 0.0,
    )
