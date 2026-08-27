"""Command-line entry point exporting per-session scores for the frontend's interactive collision chart.

Fits the same frozen pipeline Milestone B reports on, then scores the
held-out mandate-chaining corpus against that already-frozen fit (never
retraining or recalibrating, per `docs/adr/0003-held-out-class-evaluation.md`),
and writes one JSON record per exported session: its real ensemble score,
its ground-truth category, whether the rules already blocked it before
Layer 3 was ever consulted, and its real value on the model's own two
highest-ranked SHAP features (`TERRAIN_FEATURE_X`/`_Y`) for the frontend's
2D risk-terrain view. No mandate or transaction content is exported --
only the values the charts actually render.

Sampling exists purely to keep the exported file and the rendered point
count reasonable; every exported point is a real session's real score, none
are synthesized for the export itself. Legitimate sessions are down-sampled
(there are tens of thousands; a few hundred conveys the same cluster shape
a full plot would). Every known in-distribution attack in the test block is
included, since there are few enough to show in full. Held-out
mandate-chaining attacks are down-sampled from thousands to a few hundred --
still large enough that the near-total-miss result the sample shows is not
an artifact of which few points happened to be picked.

    python run_collision_export.py --json-out frontend/public/collision.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass

import numpy as np

from detect.baseline import RulesOnlyBaseline
from eval.pipeline import PipelineFit, extract_features_causally, fit_pipeline
from features.session import feature_names
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import EvaluationCorpus, build_evaluation_corpus
from generator.attacks.held_out import DEFAULT_HELD_OUT_ATTACK_BASE_RATE, build_held_out_corpus

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42
DEFAULT_HELD_OUT_N_LEGITIMATE = 20000
DEFAULT_HELD_OUT_SEED = 90042
DEFAULT_SAMPLE_SEED = 7

MAX_LEGITIMATE_POINTS = 1200
MAX_HELD_OUT_POINTS = 600

# The two highest-ranked real SHAP features (see README Section 7's top
# SHAP feature table): chosen because they are the model's own most
# important dimensions, not picked for how the resulting plot looks.
TERRAIN_FEATURE_X = "agent_prior_session_count"
TERRAIN_FEATURE_Y = "mandate_prior_use_count"

logger = logging.getLogger(__name__)

_FEATURE_NAMES = feature_names()
_X_INDEX = _FEATURE_NAMES.index(TERRAIN_FEATURE_X)
_Y_INDEX = _FEATURE_NAMES.index(TERRAIN_FEATURE_Y)


@dataclass(frozen=True)
class CollisionPoint:
    """One exported session: exactly what the chart renders and nothing else.

    Attributes:
        score: The real ensemble score (0.0-1.0, or 1.0 for a rules block).
        category: Ground-truth category label.
        blocked_by_rules: Whether Layers 1/2 blocked this session before
            Layer 3 was consulted at all.
        feature_x: This session's real `TERRAIN_FEATURE_X` value.
        feature_y: This session's real `TERRAIN_FEATURE_Y` value.
    """

    score: float
    category: str
    blocked_by_rules: bool
    feature_x: float
    feature_y: float


def _sample_indices(rng: np.random.Generator, n: int, k: int) -> np.ndarray:
    """Deterministically samples up to k indices from range(n) without replacement.

    Args:
        rng: Seeded generator.
        n: Population size.
        k: Sample size requested.

    Returns:
        Sorted sampled indices, or all of range(n) if k >= n.
    """
    if k >= n:
        return np.arange(n)
    return np.sort(rng.choice(n, size=k, replace=False))


def _in_distribution_points(fit: PipelineFit, rng: np.random.Generator) -> list[CollisionPoint]:
    """Builds collision points from the test block's real scores and categories.

    Args:
        fit: The frozen pipeline fit Milestone B reports on.
        rng: Seeded generator for the legitimate-session down-sample.

    Returns:
        One point per exported test-block session.
    """
    mask = fit.split.test
    labels, baseline_score, ensemble_score = fit.test_slice()
    test_indices = np.flatnonzero(mask)
    sessions = fit.corpus.labeled_sessions

    legit_idx = [i for i in range(len(test_indices)) if not labels[i]]
    attack_idx = [i for i in range(len(test_indices)) if labels[i]]
    sampled_legit = _sample_indices(rng, len(legit_idx), MAX_LEGITIMATE_POINTS)

    points: list[CollisionPoint] = []
    for local_i in [legit_idx[j] for j in sampled_legit] + attack_idx:
        corpus_i = int(test_indices[local_i])
        session = sessions[corpus_i]
        points.append(
            CollisionPoint(
                score=float(ensemble_score[local_i]),
                category=session.attack_class.value,
                blocked_by_rules=bool(baseline_score[local_i] >= 1.0),
                feature_x=float(fit.features[corpus_i, _X_INDEX]),
                feature_y=float(fit.features[corpus_i, _Y_INDEX]),
            )
        )
    return points


def _held_out_points(
    fit: PipelineFit, held_out_corpus: EvaluationCorpus, rng: np.random.Generator
) -> list[CollisionPoint]:
    """Scores the held-out corpus with the frozen fit and samples attack points.

    Mirrors `eval.held_out_evaluation.run_held_out_evaluation`'s scoring
    loop, but keeps the per-session scores this export needs instead of
    reducing straight to an aggregate report.

    Args:
        fit: The frozen pipeline fit -- its model and threshold are applied
            as-is, never retrained or recalibrated.
        held_out_corpus: The held-out mandate-chaining corpus.
        rng: Seeded generator for the attack down-sample.

    Returns:
        Collision points for a sample of the held-out attack sessions.
    """
    sessions = held_out_corpus.labeled_sessions
    baseline = RulesOnlyBaseline(held_out_corpus.registry, held_out_corpus.resolver)
    decisions = baseline.decide_all(s.trace for s in sessions)
    features = extract_features_causally(sessions)
    behavioral_score = fit.model.predict_proba(features)

    attack_local_indices = [i for i, s in enumerate(sessions) if s.is_attack]
    sampled = _sample_indices(rng, len(attack_local_indices), MAX_HELD_OUT_POINTS)

    points: list[CollisionPoint] = []
    for j in sampled:
        i = attack_local_indices[int(j)]
        decision = decisions[i]
        # Matches eval/pipeline.py's ensemble_score convention exactly: a
        # rules-blocked session's scalar score saturates to 1.0 regardless
        # of what Layer 3 would have scored it, since rules can only add a
        # block and never get overridden.
        score = 1.0 if decision.blocked else float(behavioral_score[i])
        points.append(
            CollisionPoint(
                score=score,
                category=sessions[i].attack_class.value,
                blocked_by_rules=decision.blocked,
                feature_x=float(features[i, _X_INDEX]),
                feature_y=float(features[i, _Y_INDEX]),
            )
        )
    return points


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-legitimate", type=int, default=DEFAULT_N_LEGITIMATE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--attack-base-rate", type=float, default=DEFAULT_ATTACK_BASE_RATE)
    parser.add_argument("--held-out-n-legitimate", type=int, default=DEFAULT_HELD_OUT_N_LEGITIMATE)
    parser.add_argument("--held-out-seed", type=int, default=DEFAULT_HELD_OUT_SEED)
    parser.add_argument("--held-out-attack-base-rate", type=float, default=DEFAULT_HELD_OUT_ATTACK_BASE_RATE)
    parser.add_argument("--sample-seed", type=int, default=DEFAULT_SAMPLE_SEED)
    parser.add_argument("--json-out", type=str, required=True)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Fits the pipeline, scores both corpora, and writes the collision export.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 on success, 1 if either corpus was rejected.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        fitting_corpus = build_evaluation_corpus(
            args.n_legitimate, seed=args.seed, attack_base_rate=args.attack_base_rate
        )
    except ValueError as error:
        print(f"could not build the fitting corpus: {error}", file=sys.stderr)
        return 1

    try:
        held_out_corpus = build_held_out_corpus(
            args.held_out_n_legitimate,
            seed=args.held_out_seed,
            attack_base_rate=args.held_out_attack_base_rate,
        )
    except ValueError as error:
        print(f"could not build the held-out corpus: {error}", file=sys.stderr)
        return 1

    fit = fit_pipeline(fitting_corpus)
    rng = np.random.default_rng(args.sample_seed)

    points = _in_distribution_points(fit, rng) + _held_out_points(fit, held_out_corpus, rng)

    payload = {
        "threshold": fit.threshold,
        "feature_x_name": TERRAIN_FEATURE_X,
        "feature_y_name": TERRAIN_FEATURE_Y,
        "points": [
            {
                "score": p.score,
                "category": p.category,
                "blocked_by_rules": p.blocked_by_rules,
                "feature_x": p.feature_x,
                "feature_y": p.feature_y,
            }
            for p in points
        ],
    }
    with open(args.json_out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    logger.info("exported %d collision points to %s", len(points), args.json_out)
    print(f"exported {len(points)} points to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
