"""Command-line entry point for the full evaluation.

Runs the complete metric set the project committed to: AUC-PR with bootstrap
confidence intervals, AUC-ROC, a DeLong comparison against the rules-only
baseline, a calibration curve and Brier score, per-class and per-variant
breakdowns, a full-range false-positive cost sweep, end-to-end per-decision
latency percentiles, and a sensitivity analysis across a grid of generator
parameters. Reproduces from a clean clone with a single command:

    python run_full_eval.py --n-legitimate 20000 --seed 42

The sensitivity grid regenerates and retrains the whole stack at every point,
so it dominates the runtime. `--skip-sensitivity` exists for iterating on the
rest of the report and prints a warning; a reported result must include it.

Every run also builds a reproducibility manifest (`manifest/`): the exact
corpus, this run's own tunables, every seed, the git commit and dependency
lock state, and the resulting metrics, hashed and appended to a hash-chained
log (`eval_manifests.jsonl` by default; `--no-manifest-log` skips this,
`--manifest-out PATH` also writes it standalone). The printed "manifest
hash" is what a README number should cite; `run_verify_manifest.py` checks
a manifest's recorded inputs against the current working tree later.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from detect.calibration import DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO
from eval.full_evaluation import (
    DEFAULT_LATENCY_SESSIONS,
    DEFAULT_SENSITIVITY_SESSIONS,
    format_full_evaluation_report,
    run_full_evaluation,
)
from eval.pipeline import DEFAULT_RANDOM_STATE
from eval.report_json import full_evaluation_report_to_dict
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import (
    SEED_OFFSET_IMPERSONATION,
    SEED_OFFSET_REPLAY,
    SEED_OFFSET_SCOPE,
    build_evaluation_corpus,
)
from manifest.build import DEFAULT_MANIFEST_LOG_PATH, build_manifest
from manifest.log import ManifestLog
from manifest.schema import manifest_hash, manifest_to_json_dict

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42
DEFAULT_BOOTSTRAP_RESAMPLES = 1000
DEFAULT_BOOTSTRAP_SEED = 42


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--n-legitimate", type=int, default=DEFAULT_N_LEGITIMATE,
        help="number of legitimate sessions in the headline corpus",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="corpus seed (reproducibility)"
    )
    parser.add_argument(
        "--attack-base-rate", type=float, default=DEFAULT_ATTACK_BASE_RATE,
        help="target fraction of the corpus that is attack traffic",
    )
    parser.add_argument(
        "--cost-ratio", type=float, default=None,
        help="override the assumed false-negative-to-false-positive cost ratio",
    )
    parser.add_argument(
        "--bootstrap-resamples", type=int, default=DEFAULT_BOOTSTRAP_RESAMPLES,
        help="resamples per confidence interval",
    )
    parser.add_argument(
        "--sensitivity-sessions", type=int, default=DEFAULT_SENSITIVITY_SESSIONS,
        help="legitimate sessions per sensitivity grid point",
    )
    parser.add_argument(
        "--latency-sessions", type=int, default=DEFAULT_LATENCY_SESSIONS,
        help="sessions timed for the latency distribution",
    )
    parser.add_argument(
        "--skip-sensitivity", action="store_true",
        help="skip the generator parameter grid; produces an incomplete report",
    )
    parser.add_argument(
        "--json-out", type=Path, default=None,
        help="also write the report as JSON to this path, for the static metrics dashboard",
    )
    parser.add_argument(
        "--manifest-out", type=Path, default=None,
        help="also write a reproducibility manifest (corpus/config/git/dependency hashes, seeds, "
        "and these metrics) as JSON to this path",
    )
    parser.add_argument(
        "--manifest-log", type=Path, default=DEFAULT_MANIFEST_LOG_PATH,
        help=f"append the manifest to this hash-chained log (default: {DEFAULT_MANIFEST_LOG_PATH})",
    )
    parser.add_argument(
        "--no-manifest-log", action="store_true",
        help="skip appending to the hash-chained manifest log (still honors --manifest-out)",
    )
    parser.add_argument("--verbose", action="store_true", help="emit progress logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Runs the full evaluation and prints the report.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 on success, 1 if the corpus or the evaluation
        was rejected as unusable.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        corpus = build_evaluation_corpus(
            args.n_legitimate, seed=args.seed, attack_base_rate=args.attack_base_rate
        )
    except ValueError as error:
        print(f"could not build corpus: {error}", file=sys.stderr)
        return 1

    kwargs = {} if args.cost_ratio is None else {"cost_ratio": args.cost_ratio}
    try:
        report = run_full_evaluation(
            corpus,
            n_resamples=args.bootstrap_resamples,
            sensitivity_sessions=args.sensitivity_sessions,
            latency_sessions=args.latency_sessions,
            run_sensitivity=not args.skip_sensitivity,
            **kwargs,
        )
    except ValueError as error:
        print(f"could not run the evaluation: {error}", file=sys.stderr)
        return 1

    print(format_full_evaluation_report(report))

    metrics = full_evaluation_report_to_dict(report)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"\nwrote JSON report to {args.json_out}", file=sys.stderr)

    manifest = build_manifest(
        "full_evaluation",
        corpus=corpus,
        n_legitimate=args.n_legitimate,
        run_config={
            # The actual value used, not the raw CLI arg -- None means "use
            # the function's own default," and a manifest must record what
            # actually governed the run, not the sentinel that requested it.
            "cost_ratio": (
                DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO if args.cost_ratio is None else args.cost_ratio
            ),
            "bootstrap_resamples": args.bootstrap_resamples,
            "sensitivity_sessions": args.sensitivity_sessions,
            "latency_sessions": args.latency_sessions,
            "run_sensitivity": not args.skip_sensitivity,
        },
        seeds={
            "corpus_seed": args.seed,
            "seed_offset_replay": SEED_OFFSET_REPLAY,
            "seed_offset_scope": SEED_OFFSET_SCOPE,
            "seed_offset_impersonation": SEED_OFFSET_IMPERSONATION,
            "bootstrap_seed": DEFAULT_BOOTSTRAP_SEED,
            "pipeline_random_state": DEFAULT_RANDOM_STATE,
        },
        metrics=metrics,
    )
    content_hash = manifest_hash(manifest)

    if args.manifest_out is not None:
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest_to_json_dict(manifest), indent=2), encoding="utf-8")
        print(f"wrote manifest to {args.manifest_out}", file=sys.stderr)

    if not args.no_manifest_log:
        args.manifest_log.parent.mkdir(parents=True, exist_ok=True)
        ManifestLog(args.manifest_log).append(manifest)
        print(f"appended manifest to {args.manifest_log}", file=sys.stderr)

    print(f"manifest hash: {content_hash}", file=sys.stderr)

    if args.skip_sensitivity:
        print(
            "\nWARNING: --skip-sensitivity was set. This report omits the generator "
            "parameter grid and is not a complete result.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
