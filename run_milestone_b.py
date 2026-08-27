"""Command-line entry point for the full evaluation.

Runs the complete metric set the project committed to: AUC-PR with bootstrap
confidence intervals, AUC-ROC, a DeLong comparison against the rules-only
baseline, a calibration curve and Brier score, per-class and per-variant
breakdowns, a full-range false-positive cost sweep, end-to-end per-decision
latency percentiles, and a sensitivity analysis across a grid of generator
parameters. Reproduces from a clean clone with a single command:

    python run_milestone_b.py --n-legitimate 20000 --seed 42

The sensitivity grid regenerates and retrains the whole stack at every point,
so it dominates the runtime. `--skip-sensitivity` exists for iterating on the
rest of the report and prints a warning; a reported result must include it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from eval.milestone_b import (
    DEFAULT_LATENCY_SESSIONS,
    DEFAULT_SENSITIVITY_SESSIONS,
    format_milestone_b_report,
    run_milestone_b,
)
from eval.report_json import milestone_b_report_to_dict
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42
DEFAULT_BOOTSTRAP_RESAMPLES = 1000


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
        report = run_milestone_b(
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

    print(format_milestone_b_report(report))

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(milestone_b_report_to_dict(report), indent=2), encoding="utf-8"
        )
        print(f"\nwrote JSON report to {args.json_out}", file=sys.stderr)

    if args.skip_sensitivity:
        print(
            "\nWARNING: --skip-sensitivity was set. This report omits the generator "
            "parameter grid and is not a complete result.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
