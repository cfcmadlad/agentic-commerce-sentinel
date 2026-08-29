"""Command-line entry point for the ensemble evaluation.

Trains the Layer 3 behavioral model on the rules-allowed residual, ensembles
it with the Layer 1/2 verdict, and reports the comparison against the
rules-only baseline with a paired significance test. Reproduces from a clean
clone with a single command:

    python run_ensemble_eval.py --n-legitimate 20000 --seed 42
"""

from __future__ import annotations

import argparse
import logging
import sys

from eval.ensemble_evaluation import format_ensemble_evaluation_report, run_ensemble_evaluation
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42


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
    parser.add_argument("--cost-ratio", type=float, default=None, help="override the default cost ratio")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Runs the ensemble-evaluation pipeline and prints the report.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 on success, 1 if corpus construction failed.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )
    try:
        corpus = build_evaluation_corpus(args.n_legitimate, seed=args.seed, attack_base_rate=args.attack_base_rate)
    except ValueError as error:
        print(f"could not build corpus: {error}", file=sys.stderr)
        return 1

    kwargs = {} if args.cost_ratio is None else {"cost_ratio": args.cost_ratio}
    report = run_ensemble_evaluation(corpus, **kwargs)
    print(format_ensemble_evaluation_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
