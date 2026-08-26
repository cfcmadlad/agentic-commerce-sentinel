"""Command-line entry point for the rules-baseline evaluation.

Generates a mixed corpus and prints the rules-only baseline's performance
against it. Dependency-free beyond the project itself so it reproduces from
a clean clone:

    python run_gate.py --n-legitimate 5000 --seed 42
"""

from __future__ import annotations

import argparse
import logging
import sys

from eval.gate import format_gate_report, run_gate_evaluation
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus

DEFAULT_N_LEGITIMATE = 5000
DEFAULT_SEED = 42


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
        help="number of legitimate sessions to generate",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="corpus seed (reproducibility)"
    )
    parser.add_argument(
        "--attack-base-rate", type=float, default=DEFAULT_ATTACK_BASE_RATE,
        help="target fraction of the corpus that is attack traffic",
    )
    parser.add_argument("--verbose", action="store_true", help="emit per-session detector logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Runs the evaluation and prints the report.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 on success, 1 if corpus construction was rejected.
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

    print(format_gate_report(run_gate_evaluation(corpus)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())