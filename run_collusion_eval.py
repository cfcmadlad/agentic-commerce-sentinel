"""Command-line entry point for the collusion-ring detection evaluation.

Builds a mixed corpus of ordinary legitimate traffic, planted malicious
rings, and hard-negative legitimate shared-infrastructure groups, then
reports precision/recall on the planted rings and false-positive rate on
the negatives across a threshold sweep.

    python run_collusion_eval.py --n-baseline-legitimate 2000 --n-malicious-rings 21 \
        --n-household-negatives 10 --n-shared-gateway-negatives 8 --seed 42

The default `n_baseline_legitimate` is deliberately calibrated, not
arbitrary: `generator/config.py`'s agent pool is a fixed 40 agents, and
baseline-agent false positives rise sharply once average per-agent session
volume over the 30-day generation horizon gets high enough that coincidental
multi-agent bursts at a shared merchant become common -- measured directly
during calibration, not assumed. See
`docs/adr/0006-collusion-ring-detection.md` for the full density-sensitivity
finding, reported honestly rather than tuned away.
"""

from __future__ import annotations

import argparse
import logging
import sys

from eval.collusion_evaluation import format_collusion_report, sweep_thresholds
from generator.collusion.corpus import build_collusion_corpus

DEFAULT_N_BASELINE_LEGITIMATE = 2000
DEFAULT_N_MALICIOUS_RINGS = 21
DEFAULT_N_HOUSEHOLD_NEGATIVES = 10
DEFAULT_N_SHARED_GATEWAY_NEGATIVES = 8
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
        "--n-baseline-legitimate", type=int, default=DEFAULT_N_BASELINE_LEGITIMATE,
        help="ordinary independent legitimate sessions",
    )
    parser.add_argument(
        "--n-malicious-rings", type=int, default=DEFAULT_N_MALICIOUS_RINGS,
        help="planted malicious ring groups, split round-robin across the three archetypes",
    )
    parser.add_argument(
        "--n-household-negatives", type=int, default=DEFAULT_N_HOUSEHOLD_NEGATIVES,
        help="legitimate household hard-negative groups",
    )
    parser.add_argument(
        "--n-shared-gateway-negatives", type=int, default=DEFAULT_N_SHARED_GATEWAY_NEGATIVES,
        help="legitimate shared-gateway hard-negative groups",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="corpus seed")
    parser.add_argument("--verbose", action="store_true", help="emit progress logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Builds the corpus, runs the threshold sweep, and prints the report.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 on success, 1 if the corpus was rejected.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        corpus = build_collusion_corpus(
            args.n_baseline_legitimate, args.n_malicious_rings, args.n_household_negatives,
            args.n_shared_gateway_negatives, seed=args.seed,
        )
    except ValueError as error:
        print(f"could not build the collusion corpus: {error}", file=sys.stderr)
        return 1

    print("Collusion-ring detection evaluation")
    print(f"  sessions={len(corpus.sessions)} malicious_rings={sum(1 for g in corpus.groups if g.is_ring)}")
    print()
    for report in sweep_thresholds(corpus):
        print(format_collusion_report(report))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
