"""Command-line entry point for the one-shot Layer 2.5 (containment) evaluation.

Fits the ordinary three-class pipeline exactly as `run_full_eval.py` and
`run_held_out_eval.py` do, then applies the resulting frozen model and
threshold -- plus the new containment gate -- to the same held-out corpus
`run_held_out_eval.py` uses. Nothing here retrains or recalibrates anything,
and the containment rules themselves are not tuned in response to this run.

    python run_containment_eval.py --n-legitimate 20000 --seed 42 --held-out-n-legitimate 20000 --held-out-seed 90042

This is meant to run exactly once per frozen pipeline state, matching
`docs/adr/0003-held-out-class-evaluation.md`'s own evaluation discipline. See
`docs/adr/0004-delegation-chain-containment.md` for the result.
"""

from __future__ import annotations

import argparse
import logging
import sys

from eval.containment_evaluation import format_containment_report, run_containment_evaluation
from eval.pipeline import fit_pipeline
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus
from generator.attacks.held_out import DEFAULT_HELD_OUT_ATTACK_BASE_RATE, build_held_out_corpus

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42
DEFAULT_HELD_OUT_N_LEGITIMATE = 20000
# Matches run_held_out_eval.py's own seed choice, so this evaluation is
# scored against the identical held-out corpus the held-out evaluation's
# own number was measured on.
DEFAULT_HELD_OUT_SEED = 90042


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
        help="legitimate sessions in the three-class corpus the pipeline is fit against",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="three-class corpus seed")
    parser.add_argument(
        "--attack-base-rate", type=float, default=DEFAULT_ATTACK_BASE_RATE,
        help="attack fraction for the three-class fitting corpus",
    )
    parser.add_argument(
        "--held-out-n-legitimate", type=int, default=DEFAULT_HELD_OUT_N_LEGITIMATE,
        help="legitimate sessions in the held-out corpus",
    )
    parser.add_argument(
        "--held-out-seed", type=int, default=DEFAULT_HELD_OUT_SEED, help="held-out corpus seed"
    )
    parser.add_argument(
        "--held-out-attack-base-rate", type=float, default=DEFAULT_HELD_OUT_ATTACK_BASE_RATE,
        help="attack fraction for the held-out corpus",
    )
    parser.add_argument("--verbose", action="store_true", help="emit progress logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Runs the containment evaluation and prints the report.

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
    report = run_containment_evaluation(fit, held_out_corpus)
    print(format_containment_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
