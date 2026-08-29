"""Command-line entry point for the one-shot held-out evaluation.

Fits the ordinary three-class pipeline exactly as `run_full_eval.py` does,
then applies the resulting frozen model and threshold to a held-out corpus
containing only mandate-chaining / privilege-escalation attacks -- a class
neither trained on nor tuned against. Nothing here retrains or recalibrates
anything.

    python run_held_out_eval.py --n-legitimate 20000 --seed 42 --held-out-n-legitimate 20000 --held-out-seed 90042

This is meant to run exactly once per frozen pipeline state. Re-running it
after changing `detect/`, `features/`, or the generator's attack-side tuning
in response to a prior result would be exactly the thing
`docs/adr/0003-held-out-class-evaluation.md` documents as off-limits.
"""

from __future__ import annotations

import argparse
import logging
import sys

from eval.held_out_evaluation import format_held_out_report, run_held_out_evaluation
from eval.pipeline import fit_pipeline
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus
from generator.attacks.held_out import DEFAULT_HELD_OUT_ATTACK_BASE_RATE, build_held_out_corpus

DEFAULT_N_LEGITIMATE = 20000
DEFAULT_SEED = 42
DEFAULT_HELD_OUT_N_LEGITIMATE = 20000
# Deliberately far outside the range any training/tuning seed would plausibly
# use, so the held-out corpus's legitimate substrate and agent pool are never
# mistakable for ones a model could have trained against.
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
    """Runs the held-out evaluation and prints the report.

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
    report = run_held_out_evaluation(fit, held_out_corpus)
    print(format_held_out_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
