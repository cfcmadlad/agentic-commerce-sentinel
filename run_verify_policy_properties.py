"""Command-line entry point for formal verification of the deterministic layers.

Checks all eight safety properties `formal/properties.py` defines against
the Z3 encoding in `formal/model.py`, and reports proved/violated for each,
with a concrete counterexample for any that fail.

    python run_verify_policy_properties.py

This never touches Layer 3 (the learned model) -- see `formal/__init__.py`
and `docs/adr/0005-formal-verification-of-deterministic-layers.md` for the
exact scope boundary between what is proved here and what is not.
"""

from __future__ import annotations

import logging

from formal.properties import all_properties
from formal.verify import format_report, verify_all


def main(argv: list[str] | None = None) -> int:
    """Runs every property check and prints the report.

    Args:
        argv: Argument list, excluding the program name. Accepted for
            symmetry with this project's other `run_*.py` entry points;
            this script takes no arguments and ignores its contents.

    Returns:
        A process exit code: 0 if every property was proved, 1 if any was
        violated.
    """
    del argv
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    results = verify_all(all_properties())
    print(format_report(results))
    return 0 if all(result.proved for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
