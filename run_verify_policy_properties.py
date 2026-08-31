"""Command-line entry point for formal verification of the deterministic layers.

Checks all eight safety properties `formal/properties.py` defines against
the Z3 encoding in `formal/model.py`, and reports proved/violated for each,
with a concrete counterexample for any that fail.

    python run_verify_policy_properties.py
    python run_verify_policy_properties.py --json-out frontend/public/formal_properties.json

This never touches Layer 3 (the learned model) -- see `formal/__init__.py`
and `docs/adr/0005-formal-verification-of-deterministic-layers.md` for the
exact scope boundary between what is proved here and what is not.

`--json-out` exists for the frontend's Proof Panel (`docs/adr/0016-governed-live-agent.md`'s
Phase 2 addition): the panel renders each property's real name, layer, and
description alongside its actual proved/violated outcome from a real run of
this script, never a hand-typed list -- matching this project's standing
"every claim traces to a real, reproducible number" rule.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from formal.properties import all_properties
from formal.verify import PropertyResult, format_report, verify_all


def _result_to_json(result: PropertyResult) -> dict[str, Any]:
    """Renders one `PropertyResult` as a JSON-safe dict.

    Args:
        result: The result to render.

    Returns:
        The rendered dict, naming the property explicitly rather than
        exposing its raw Z3 formula (not JSON-safe, and not something a
        frontend has any use for).
    """
    return {
        "name": result.property.name,
        "layer": result.property.layer,
        "description": result.property.description,
        "proved": result.proved,
        "counterexample": result.counterexample,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json-out", default=None, help="optional path to also write the full property-by-property report as JSON"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Runs every property check, prints the report, and optionally writes it as JSON.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 if every property was proved, 1 if any was
        violated.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    results = verify_all(all_properties())
    print(format_report(results))

    if args.json_out is not None:
        payload = {
            "properties": [_result_to_json(r) for r in results],
            "all_proved": all(r.proved for r in results),
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        print(f"wrote {len(results)} propert{'y' if len(results) == 1 else 'ies'} to {args.json_out}")

    return 0 if all(result.proved for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
