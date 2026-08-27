"""Exports the five live-demo scenarios' final request bodies as JSON.

The frontend's live demo view (`frontend/src/pages/LiveDemo.tsx`) POSTs
these bodies verbatim to a running `/sessions/decide` when a live API base
URL is configured -- this script produces exactly what it sends, not a
separate or simplified payload. Each mandate is signed with the same demo
agent keys `service/state.py` registers at startup, so every exported
request verifies against a real running service; regenerating this file
never requires the service to be running, since it only calls the pure
`service.demo_scenarios` builder.

    python run_live_demo_export.py --json-out frontend/public/live_demo_requests.json
"""

from __future__ import annotations

import argparse
import json
import sys

from service.demo_scenarios import build_demo_scenarios

DEFAULT_JSON_OUT = "frontend/public/live_demo_requests.json"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json-out", default=DEFAULT_JSON_OUT, help="path to write the exported request map to"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Builds the demo scenarios and writes their final requests as JSON.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code, always 0.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    scenarios = build_demo_scenarios()
    payload = {str(session_id): scenario.final.model_dump(mode="json") for session_id, scenario in scenarios.items()}
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    print(f"wrote {len(payload)} demo request(s) to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
