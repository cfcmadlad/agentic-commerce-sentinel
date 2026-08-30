"""Exports the three delegation-chain demo scenarios as JSON.

Runs each scenario's parent (and sibling, where there is one) mandate
through the real `service.main.decide` handler, then the focus child, then
computes that child's real delegation chain (`service.delegation_chain
.build_delegation_chain`) -- the same computation
`GET /mandates/{id}/chain` performs live. The focus session's own decision
(baseline, ensemble, attribution, and -- when `GROQ_API_KEY` is set -- a
genuine Groq narration) is captured from that real call, never
hand-written. `frontend/src/pages/Delegation.tsx` renders this file
directly in its recorded (non-live) mode, and POSTs the same request
bodies to a running service in live mode.

    python run_delegation_demo_export.py --json-out frontend/public/delegation_demo.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass  # python-dotenv is a dev-only dependency; narration stays best-effort without it

from service.delegation_chain import build_delegation_chain
from service.delegation_scenarios import DelegationScenario, build_delegation_scenarios
from service.main import decide
from service.schemas import SessionDecisionResponse
from service.state import AppState, build_app_state

DEFAULT_JSON_OUT = "frontend/public/delegation_demo.json"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT, help="path to write the exported scenarios to")
    return parser.parse_args(argv)


def _export_one_scenario(scenario: DelegationScenario, state: AppState) -> dict[str, Any]:
    """Runs one scenario's requests through the real pipeline and exports the result.

    Args:
        scenario: The scenario to run.
        state: Shared application state -- mutated by this call (the
            parent and every child are recorded in `state.mandate_store`
            and `state.ledger`), same as a live sequence of real requests
            would do. Each scenario uses its own demo agent, so scenarios
            do not interfere with each other's causal history.

    Returns:
        A JSON-safe dict: the scenario's metadata, every request body (for
        live-mode replay), the real chain computed for the focus mandate,
        and the focus session's own real decision.
    """
    decide(scenario.parent_request, state)
    focus_response: SessionDecisionResponse | None = None
    for request in scenario.child_requests:
        response = decide(request, state)
        if request.trace.mandate_id == scenario.focus_mandate_id:
            focus_response = response
    if focus_response is None:
        raise AssertionError(f"scenario {scenario.key!r}: no child request presented the focus mandate")

    focus_mandate = state.mandate_store.get(scenario.focus_mandate_id)
    assert focus_mandate is not None, f"scenario {scenario.key!r}: focus mandate not in the store after deciding"
    chain = build_delegation_chain(focus_mandate, state.mandate_store)

    return {
        "key": scenario.key,
        "label": scenario.label,
        "description": scenario.description,
        "parent_request": scenario.parent_request.model_dump(mode="json"),
        "child_requests": [r.model_dump(mode="json") for r in scenario.child_requests],
        "focus_mandate_id": str(scenario.focus_mandate_id),
        "chain": chain.model_dump(mode="json"),
        "focus_decision": focus_response.model_dump(mode="json"),
    }


def main(argv: list[str] | None = None) -> int:
    """Builds the delegation scenarios, runs them for real, and writes the result as JSON.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code, always 0.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    print("fitting pipeline (this takes a while)...")
    # Isolated, temporary audit/escalation log paths -- not this project's
    # shared `service_audit.jsonl`/`service_escalations.jsonl` defaults.
    # Those accumulate real state across every process that touches them
    # (including a live `uvicorn` instance run for manual testing), and this
    # script's demo agents (demo-agent-00/01/02) are the same ones a live
    # service registers -- a prior interactive session tripping one of their
    # circuit breakers would otherwise silently short-circuit this export's
    # own decide() calls the next time it runs, before the mandate ever
    # reaches the store. A one-shot export should not be able to observe,
    # or be affected by, any other process's history.
    with tempfile.TemporaryDirectory() as tmp_dir:
        state = build_app_state(
            audit_log_path=Path(tmp_dir) / "audit.jsonl", escalation_log_path=Path(tmp_dir) / "escalations.jsonl"
        )
        scenarios = build_delegation_scenarios()
        payload = [_export_one_scenario(scenario, state) for scenario in scenarios]

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    print(f"wrote {len(payload)} delegation scenario(s) to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
