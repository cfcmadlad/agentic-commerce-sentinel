"""Runs the four governed-shopper-agent scenarios and exports the transcripts as JSON.

Matches the established `run_*.py` convention (`run_delegation_demo_export.py`,
`run_collision_export.py`): fits the real pipeline once, runs every scenario
against a demo-run-isolated `service.state.AppState` (own temp-file audit and
escalation log paths -- never the shared `service_audit.jsonl`/
`service_escalations.jsonl` defaults a live service or another run would use,
same reasoning `run_delegation_demo_export.py`'s own module docstring already
states), and writes one JSON file a frontend could render later.

Uses a real Groq tool-calling client (`agent.llm_client.GroqToolCallingClient`)
when `GROQ_API_KEY` is configured -- the default and the only mode that
produces a genuinely live transcript. Without a key, `--fake-llm` runs a
small, fixed, scripted tool-call sequence per scenario instead: useful for an
offline smoke check that the rest of the pipeline (real `decide()`, real
containment, real escalation-queue wiring) still works end to end, but never
presented as a live agent decision -- every exported scenario's
`llm_backend` field states plainly which mode produced it.

    python run_agent_demo_export.py --json-out frontend/public/agent_demo.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass  # python-dotenv is a dev-only dependency; --fake-llm works without it

from agent.llm_client import (
    DEFAULT_MODEL,
    AssistantTurn,
    GroqToolCallingClient,
    ToolCall,
    ToolCallingClient,
    ToolDefinition,
)
from agent.scenarios import ShopperScenario, build_scenarios
from agent.shopper import ShopperTranscript, render_verdict, run_shopper_session
from service.state import AppState, build_app_state

DEFAULT_JSON_OUT = "frontend/public/agent_demo.json"

# One fixed scripted tool-call plan per scenario key, used only in
# --fake-llm mode. Deliberately mirrors what a well-behaved model given
# that scenario's prompt would plausibly do -- but is not, and must never
# be presented as, live model output.
_FAKE_PLANS: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "allowed": [
        ("search_catalog", {"query": "earbuds"}),
        ("propose_purchase", {"item_id": "earbuds-wireless-01", "quantity": 1}),
        ("checkout", {"item_id": "earbuds-wireless-01", "quantity": 1}),
    ],
    "blocked_scope_violation": [
        ("search_catalog", {"query": "laptop"}),
        ("propose_purchase", {"item_id": "laptop-pro-01", "quantity": 1}),
        ("checkout", {"item_id": "laptop-pro-01", "quantity": 1}),
    ],
    "escalated_behavioral_anomaly": [
        ("propose_purchase", {"item_id": "sneakers-running-01", "quantity": 1}),
        ("checkout", {"item_id": "sneakers-running-01", "quantity": 1}),
    ],
    "headline_budget_escalation": [
        ("search_catalog", {"query": "rice"}),
        ("propose_purchase", {"item_id": "rice-sack-5kg-01", "quantity": 1}),
        ("checkout", {"item_id": "rice-sack-5kg-01", "quantity": 1}),
    ],
}


class ScriptedToolCallingClient:
    """A fixed, deterministic tool-call sequence -- explicitly not a live model.

    Attributes:
        plan: The remaining `(tool_name, arguments)` steps to emit, one per
            `complete()` call.
    """

    def __init__(self, plan: list[tuple[str, dict[str, Any]]]) -> None:
        """Initializes the client with its fixed plan.

        Args:
            plan: The scripted `(tool_name, arguments)` sequence.
        """
        self.plan = list(plan)
        self._call_counter = 0

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        """Returns the next scripted step, or a final summary once the plan is exhausted.

        Args:
            messages: Ignored -- this client does not read conversation
                history, since its output is fixed ahead of time.
            tools: Ignored.

        Returns:
            The next scripted tool call, or a final content-only turn.
        """
        if not self.plan:
            return AssistantTurn(content="Scripted plan complete.", tool_calls=())
        name, arguments = self.plan.pop(0)
        self._call_counter += 1
        call = ToolCall(call_id=f"fake-call-{self._call_counter}", name=name, arguments=arguments)
        return AssistantTurn(content=None, tool_calls=(call,))


def _build_client(scenario_key: str, use_fake: bool) -> tuple[ToolCallingClient, str]:
    """Builds the tool-calling client for one scenario.

    Args:
        scenario_key: The scenario's key, used to select the fake plan when
            `use_fake` is True.
        use_fake: Whether to use the scripted fake client.

    Returns:
        `(client, llm_backend_label)`.
    """
    if use_fake:
        return ScriptedToolCallingClient(_FAKE_PLANS[scenario_key]), "fake-scripted (no GROQ_API_KEY / --fake-llm)"
    from groq import Groq

    return GroqToolCallingClient(client=Groq()), f"groq:{DEFAULT_MODEL}"


def _transcript_to_json(scenario: ShopperScenario, transcript: ShopperTranscript, llm_backend: str) -> dict[str, Any]:
    """Renders one scenario's run as a JSON-safe dict.

    Args:
        scenario: The scenario that was run.
        transcript: The resulting transcript.
        llm_backend: Which client produced it (see `_build_client`).

    Returns:
        The rendered dict.
    """
    return {
        "key": scenario.key,
        "label": scenario.label,
        "description": scenario.description,
        "llm_backend": llm_backend,
        "final_text": transcript.final_text,
        "hit_iteration_cap": transcript.hit_iteration_cap,
        "invocations": [
            {"name": inv.name, "arguments": inv.arguments, "result": inv.result, "is_error": inv.is_error}
            for inv in transcript.invocations
        ],
        "verdicts": [render_verdict(v) for v in transcript.verdicts],
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT, help="path to write the exported transcripts to")
    parser.add_argument(
        "--fake-llm",
        action="store_true",
        help="use a fixed, scripted tool-call sequence instead of a real Groq call (for an offline smoke check)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Builds the four scenarios, runs each through the shopper agent loop, and writes the result as JSON.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code, always 0 (falls back to `--fake-llm` behavior
        automatically, with a printed notice, rather than failing when
        `GROQ_API_KEY` is not set).
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    use_fake = args.fake_llm or not os.environ.get("GROQ_API_KEY")
    if not args.fake_llm and not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY not set: falling back to --fake-llm (scripted, not live) for this run")

    print("fitting pipeline (this takes a while)...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        state: AppState = build_app_state(
            audit_log_path=Path(tmp_dir) / "audit.jsonl", escalation_log_path=Path(tmp_dir) / "escalations.jsonl"
        )
        scenarios = build_scenarios(state)

        payload = []
        for scenario in scenarios:
            client, llm_backend = _build_client(scenario.key, use_fake)
            transcript = run_shopper_session(
                scenario.context,
                client,
                scenario.user_prompt,
                system_prompt_addition=scenario.system_prompt_addition,
            )
            payload.append(_transcript_to_json(scenario, transcript, llm_backend))
            print(f"scenario {scenario.key!r}: {len(transcript.verdicts)} checkout verdict(s)")

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    print(f"wrote {len(payload)} scenario transcript(s) to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
