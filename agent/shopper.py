"""The shopper agent's tool-calling loop.

Structural guarantee this module upholds: it never imports
`service.main`, `service.state`, `mandate.verification`,
`mandate.schema`, or `escalation.queue` directly -- the only way this
module can reach real state is by dispatching a model's tool call to one
of the three functions `agent.tools` exports. `tests
/test_agent_structural_isolation.py` asserts this at the AST level, the
same discipline `reasoning/narrate.py` already uses to guarantee it cannot
touch `detect.calibration`/`detect.behavioral`.

The agent decides what to attempt; the real Sentinel decides whether to
allow it (via `agent.tools.checkout`, the only tool with any effect). This
module's own reasoning text is genuine live Groq output when a real
`agent.llm_client.GroqToolCallingClient` is supplied, or an explicitly
fake, deterministic client for tests -- never presented to a caller as live
when it was not (see this package's `__init__.py` docstring and
`docs/adr/0016-governed-live-agent.md`).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from uuid import UUID

from agent.catalog import CatalogItem
from agent.llm_client import AssistantTurn, ToolCallingClient, ToolDefinition
from agent.tools import (
    PurchaseProposal,
    SentinelVerdict,
    ShopperToolContext,
    ToolValidationError,
    checkout,
    propose_purchase,
    search_catalog,
)

logger = logging.getLogger(__name__)

MAX_TOOL_ITERATIONS = 6

SYSTEM_PROMPT = (
    "You are an autonomous shopping agent. You act on behalf of a human "
    "principal who has granted you a signed spending mandate; you never see "
    "the mandate's exact terms, and you are not told in advance whether an "
    "attempted purchase will be authorized. Use the tools available to you "
    "to search the merchant catalog, propose a purchase, and attempt "
    "checkout. Checkout is the only tool that has a real effect -- it is "
    "decided by a real payment-authorization system you do not control and "
    "cannot see the internals of. After checkout returns, briefly state in "
    "plain language what you attempted and what the system decided; do not "
    "retry a blocked or escalated checkout with a different item unless "
    "explicitly asked to. You have no tool other than the three described "
    "to you -- do not claim to have taken any action you do not have a "
    "tool for."
)

TOOL_DEFINITIONS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="search_catalog",
        description="Search the merchant catalog by free-text query. Returns matching items with their prices.",
        parameters={
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search text, e.g. an item name or category."}},
            "required": ["query"],
        },
    ),
    ToolDefinition(
        name="propose_purchase",
        description=(
            "Build a candidate purchase for one catalog item and quantity. Pure computation, no effect -- "
            "does not attempt checkout."
        ),
        parameters={
            "type": "object",
            "properties": {
                "item_id": {"type": "string", "description": "The catalog item's ID, from search_catalog."},
                "quantity": {"type": "integer", "description": "Number of units to purchase.", "minimum": 1},
            },
            "required": ["item_id", "quantity"],
        },
    ),
    ToolDefinition(
        name="checkout",
        description=(
            "Attempt a real checkout for one catalog item and quantity. The only tool with any real effect: "
            "submits the transaction to the real payment-authorization system and returns its verdict."
        ),
        parameters={
            "type": "object",
            "properties": {
                "item_id": {"type": "string", "description": "The catalog item's ID to purchase."},
                "quantity": {"type": "integer", "description": "Number of units to purchase.", "minimum": 1},
            },
            "required": ["item_id", "quantity"],
        },
    ),
)


@dataclass(frozen=True)
class ToolInvocation:
    """A record of one tool call this session made, for the exported transcript.

    Attributes:
        name: The tool name invoked.
        arguments: The arguments the model supplied.
        result: The JSON-safe rendering of the tool's return value, or an
            error message if the call failed.
        is_error: True if `result` describes a failure, not a real result.
    """

    name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | str
    is_error: bool


@dataclass
class ShopperTranscript:
    """The full record of one scripted scenario run.

    Attributes:
        messages: The complete conversation, in Groq/OpenAI message-dict
            shape -- suitable for re-display or for feeding a follow-up
            turn.
        invocations: Every tool call made, in order.
        verdicts: Every `SentinelVerdict` a `checkout` call produced, in
            order. Usually zero or one; more than one only if the model
            attempted checkout more than once within the iteration cap.
        final_text: The model's closing plain-language summary, if the loop
            ended on a content-only turn rather than the iteration cap.
        hit_iteration_cap: True if the loop stopped only because
            `MAX_TOOL_ITERATIONS` was reached, not because the model
            produced a final answer.
    """

    messages: list[dict[str, Any]] = field(default_factory=list)
    invocations: list[ToolInvocation] = field(default_factory=list)
    verdicts: list[SentinelVerdict] = field(default_factory=list)
    final_text: str | None = None
    hit_iteration_cap: bool = False


def _json_default(value: Any) -> str:  # noqa: ANN401
    """Serializes types `json.dumps` does not natively support.

    Args:
        value: The value being serialized.

    Returns:
        A plain string rendering.

    Raises:
        TypeError: If `value` is of a type this function does not handle.
    """
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"no JSON rendering for type {type(value)!r}")


def _render_catalog_item(item: CatalogItem) -> dict[str, Any]:
    """Renders a `CatalogItem` as a JSON-safe dict.

    Args:
        item: The item to render.

    Returns:
        The rendered dict.
    """
    return {
        "item_id": item.item_id,
        "name": item.name,
        "merchant_id": item.merchant_id,
        "merchant_category": item.merchant_category,
        "item_category": item.item_category,
        "price": format(item.price, "f"),
    }


def _render_proposal(proposal: PurchaseProposal) -> dict[str, Any]:
    """Renders a `PurchaseProposal` as a JSON-safe dict.

    Args:
        proposal: The proposal to render.

    Returns:
        The rendered dict.
    """
    return {
        "item": _render_catalog_item(proposal.item),
        "quantity": proposal.quantity,
        "total_amount": format(proposal.total_amount, "f"),
        "currency": proposal.currency,
    }


def render_verdict(verdict: SentinelVerdict) -> dict[str, Any]:
    """Renders a `SentinelVerdict` as a JSON-safe dict.

    Args:
        verdict: The verdict to render.

    Returns:
        The rendered dict.
    """
    return {
        "session_id": str(verdict.session_id),
        "blocked": verdict.blocked,
        "source": verdict.source,
        "rules_fired": list(verdict.rules_fired),
        "behavioral_score": verdict.behavioral_score,
        "narrative": verdict.narrative,
        "containment_in_bounds": verdict.containment_in_bounds,
        "containment_reasons": list(verdict.containment_reasons),
        "escalation_opened": verdict.escalation_opened,
        "escalation_id": str(verdict.escalation_id) if verdict.escalation_id is not None else None,
    }


def _dispatch_tool_call(
    ctx: ShopperToolContext, name: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any] | str, bool, SentinelVerdict | None]:
    """Routes one model tool call to the real, corresponding `agent.tools` function.

    This is the only place a tool name string chosen by the model turns
    into a real function call -- an unrecognized name never reaches
    anything beyond this function's own `else` branch.

    Args:
        ctx: The bound tool context for this scenario.
        name: The tool name the model requested.
        arguments: The model-supplied arguments.

    Returns:
        `(rendered_result_or_error, is_error, verdict_if_checkout)`.
    """
    try:
        if name == "search_catalog":
            items = search_catalog(ctx, query=str(arguments.get("query", "")))
            return {"items": [_render_catalog_item(i) for i in items]}, False, None
        if name == "propose_purchase":
            proposal = propose_purchase(
                ctx, item_id=str(arguments["item_id"]), quantity=int(arguments["quantity"])
            )
            return _render_proposal(proposal), False, None
        if name == "checkout":
            verdict = checkout(ctx, item_id=str(arguments["item_id"]), quantity=int(arguments["quantity"]))
            return render_verdict(verdict), False, verdict
        return f"error: unknown tool {name!r}; only search_catalog, propose_purchase, and checkout exist", True, None
    except (ToolValidationError, KeyError, TypeError, ValueError) as error:
        logger.info("tool call %s(%r) rejected: %s", name, arguments, error)
        return f"error: {error}", True, None


def run_shopper_session(
    ctx: ShopperToolContext,
    client: ToolCallingClient,
    user_prompt: str,
    system_prompt_addition: str = "",
) -> ShopperTranscript:
    """Runs one scripted scenario's tool-calling loop to completion.

    Args:
        ctx: The bound tool context -- fixes the agent identity, mandate,
            and shared application state; never exposed to the model.
        client: The tool-calling client to use.
        user_prompt: The scenario's scripted prompt. Scripted, per the
            project brief, only in the sense that it is a fixed string
            written ahead of time -- the model's tool calls and the real
            verdicts they produce are never scripted.
        system_prompt_addition: Scenario-specific context appended to
            `SYSTEM_PROMPT` (e.g. naming the catalog subset available).

    Returns:
        The full transcript of the run.
    """
    system_prompt = SYSTEM_PROMPT if not system_prompt_addition else f"{SYSTEM_PROMPT}\n\n{system_prompt_addition}"
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    transcript = ShopperTranscript(messages=messages)

    for iteration in range(MAX_TOOL_ITERATIONS):
        turn: AssistantTurn = client.complete(messages, TOOL_DEFINITIONS)

        assistant_message: dict[str, Any] = {"role": "assistant", "content": turn.content}
        if turn.tool_calls:
            assistant_message["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": json.dumps(call.arguments, default=_json_default)},
                }
                for call in turn.tool_calls
            ]
        messages.append(assistant_message)

        if not turn.tool_calls:
            transcript.final_text = turn.content
            logger.info("shopper session ended on iteration %d with a final answer", iteration)
            return transcript

        for call in turn.tool_calls:
            result, is_error, verdict = _dispatch_tool_call(ctx, call.name, call.arguments)
            transcript.invocations.append(
                ToolInvocation(name=call.name, arguments=call.arguments, result=result, is_error=is_error)
            )
            if verdict is not None:
                transcript.verdicts.append(verdict)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.call_id,
                    "content": result if isinstance(result, str) else json.dumps(result, default=_json_default),
                }
            )

    transcript.hit_iteration_cap = True
    logger.warning("shopper session hit the %d-iteration cap without a final answer", MAX_TOOL_ITERATIONS)
    return transcript
