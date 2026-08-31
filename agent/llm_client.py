"""A tool-calling-capable Groq client, for the shopper agent only.

`reasoning.narrate.GroqNarrationClient` is plain-text-completion only
(`complete(system_prompt, user_prompt) -> str`) and is deliberately not
reused here: Layer 4 narrates an already-decided verdict and must never be
confused, in code or in the frontend, with a component that takes actions
(see `docs/adr/0016-governed-live-agent.md` and this package's own
`__init__.py` docstring on why the two stay architecturally distinct). This
module follows the same conventions `GroqNarrationClient` already
established -- the caller constructs `groq.Groq()` (which reads
`GROQ_API_KEY` itself) and passes the client in, so credential resolution
stays entirely the caller's responsibility, and a completion with no content
and no tool calls is treated as a hard failure, never a silent pass -- but
the call shape is genuinely different: this client asks for and returns tool
calls, not narration text.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from groq import Groq

logger = logging.getLogger(__name__)

# Same model already verified live against this project's own Groq account
# (see `reasoning/narrate.py`'s module docstring) and already known to
# support tool calling on Groq's own hosted lineup. Reusing it rather than
# picking a second model keeps this sprint's account/quota footprint to one
# model, not two.
DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_COMPLETION_TOKENS = 800


@dataclass(frozen=True)
class ToolDefinition:
    """One tool's schema, in the shape a tool-calling model needs to see it.

    Attributes:
        name: The tool's callable name -- must match the dispatch key
            `agent.shopper` uses to route a model's tool call.
        description: Plain-language description shown to the model.
        parameters: A JSON Schema object describing the tool's arguments.
    """

    name: str
    description: str
    parameters: dict[str, Any]

    def to_groq_param(self) -> dict[str, Any]:
        """Renders this definition as a Groq/OpenAI-shaped tool parameter.

        Returns:
            A `{"type": "function", "function": {...}}` dict, the exact
            shape `groq.types.chat.ChatCompletionToolParam` expects.
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class ToolCall:
    """One tool call the model asked for.

    Attributes:
        call_id: The model-assigned ID, echoed back in the tool-result
            message so the model can match its call to the result.
        name: The tool name requested.
        arguments: The parsed JSON arguments the model supplied. Parsing
            happens here, once, rather than leaving every caller to repeat
            `json.loads` on the raw string the SDK returns.
    """

    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class AssistantTurn:
    """One assistant turn: either a final answer, one or more tool calls, or both.

    Attributes:
        content: The assistant's text content, if any. A tool-calls-only
            turn commonly has no content -- that is expected, not an error.
        tool_calls: Every tool call requested this turn, in the order the
            model returned them.
    """

    content: str | None
    tool_calls: tuple[ToolCall, ...]


class ToolCallingClient(Protocol):
    """A minimal tool-calling chat-completion interface `agent.shopper` depends on.

    Isolates the agent loop from any specific LLM SDK, the same way
    `reasoning.narrate.NarrationClient` isolates narration -- a test can
    supply a fake implementation with no network access, and a future
    provider swap needs only a new adapter class.
    """

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        """Runs one chat-completion turn, offering the given tools.

        Args:
            messages: The full conversation so far, OpenAI/Groq message-dict
                shape (`role`, `content`, and for tool-result messages
                `tool_call_id`).
            tools: The tools available to the model this turn.

        Returns:
            The assistant's turn.
        """
        ...  # pragma: no cover - protocol method


@dataclass(frozen=True)
class GroqToolCallingClient:
    """Adapts the Groq SDK's chat completions API to `ToolCallingClient`.

    Attributes:
        client: A constructed `groq.Groq` instance. Constructed by the
            caller, not here -- same discipline as `GroqNarrationClient`.
        model: The Groq model ID to call.
        temperature: Sampling temperature.
        max_completion_tokens: Cap on generated tokens per turn.
    """

    client: Groq
    model: str = DEFAULT_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS

    def complete(self, messages: list[dict[str, Any]], tools: tuple[ToolDefinition, ...]) -> AssistantTurn:
        """Calls Groq's chat completions API with the given tools available.

        Args:
            messages: The full conversation so far.
            tools: The tools available to the model this turn. An empty
                tuple omits the `tools` parameter entirely rather than
                sending an empty list, matching how a caller with nothing
                left to offer (the final summary turn) would naturally
                call this.

        Returns:
            The assistant's turn.

        Raises:
            RuntimeError: If Groq returns a completion with no tool calls
                and no message content -- a real failure for an agent loop
                to silently accept, the same class of guard
                `GroqNarrationClient.complete` already applies to narration.
        """
        create_kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
        }
        if tools:
            create_kwargs["tools"] = [t.to_groq_param() for t in tools]
            create_kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**create_kwargs)
        message = response.choices[0].message
        raw_tool_calls = message.tool_calls or []

        tool_calls = tuple(
            ToolCall(call_id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments or "{}"))
            for tc in raw_tool_calls
        )
        content = message.content

        if not tool_calls and not content:
            raise RuntimeError("Groq chat completion returned neither tool calls nor message content")

        logger.info("shopper agent turn: %d tool call(s), content=%s", len(tool_calls), content is not None)
        return AssistantTurn(content=content, tool_calls=tool_calls)
