"""Tests for `agent.llm_client`, the tool-calling Groq adapter.

Uses hand-built stand-ins for the Groq SDK's response shape (a `choices`
list of message objects) rather than the real client -- no network access,
matching `tests/test_narrate.py`'s own `_FakeClient` convention for
`GroqNarrationClient`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from agent.llm_client import GroqToolCallingClient, ToolDefinition


@dataclass
class _FakeFunction:
    name: str
    arguments: str


@dataclass
class _FakeToolCall:
    id: str
    function: _FakeFunction


@dataclass
class _FakeMessage:
    content: str | None
    tool_calls: list[_FakeToolCall] | None = None


@dataclass
class _FakeChoice:
    message: _FakeMessage


@dataclass
class _FakeCompletion:
    choices: list[_FakeChoice]


class _FakeCompletionsResource:
    """Stands in for `groq.Groq().chat.completions`, recording the last call."""

    def __init__(self, response: _FakeCompletion) -> None:
        self._response = response
        self.last_kwargs: dict[str, Any] | None = None

    def create(self, **kwargs: Any) -> _FakeCompletion:  # noqa: ANN401
        self.last_kwargs = kwargs
        return self._response


class _FakeChatResource:
    def __init__(self, completions: _FakeCompletionsResource) -> None:
        self.completions = completions


@dataclass
class _FakeGroqClient:
    """Stands in for `groq.Groq()` -- only the `.chat.completions.create` surface is used."""

    chat: _FakeChatResource = field(init=False)
    _completions: _FakeCompletionsResource = field(init=False)

    def __init__(self, response: _FakeCompletion) -> None:
        self._completions = _FakeCompletionsResource(response)
        self.chat = _FakeChatResource(self._completions)


_SEARCH_TOOL = ToolDefinition(
    name="search_catalog", description="Search the catalog.", parameters={"type": "object", "properties": {}}
)


def test_tool_definition_renders_groq_shape() -> None:
    """`to_groq_param` produces the exact `{"type": "function", "function": {...}}` shape."""
    rendered = _SEARCH_TOOL.to_groq_param()
    assert rendered == {
        "type": "function",
        "function": {
            "name": "search_catalog",
            "description": "Search the catalog.",
            "parameters": {"type": "object", "properties": {}},
        },
    }


def test_complete_returns_tool_calls_with_parsed_arguments() -> None:
    """A response carrying tool calls is parsed into `ToolCall`s with JSON-decoded arguments."""
    response = _FakeCompletion(
        choices=[
            _FakeChoice(
                message=_FakeMessage(
                    content=None,
                    tool_calls=[
                        _FakeToolCall(
                            id="call-1", function=_FakeFunction(name="search_catalog", arguments='{"query": "earbuds"}')
                        )
                    ],
                )
            )
        ]
    )
    client = GroqToolCallingClient(client=_FakeGroqClient(response))  # type: ignore[arg-type]
    turn = client.complete([{"role": "user", "content": "hi"}], (_SEARCH_TOOL,))
    assert turn.content is None
    assert len(turn.tool_calls) == 1
    assert turn.tool_calls[0].call_id == "call-1"
    assert turn.tool_calls[0].name == "search_catalog"
    assert turn.tool_calls[0].arguments == {"query": "earbuds"}


def test_complete_returns_content_only_turn() -> None:
    """A response with no tool calls and real content is a final-answer turn."""
    response = _FakeCompletion(choices=[_FakeChoice(message=_FakeMessage(content="All done.", tool_calls=None))])
    client = GroqToolCallingClient(client=_FakeGroqClient(response))  # type: ignore[arg-type]
    turn = client.complete([{"role": "user", "content": "hi"}], ())
    assert turn.content == "All done."
    assert turn.tool_calls == ()


def test_complete_raises_on_neither_content_nor_tool_calls() -> None:
    """A completion with no content and no tool calls is a hard failure, never a silent pass."""
    response = _FakeCompletion(choices=[_FakeChoice(message=_FakeMessage(content=None, tool_calls=None))])
    client = GroqToolCallingClient(client=_FakeGroqClient(response))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="neither tool calls nor message content"):
        client.complete([{"role": "user", "content": "hi"}], ())


def test_complete_omits_tools_kwarg_when_no_tools_offered() -> None:
    """An empty tools tuple omits the `tools`/`tool_choice` kwargs rather than sending an empty list."""
    response = _FakeCompletion(choices=[_FakeChoice(message=_FakeMessage(content="ok", tool_calls=None))])
    fake_client = _FakeGroqClient(response)
    client = GroqToolCallingClient(client=fake_client)  # type: ignore[arg-type]
    client.complete([{"role": "user", "content": "hi"}], ())
    assert fake_client._completions.last_kwargs is not None
    assert "tools" not in fake_client._completions.last_kwargs
    assert "tool_choice" not in fake_client._completions.last_kwargs


def test_complete_includes_tools_kwarg_when_tools_offered() -> None:
    """A non-empty tools tuple is rendered into the `tools` kwarg with `tool_choice="auto"`."""
    response = _FakeCompletion(choices=[_FakeChoice(message=_FakeMessage(content="ok", tool_calls=None))])
    fake_client = _FakeGroqClient(response)
    client = GroqToolCallingClient(client=fake_client)  # type: ignore[arg-type]
    client.complete([{"role": "user", "content": "hi"}], (_SEARCH_TOOL,))
    assert fake_client._completions.last_kwargs is not None
    assert fake_client._completions.last_kwargs["tool_choice"] == "auto"
    assert fake_client._completions.last_kwargs["tools"] == [_SEARCH_TOOL.to_groq_param()]
