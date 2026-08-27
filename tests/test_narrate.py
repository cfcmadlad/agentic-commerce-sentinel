"""Tests for `reasoning.narrate`: narration, and the non-mutation guarantee.

Two kinds of coverage live here, deliberately kept apart per the module's
own determinism note:

- Structural tests, checked for exact equality every run: `NarrationInput`
  assembly, the verdict summary, rule/feature citations, and the guarantee
  that this layer cannot write back into a verdict.
- One live integration test against the real Groq API, skipped unless
  `GROQ_API_KEY` is set in the environment, since an LLM's prose is not
  byte-reproducible even at temperature 0.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import os
from uuid import uuid4

import numpy as np
import pytest

import reasoning.narrate as narrate_module
from detect.attribution import AttributionResult
from detect.baseline import BaselineDecision
from detect.ensemble import SOURCE_ALLOWED, SOURCE_BEHAVIORAL, SOURCE_RULES, EnsembleDecision
from detect.scope import ScopeViolationReason
from reasoning.narrate import GroqNarrationClient, build_narration_input, narrate
from reasoning.schema import Narration, NarrationInput
from tests.factories import build_session_trace


class _FakeClient:
    """A `NarrationClient` that returns a fixed string and records its prompts."""

    def __init__(self, response: str = "This session was blocked because a scope rule fired.") -> None:
        self.response = response
        self.system_prompts: list[str] = []
        self.user_prompts: list[str] = []

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.system_prompts.append(system_prompt)
        self.user_prompts.append(user_prompt)
        return self.response


def _blocked_by_rules() -> tuple[BaselineDecision, EnsembleDecision]:
    """Builds a baseline/ensemble pair blocked by a Layer 2 scope rule.

    Returns:
        A (baseline, ensemble) pair sharing one session ID.
    """
    session_id = uuid4()
    baseline = BaselineDecision(
        session_id=session_id,
        blocked=True,
        verification_reasons=(),
        scope_reasons=(ScopeViolationReason.AMOUNT_OVER_CEILING,),
    )
    ensemble = EnsembleDecision(
        session_id=session_id,
        blocked=True,
        source=SOURCE_RULES,
        behavioral_score=None,
        rules_fired=("layer2:amount_over_ceiling",),
    )
    return baseline, ensemble


def _allowed_by_behavioral_score(blocked: bool) -> tuple[BaselineDecision, EnsembleDecision]:
    """Builds a baseline/ensemble pair the rules allowed, scored by Layer 3.

    Args:
        blocked: Whether the behavioral score should cross the threshold.

    Returns:
        A (baseline, ensemble) pair sharing one session ID.
    """
    session_id = uuid4()
    baseline = BaselineDecision(session_id=session_id, blocked=False, verification_reasons=(), scope_reasons=())
    ensemble = EnsembleDecision(
        session_id=session_id,
        blocked=blocked,
        source=SOURCE_BEHAVIORAL if blocked else SOURCE_ALLOWED,
        behavioral_score=0.87 if blocked else 0.01,
        rules_fired=(),
    )
    return baseline, ensemble


def _attribution_for(feature_names: tuple[str, ...], row: tuple[float, ...]) -> AttributionResult:
    """Builds a single-row `AttributionResult` for narration tests.

    Args:
        feature_names: Column order.
        row: Signed SHAP values for the one row.

    Returns:
        An `AttributionResult` with one row.
    """
    values = np.array([row])
    return AttributionResult(
        feature_names=feature_names,
        shap_values=values,
        mean_abs_shap=tuple(abs(v) for v in row),
    )


# --- build_narration_input ---------------------------------------------------


def test_build_narration_input_rejects_baseline_ensemble_mismatch() -> None:
    """Wiring a baseline and ensemble decision for different sessions is a bug."""
    trace = build_session_trace()
    _, ensemble = _blocked_by_rules()
    other_baseline = BaselineDecision(session_id=uuid4(), blocked=True, verification_reasons=(), scope_reasons=())
    with pytest.raises(ValueError, match="session_id mismatch"):
        build_narration_input(trace, other_baseline, ensemble)


def test_build_narration_input_rejects_attribution_without_row_index() -> None:
    """Attribution without a row index is ambiguous and must fail loudly."""
    baseline, ensemble = _allowed_by_behavioral_score(blocked=True)
    trace = build_session_trace(session_id=ensemble.session_id)
    attribution = _attribution_for(("f1",), (0.5,))
    with pytest.raises(ValueError, match="row_index is required"):
        build_narration_input(trace, baseline, ensemble, attribution=attribution)


def test_build_narration_input_copies_verdict_fields_from_ensemble() -> None:
    """The assembled input must reflect the ensemble's own verdict, not re-derive it."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    result = build_narration_input(trace, baseline, ensemble)
    assert result.blocked is True
    assert result.source == SOURCE_RULES
    assert result.rules_fired == ("layer2:amount_over_ceiling",)
    assert result.behavioral_score is None
    assert result.top_features == ()


def test_build_narration_input_attaches_requested_top_features() -> None:
    """Attribution, when given, is trimmed to the requested row and top_n."""
    baseline, ensemble = _allowed_by_behavioral_score(blocked=True)
    trace = build_session_trace(session_id=ensemble.session_id)
    attribution = _attribution_for(
        ("agent_prior_session_count", "hour_of_day", "duration_seconds"),
        (0.9, -0.1, 0.05),
    )
    result = build_narration_input(trace, baseline, ensemble, attribution=attribution, row_index=0, top_n=2)
    assert len(result.top_features) == 2
    assert result.top_features[0][0] == "agent_prior_session_count"


def test_build_narration_input_copies_free_text_fields_verbatim() -> None:
    """Merchant/item fields are copied as-is; the narration layer must not alter them."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id, merchant_id="electronics-mart")
    result = build_narration_input(trace, baseline, ensemble)
    assert result.merchant_id == "electronics-mart"


# --- narrate: citations and verdict derivation -------------------------------


def test_narrate_verdict_summary_is_blocked_with_source() -> None:
    """A blocked verdict's summary must name the layer that blocked it."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    result = narrate(input_data, _FakeClient())
    assert result.verdict_summary == "blocked (rules)"


def test_narrate_verdict_summary_is_allowed() -> None:
    """An allowed verdict's summary must say so plainly."""
    baseline, ensemble = _allowed_by_behavioral_score(blocked=False)
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    result = narrate(input_data, _FakeClient())
    assert result.verdict_summary == "allowed"


def test_narrate_citations_match_input_not_llm_output() -> None:
    """rule_citations/feature_citations come from the input, regardless of narrative text."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    client = _FakeClient(response="a completely unrelated sentence naming nothing real")
    result = narrate(input_data, client)
    assert result.rule_citations == ("layer2:amount_over_ceiling",)
    assert result.narrative == "a completely unrelated sentence naming nothing real"


def test_narrate_prompt_cites_real_rule_and_feature_names() -> None:
    """The prompt sent to the LLM must name the actual rules and features, not placeholders."""
    baseline, ensemble = _allowed_by_behavioral_score(blocked=True)
    trace = build_session_trace(session_id=ensemble.session_id)
    attribution = _attribution_for(("agent_prior_session_count",), (0.9,))
    input_data = build_narration_input(
        trace, baseline, ensemble, attribution=attribution, row_index=0, threshold=0.5
    )
    client = _FakeClient()
    narrate(input_data, client)
    assert "agent_prior_session_count" in client.user_prompts[0]
    assert "0.5000" in client.user_prompts[0]


def test_narrate_prompt_states_no_rule_fired_when_none_did() -> None:
    """A session with nothing to cite must say so in the prompt, not omit the fact."""
    baseline, ensemble = _allowed_by_behavioral_score(blocked=False)
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    client = _FakeClient()
    narrate(input_data, client)
    assert "rules fired: none" in client.user_prompts[0]


def test_narrate_records_model_identifier_and_timestamp() -> None:
    """The narration must record which model produced it and when."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    result = narrate(input_data, _FakeClient(), model="openai/gpt-oss-120b")
    assert result.model == "openai/gpt-oss-120b"
    assert result.generated_at is not None


def _fake_groq_returning(content: str | None) -> object:
    """Builds a fake Groq-shaped client whose completion returns the given content.

    Args:
        content: The message content the fake completion should return.

    Returns:
        An object satisfying the small subset of the Groq client's shape
        `GroqNarrationClient.complete` actually touches.
    """

    class _Message:
        pass

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _FakeChatCompletions:
        def create(self, **_kwargs: object) -> _Response:
            return _Response()

    class _FakeChat:
        completions = _FakeChatCompletions()

    class _FakeGroq:
        chat = _FakeChat()

    _Message.content = content  # type: ignore[attr-defined]
    return _FakeGroq()


def test_groq_narration_client_rejects_none_content() -> None:
    """A Groq response with no message content must fail loudly, not narrate silently."""
    client = GroqNarrationClient(client=_fake_groq_returning(None))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="missing or empty"):
        client.complete("system", "user")


def test_groq_narration_client_rejects_empty_string_content() -> None:
    """An empty-string response is the same failure as None -- observed in practice.

    A reasoning model can spend its entire `max_completion_tokens` budget on
    invisible reasoning tokens and return an empty (not None) visible
    content string. Silently accepting that would put a blank narrative in
    the audit trail, so it must fail exactly like a missing response.
    """
    client = GroqNarrationClient(client=_fake_groq_returning(""))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="missing or empty"):
        client.complete("system", "user")


# --- structural non-mutation guarantee ---------------------------------------


def test_narration_input_and_narration_are_frozen() -> None:
    """Neither type may be mutated after construction."""
    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)
    with pytest.raises(dataclasses.FrozenInstanceError):
        input_data.blocked = False  # type: ignore[misc]

    result = narrate(input_data, _FakeClient())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.verdict_summary = "allowed"  # type: ignore[misc]


def test_narration_type_has_no_field_that_could_carry_a_verdict_back() -> None:
    """`Narration` must have no field typed as a detect/ decision type.

    This is the guarantee the module docstring describes: there is no field
    on the narration output whose type could be handed to
    `detect.ensemble.ensemble_decide` or stored back as a verdict. If a
    future edit ever added, say, a `verdict: EnsembleDecision` field to
    `Narration`, this test starts failing immediately.
    """
    forbidden_type_names = {"EnsembleDecision", "BaselineDecision", "CalibrationResult"}
    for field in dataclasses.fields(Narration):
        type_name = field.type if isinstance(field.type, str) else getattr(field.type, "__name__", "")
        assert not any(forbidden in str(type_name) for forbidden in forbidden_type_names), (
            f"Narration.{field.name} is typed {type_name!r}, which could carry a verdict back "
            f"into the detect/ layer"
        )


def test_narration_input_is_also_free_of_writeback_paths() -> None:
    """`NarrationInput` itself must hold copied values, not live decision references."""
    forbidden_type_names = {"EnsembleDecision", "BaselineDecision", "CalibrationResult"}
    for field in dataclasses.fields(NarrationInput):
        type_name = field.type if isinstance(field.type, str) else getattr(field.type, "__name__", "")
        assert not any(forbidden in str(type_name) for forbidden in forbidden_type_names)


def test_narrate_module_never_imports_calibration_or_behavioral() -> None:
    """AST-level guarantee: this module cannot touch the score or the threshold.

    Same discipline `features/session.py` uses to guarantee label isolation,
    and `generator/attacks/held_out.py` uses to guarantee the training
    corpus never imports the held-out generator: parse the module's own
    source and assert the forbidden imports are structurally absent, rather
    than trusting that nobody adds one later.
    """
    source = inspect.getsource(narrate_module)
    tree = ast.parse(source)
    forbidden_modules = {"detect.calibration", "detect.behavioral"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden_modules
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            assert node.module not in forbidden_modules


def test_ensemble_decision_itself_is_frozen() -> None:
    """Sanity check underpinning the whole guarantee: the input narrate() receives can't be mutated."""
    _, ensemble = _blocked_by_rules()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ensemble.blocked = not ensemble.blocked  # type: ignore[misc]


# --- live integration test (real Groq call) ----------------------------------


@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="GROQ_API_KEY not set; skipping live Groq call")
def test_narrate_live_groq_call_produces_a_real_explanation() -> None:
    """End-to-end smoke test against the real Groq API, run only when a key is configured."""
    from groq import Groq

    baseline, ensemble = _blocked_by_rules()
    trace = build_session_trace(session_id=ensemble.session_id)
    input_data = build_narration_input(trace, baseline, ensemble)

    client = GroqNarrationClient(client=Groq())
    result = narrate(input_data, client)

    assert result.verdict_summary == "blocked (rules)"
    assert result.rule_citations == ("layer2:amount_over_ceiling",)
    assert isinstance(result.narrative, str)
    assert len(result.narrative.strip()) > 0
