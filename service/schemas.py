"""Request and response schemas for the API service.

The request body reuses `common.schema.SessionTrace` and
`mandate.schema.SignedMandate` directly -- both are already Pydantic
models, so redefining a parallel request schema would only create a
second place for the wire format to drift from what the rest of the
project actually operates on.

The response schema is written explicitly, field by field, from the real
`detect.baseline.BaselineDecision` / `detect.ensemble.EnsembleDecision` /
`detect.attribution` / `reasoning.schema.Narration` dataclasses -- not a
generic `dataclasses.asdict` walk -- matching the convention
`eval/report_json.py` already established for the metrics dashboard export,
for the same reason: those dataclasses carry enum members and other
values that are not JSON-safe as-is, and an explicit mapping is the one
place a reviewer can check the wire shape against the internal type by
reading both side by side. This response shape mirrors
`frontend/src/types/contract.ts::SessionDecisionResponse` field for field.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from common.schema import SessionTrace
from detect.attribution import AttributionResult
from detect.baseline import BaselineDecision
from detect.ensemble import EnsembleDecision
from mandate.schema import SignedMandate
from reasoning.schema import Narration


class DecideRequest(BaseModel):
    """One session submitted for a decision.

    Attributes:
        trace: The session's transaction and event lifecycle.
        signed_mandate: The mandate presented alongside it, or None for a
            session that presents no mandate at all -- itself a Layer 2
            finding (`no_mandate_presented`), not a request error.
    """

    trace: SessionTrace
    signed_mandate: SignedMandate | None = None


class BaselineDecisionOut(BaseModel):
    """Wire form of `detect.baseline.BaselineDecision`."""

    session_id: UUID
    blocked: bool
    verification_reasons: list[str]
    scope_reasons: list[str]
    fired_rules: list[str]


class EnsembleDecisionOut(BaseModel):
    """Wire form of `detect.ensemble.EnsembleDecision`."""

    session_id: UUID
    blocked: bool
    source: str
    behavioral_score: float | None
    rules_fired: list[str]


class AttributionRowOut(BaseModel):
    """One feature's signed contribution to a session's score."""

    feature: str
    shap_value: float


class ReasoningNarrativeOut(BaseModel):
    """Wire form of `reasoning.schema.Narration`."""

    session_id: UUID
    verdict_summary: str
    narrative: str
    rule_citations: list[str]
    feature_citations: list[str]
    model: str
    generated_at: datetime


class SessionDecisionResponse(BaseModel):
    """The full per-session decision record returned to a caller.

    Attributes:
        session_id: The session decided on.
        baseline: The Layer 1/2 verdict.
        ensemble: The combined Layer 1-3 verdict.
        attribution: Per-feature SHAP contribution, or None if Layer 3 was
            never consulted (the rules already blocked the session).
        narrative: The Layer 4 narration, or None if no narration client
            was configured for this service instance (see
            `service/state.py`) -- narration is best-effort, not a
            structural requirement of the decision itself.
    """

    session_id: UUID
    baseline: BaselineDecisionOut
    ensemble: EnsembleDecisionOut
    attribution: list[AttributionRowOut] | None
    narrative: ReasoningNarrativeOut | None


def baseline_to_out(decision: BaselineDecision) -> BaselineDecisionOut:
    """Renders a `BaselineDecision` as its wire form.

    Args:
        decision: The decision to render.

    Returns:
        The wire-form model.
    """
    return BaselineDecisionOut(
        session_id=decision.session_id,
        blocked=decision.blocked,
        verification_reasons=[r.value for r in decision.verification_reasons],
        scope_reasons=[r.value for r in decision.scope_reasons],
        fired_rules=list(decision.fired_rules),
    )


def ensemble_to_out(decision: EnsembleDecision) -> EnsembleDecisionOut:
    """Renders an `EnsembleDecision` as its wire form.

    Args:
        decision: The decision to render.

    Returns:
        The wire-form model.
    """
    return EnsembleDecisionOut(
        session_id=decision.session_id,
        blocked=decision.blocked,
        source=decision.source,
        behavioral_score=decision.behavioral_score,
        rules_fired=list(decision.rules_fired),
    )


def attribution_row_to_out(attribution: AttributionResult, row_index: int) -> list[AttributionRowOut]:
    """Renders one row's full signed attribution as its wire form.

    Args:
        attribution: The corpus-level attribution containing the row.
        row_index: The row to render.

    Returns:
        Every feature's signed contribution for that row, in
        `attribution.feature_names` order (not re-ranked, unlike
        `explain_row`'s top-N convenience view -- a caller inspecting the
        full response gets the complete picture, not a truncated one).
    """
    row = attribution.shap_values[row_index]
    pairs = zip(attribution.feature_names, row, strict=True)
    return [AttributionRowOut(feature=name, shap_value=float(value)) for name, value in pairs]


def narration_to_out(narration: Narration) -> ReasoningNarrativeOut:
    """Renders a `Narration` as its wire form.

    Args:
        narration: The narration to render.

    Returns:
        The wire-form model.
    """
    return ReasoningNarrativeOut(
        session_id=narration.session_id,
        verdict_summary=narration.verdict_summary,
        narrative=narration.narrative,
        rule_citations=list(narration.rule_citations),
        feature_citations=list(narration.feature_citations),
        model=narration.model,
        generated_at=narration.generated_at,
    )
