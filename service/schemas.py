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
from escalation.schema import Escalation, EscalationEvent
from mandate.schema import SignedMandate
from reasoning.schema import Counterfactual, Narration


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


class CounterfactualEditOut(BaseModel):
    """Wire form of `reasoning.schema.CounterfactualEdit`."""

    field: str
    real_value: str
    suggested_value: str


class CounterfactualOut(BaseModel):
    """Wire form of `reasoning.schema.Counterfactual`."""

    layer: str
    feasible: bool
    edits: list[CounterfactualEditOut]
    explanation: str


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
        counterfactual: The minimal-edit explanation of what would have
            allowed this session, or None for an allowed session (nothing
            to explain).
    """

    session_id: UUID
    baseline: BaselineDecisionOut
    ensemble: EnsembleDecisionOut
    attribution: list[AttributionRowOut] | None
    narrative: ReasoningNarrativeOut | None
    counterfactual: CounterfactualOut | None


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


class EscalationEventOut(BaseModel):
    """Wire form of `escalation.schema.EscalationEvent`."""

    event_id: UUID
    escalation_id: UUID | None
    session_id: UUID | None
    agent_id: str
    kind: str
    actor: str
    note: str
    created_at: datetime


class EscalationOut(BaseModel):
    """Wire form of `escalation.schema.Escalation`."""

    escalation_id: UUID
    session_id: UUID
    agent_id: str
    status: str
    reason: str
    opened_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    resolution: str | None
    events: list[EscalationEventOut]


class ReviewEscalationRequest(BaseModel):
    """A human reviewer's request to mark an escalation reviewed."""

    actor: str
    note: str = ""


class ResolveEscalationRequest(BaseModel):
    """A human reviewer's request to resolve a reviewed escalation."""

    actor: str
    note: str = ""
    decision: str


class CircuitBreakerResetRequest(BaseModel):
    """A human reviewer's request to lift an agent's circuit-breaker suspension."""

    actor: str
    note: str = ""


class CircuitBreakerStatusOut(BaseModel):
    """An agent's current circuit-breaker suspension status."""

    agent_id: str
    suspended: bool


def escalation_event_to_out(event: EscalationEvent) -> EscalationEventOut:
    """Renders an `EscalationEvent` as its wire form.

    Args:
        event: The event to render.

    Returns:
        The wire-form model.
    """
    return EscalationEventOut(
        event_id=event.event_id,
        escalation_id=event.escalation_id,
        session_id=event.session_id,
        agent_id=event.agent_id,
        kind=event.kind.value,
        actor=event.actor,
        note=event.note,
        created_at=event.created_at,
    )


def escalation_to_out(escalation: Escalation) -> EscalationOut:
    """Renders an `Escalation` as its wire form.

    Args:
        escalation: The escalation to render.

    Returns:
        The wire-form model.
    """
    return EscalationOut(
        escalation_id=escalation.escalation_id,
        session_id=escalation.session_id,
        agent_id=escalation.agent_id,
        status=escalation.status.value,
        reason=escalation.reason,
        opened_at=escalation.opened_at,
        reviewed_at=escalation.reviewed_at,
        reviewed_by=escalation.reviewed_by,
        resolved_at=escalation.resolved_at,
        resolved_by=escalation.resolved_by,
        resolution=escalation.resolution.value if escalation.resolution is not None else None,
        events=[escalation_event_to_out(e) for e in escalation.events],
    )


def counterfactual_to_out(counterfactual: Counterfactual) -> CounterfactualOut:
    """Renders a `Counterfactual` as its wire form.

    Args:
        counterfactual: The counterfactual to render.

    Returns:
        The wire-form model.
    """
    return CounterfactualOut(
        layer=counterfactual.layer,
        feasible=counterfactual.feasible,
        edits=[
            CounterfactualEditOut(field=e.field, real_value=e.real_value, suggested_value=e.suggested_value)
            for e in counterfactual.edits
        ],
        explanation=counterfactual.explanation,
    )


class ChainNodeOut(BaseModel):
    """One mandate along a delegation chain, with its own containment verdict.

    Attributes:
        mandate_id: This node's mandate ID.
        agent_id: The agent this mandate authorizes.
        parent_mandate_id: This node's own declared parent, or None if it
            is a root mandate.
        depth: 0 for the mandate the chain was requested for, 1 for its
            immediate parent, and so on up the chain.
        is_root: True if this node declares no parent at all.
        in_bounds: This node's own containment verdict against its
            immediate parent. None for a root (containment does not apply
            to one) or for a node whose own parent could not be resolved
            (see `unresolvable_parent`).
        reasons: Every containment rule that fired for this node, empty if
            `in_bounds` is True or None.
        unresolvable_parent: True if this node declares a parent that
            could not be found in the live mandate store -- distinct from
            a containment violation, since there is no scope to check
            against at all.
    """

    mandate_id: UUID
    agent_id: str
    parent_mandate_id: UUID | None
    depth: int
    is_root: bool
    in_bounds: bool | None
    reasons: list[str]
    unresolvable_parent: bool


class ChainEdgeOut(BaseModel):
    """One parent-child link along a delegation chain.

    Attributes:
        child_mandate_id: The delegated mandate.
        parent_mandate_id: The mandate it declares as its parent.
        violates: True if the child's containment check against this
            parent failed -- the edge the frontend highlights.
    """

    child_mandate_id: UUID
    parent_mandate_id: UUID
    violates: bool


class DelegationChainOut(BaseModel):
    """A mandate's full ancestor chain, each node's own containment verdict included.

    Attributes:
        nodes: The requested mandate (depth 0) and every resolved
            ancestor, deepest (closest to the requested mandate) first.
        edges: One entry per resolved parent-child link in `nodes`.
        chain_broken: True if the ancestor walk stopped before reaching an
            actual root (a cycle, the depth bound, or an unresolvable
            ancestor -- see `containment.chain.AncestorChainResolution
            .broken`).
        chain_broken_reason: Which of the three `chain_broken` caused,
            or None if the chain resolved cleanly to a root.
    """

    nodes: list[ChainNodeOut]
    edges: list[ChainEdgeOut]
    chain_broken: bool
    chain_broken_reason: str | None


class RevokeKeyRequest(BaseModel):
    """A human's request to revoke one of an agent's registered keys.

    Attributes:
        reason: One of `mandate.verification.KeyRevocationReason`'s values.
        revoked_by: Identifier of the human making the request.
    """

    reason: str
    revoked_by: str


DEFAULT_KEY_ROTATION_OVERLAP_HOURS = 24.0
"""Default overlap window for a routine key rotation.

Long enough to cover the realistic duration of any single in-flight
session many times over -- this project's own sessions complete in
seconds to minutes (see `eval/latency.py`'s measured percentiles) -- while
still bounding how long a key being rotated out keeps verifying at all.
Rotation is often prompted by suspected, not confirmed, compromise, so the
window should stay short relative to a day, not open-ended; a caller who
knows the old key is definitely compromised should pass `overlap_hours=0`
instead of relying on this default at all (see
`docs/adr/0014-agent-key-lifecycle.md`).
"""


class RotateKeyRequest(BaseModel):
    """A human's request to rotate an agent's key, with an overlap window.

    Attributes:
        new_key_id: Fingerprint of the incoming key.
        new_public_key_base64: The incoming key's public bytes, base64-encoded.
        overlap_hours: How long the old key keeps verifying after this
            request, before it is treated as revoked. Defaults to
            `DEFAULT_KEY_ROTATION_OVERLAP_HOURS`; pass `0` for an
            immediate cutover (suspected key compromise, not routine
            rotation).
        rotated_by: Identifier of the human making the request.
    """

    new_key_id: str
    new_public_key_base64: str
    overlap_hours: float = DEFAULT_KEY_ROTATION_OVERLAP_HOURS
    rotated_by: str


class KeyRevocationOut(BaseModel):
    """Wire form of `mandate.verification.KeyRevocation`."""

    agent_id: str
    key_id: str
    reason: str
    revoked_by: str
    revoked_at: datetime
    effective_at: datetime
