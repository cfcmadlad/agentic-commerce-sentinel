"""The shopper agent's three tools -- the only way it can act on anything real.

`checkout` is the single integration point with the real system and is
deliberately small: it calls `service.main.decide` in-process with a real,
already-signed mandate the scenario harness bound the agent to (never one
the model constructs or edits), then separately computes the real Layer 2.5
containment verdict via `service.delegation_chain.build_delegation_chain` --
the same function `GET /mandates/{id}/chain` uses, since containment is not
wired into `decide` itself (see that function's own docstring). If
containment finds a violation, `checkout` opens a real escalation the same
way `decide` already does for a behavioral block -- a mirrored, disclosed
extension of an existing pattern, not a new enforcement path.

Anti-tamper note, a deliberate deviation from a literal reading of the
project brief: `checkout`'s tool schema takes `(item_id, quantity)`, the same
two fields `propose_purchase` takes, not an opaque, model-echoed proposal
object carrying a price. A tool-calling model only ever sees its own prior
tool results as text it can, in principle, alter before echoing back;
trusting a monetary amount round-tripped through the model would let a
malformed or tampered proposal reach checkout. `checkout` re-derives the
proposal from the catalog itself, exactly like `propose_purchase` does, so
the only thing the model actually controls is which item and how many.

Every side effect here (audit log entries, escalation queue entries,
mandate/ledger state) lands on the `service.state.AppState` instance the
agent was constructed with -- always a demo-run-isolated instance built by
`agent.scenarios`, never the shared default paths a live service or the rest
of the test suite use. See `docs/adr/0016-governed-live-agent.md`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

from agent.catalog import CATALOG_CURRENCY, CatalogItem, find_item, search_items
from common.schema import EventType, SessionEvent, SessionTrace
from detect.ensemble import SOURCE_BEHAVIORAL
from mandate.schema import SignedMandate
from service.delegation_chain import build_delegation_chain
from service.main import decide
from service.schemas import DecideRequest
from service.state import AppState

logger = logging.getLogger(__name__)

MIN_QUANTITY = 1
MAX_QUANTITY = 20

# Standard event lifecycle stages and inter-stage gaps, matching the
# established `service/demo_scenarios.py`/`service/delegation_scenarios.py`
# convention of a fixed pacing template per scenario rather than real
# wall-clock tool-call latency -- an LLM call's own latency is not
# reproducible run to run, and this project's standing rule is that every
# random draw (here, every timestamp) traces back to a fixed, named value,
# never the system clock. `ShopperToolContext.event_gaps` selects which
# template a given scenario uses (this ordinary pacing vs. the scripted-fast
# pacing `agent.scenarios`'s escalated scenario uses to cross Layer 3's
# threshold, reusing the exact numbers the existing `BEHAVIORAL_ONLY_ID`
# demo scenario already proved does so).
STANDARD_EVENT_GAPS: tuple[float, ...] = (18.0, 24.0, 21.0, 26.0, 15.0)


class ToolValidationError(ValueError):
    """Raised when a tool call's arguments do not describe a valid action.

    Never silently corrected or defaulted -- a malformed or out-of-range
    argument (an unknown item ID, a non-positive quantity) is reported back
    to the model as an error message so it can retry with a valid call, per
    this project's standing "fail loudly, never silently pass" rule.
    """


@dataclass(frozen=True)
class PurchaseProposal:
    """A pure, no-side-effect candidate transaction against the fake catalog.

    Attributes:
        item: The catalog item being purchased.
        quantity: Number of units.
        total_amount: `item.price * quantity`, computed here rather than
            trusted from any external input.
        currency: Always `agent.catalog.CATALOG_CURRENCY`.
    """

    item: CatalogItem
    quantity: int
    total_amount: Decimal
    currency: str


@dataclass(frozen=True)
class SentinelVerdict:
    """The real Sentinel verdict for one checkout attempt.

    Attributes:
        session_id: The session ID this verdict was decided for.
        blocked: Whether Layers 1-3 (plus the circuit breaker) blocked the
            transaction. This is `decide`'s own verdict; it does not
            reflect a containment violation on its own, since containment
            is not part of `decide` -- see `containment_in_bounds` for that.
        source: Which layer decided -- one of `detect.ensemble`'s
            `SOURCE_*` constants, or `service.main.SOURCE_CIRCUIT_BREAKER`.
        rules_fired: Named deterministic rules that fired, if any.
        behavioral_score: Layer 3's score, if it was consulted.
        narrative: Layer 4's plain-language explanation of the `decide`
            verdict, or None if no narration client is configured for this
            run -- narration is best-effort, never a precondition.
        containment_in_bounds: The real Layer 2.5 verdict for this
            mandate's presented session, computed separately from `decide`
            via `service.delegation_chain.build_delegation_chain`. None for
            a root mandate (nothing to check containment against).
        containment_reasons: Every containment rule that fired, if
            `containment_in_bounds` is False.
        escalation_opened: True if this checkout opened a new escalation --
            either because Layer 3 flagged it (mirroring `decide`'s own
            behavior) or because containment found a violation (this
            package's own disclosed extension of that same pattern).
        escalation_id: The opened escalation's ID, if any.
    """

    session_id: UUID
    blocked: bool
    source: str
    rules_fired: tuple[str, ...]
    behavioral_score: float | None
    narrative: str | None
    containment_in_bounds: bool | None
    containment_reasons: tuple[str, ...]
    escalation_opened: bool
    escalation_id: UUID | None


@dataclass(frozen=True)
class ShopperToolContext:
    """Everything the three tools need, bound once per scenario -- never chosen by the model.

    The model only ever chooses *what to search for* and *which item and
    quantity to propose/check out*. Every other input to a real decision --
    which agent identity, which mandate, its signature, the session's event
    pacing, and which shared `AppState` any side effect lands on -- is fixed
    here by `agent.scenarios` before the agent loop ever starts. This is the
    structural half of "the agent cannot escalate its own authority": there
    is no tool argument through which a model could select a different
    mandate or a different agent identity.

    Attributes:
        agent_id: The demo shopper agent's identity, always prefixed
            `shopper-agent-` -- distinct from the live service's own
            `demo-agent-NN` namespace, so this package's demo runs can never
            collide with or be mistaken for the service's own demo agents
            (see the project brief's isolation requirement).
        user_id: The human principal this agent claims to act for.
        signed_mandate: The real, Ed25519-signed mandate this scenario binds
            the agent to.
        app_state: The demo-run-isolated application state every tool call
            reads and writes. Always built by `agent.scenarios` with its own
            temp-file audit/escalation log paths -- never the service's
            shared default paths.
        session_started_at: The anchor instant the session's event lifecycle
            starts from. Fixed, not wall-clock, so a session built from this
            context is exactly as reproducible as everything else the
            project builds from a seed.
        event_gaps: Inter-stage gaps (seconds) for the session's event
            lifecycle, one of the fixed pacing templates in this module.
            Must have exactly one fewer entry than the stage count
            `include_browse` selects.
        include_browse: Whether the session's event lifecycle includes a
            catalog-browse stage. False reproduces the scripted-fast,
            no-browse pacing the existing `BEHAVIORAL_ONLY_ID` demo
            scenario in `service/demo_scenarios.py` uses to cross Layer 3's
            threshold.
        catalog: The subset of `agent.catalog.CATALOG` this scenario makes
            searchable -- narrower than the full catalog so a scenario's
            prompt can plausibly steer the model toward the item the
            scenario needs, without silently hiding the full catalog either
            (every scenario in `agent.scenarios` exposes at least three
            items, including at least one it does not want chosen).
    """

    agent_id: str
    user_id: str
    signed_mandate: SignedMandate
    app_state: AppState
    session_started_at: datetime
    event_gaps: tuple[float, ...]
    include_browse: bool
    catalog: tuple[CatalogItem, ...]


def search_catalog(ctx: ShopperToolContext, query: str) -> tuple[CatalogItem, ...]:
    """Searches this scenario's catalog subset. Read-only, no side effects.

    Args:
        ctx: The bound tool context.
        query: Free-text search query.

    Returns:
        Every matching item from `ctx.catalog`.
    """
    matches = tuple(item for item in search_items(query) if item in ctx.catalog)
    logger.info("search_catalog(%r): %d match(es)", query, len(matches))
    return matches


def propose_purchase(ctx: ShopperToolContext, item_id: str, quantity: int) -> PurchaseProposal:
    """Builds a candidate transaction against the fake catalog. Pure, no side effects.

    Args:
        ctx: The bound tool context.
        item_id: The catalog item ID to purchase.
        quantity: Number of units. Must be a positive integer within
            `MIN_QUANTITY`..`MAX_QUANTITY`.

    Returns:
        The proposal, with `total_amount` computed here from the catalog's
        own price -- never trusted from any external input.

    Raises:
        ToolValidationError: If `item_id` is unknown to this scenario's
            catalog, or `quantity` is out of range.
    """
    item = find_item(item_id)
    if item is None or item not in ctx.catalog:
        raise ToolValidationError(f"unknown catalog item {item_id!r} for this scenario")
    if not (MIN_QUANTITY <= quantity <= MAX_QUANTITY):
        raise ToolValidationError(f"quantity must be between {MIN_QUANTITY} and {MAX_QUANTITY}, got {quantity}")

    proposal = PurchaseProposal(
        item=item, quantity=quantity, total_amount=item.price * quantity, currency=CATALOG_CURRENCY
    )
    logger.info("propose_purchase(%s, %d): total_amount=%s", item_id, quantity, proposal.total_amount)
    return proposal


def _build_session_trace(ctx: ShopperToolContext, proposal: PurchaseProposal) -> SessionTrace:
    """Builds the session trace for one checkout attempt.

    Args:
        ctx: The bound tool context.
        proposal: The re-derived, validated proposal to transact.

    Returns:
        The session trace, ready to submit alongside `ctx.signed_mandate`.
    """
    stages = [EventType.INTENT_CAPTURED, EventType.MANDATE_PRESENTED]
    if ctx.include_browse:
        stages.append(EventType.CATALOG_BROWSE)
    stages += [EventType.CART_BUILD, EventType.PAYMENT_ATTEMPT, EventType.PAYMENT_RESULT]
    if len(ctx.event_gaps) != len(stages) - 1:
        raise ToolValidationError(
            f"event_gaps must have {len(stages) - 1} entries for include_browse={ctx.include_browse}, "
            f"got {len(ctx.event_gaps)}"
        )
    timestamps = [ctx.session_started_at]
    for gap in ctx.event_gaps:
        timestamps.append(timestamps[-1] + timedelta(seconds=gap))
    events = [SessionEvent(event_type=stage, timestamp=ts) for stage, ts in zip(stages, timestamps, strict=True)]

    return SessionTrace(
        session_id=uuid4(),
        agent_id=ctx.agent_id,
        user_id=ctx.user_id,
        mandate_id=ctx.signed_mandate.mandate.mandate_id,
        merchant_id=proposal.item.merchant_id,
        merchant_category=proposal.item.merchant_category,
        item_category=proposal.item.item_category,
        amount=proposal.total_amount,
        currency=proposal.currency,
        events=events,
        started_at=events[0].timestamp,
        completed_at=events[-1].timestamp,
    )


def checkout(ctx: ShopperToolContext, item_id: str, quantity: int) -> SentinelVerdict:
    """Attempts a real checkout: the sole tool with any effect on real state.

    Re-derives the proposal from the catalog (see the module docstring's
    anti-tamper note), builds a real session trace, and submits it alongside
    `ctx.signed_mandate` to the real `service.main.decide` -- Layers 1-3 plus
    the circuit breaker. Separately computes the real Layer 2.5 containment
    verdict for the same mandate; if that verdict is a violation, opens a
    real escalation, mirroring `decide`'s own existing behavior for a
    behavioral block.

    Args:
        ctx: The bound tool context.
        item_id: The catalog item ID to purchase.
        quantity: Number of units.

    Returns:
        The real verdict.

    Raises:
        ToolValidationError: If `item_id`/`quantity` do not describe a valid
            proposal -- propagated from `propose_purchase`.
    """
    proposal = propose_purchase(ctx, item_id, quantity)
    trace = _build_session_trace(ctx, proposal)
    request = DecideRequest(trace=trace, signed_mandate=ctx.signed_mandate)
    response = decide(request, ctx.app_state)

    mandate = ctx.signed_mandate.mandate
    containment_in_bounds: bool | None = None
    containment_reasons: tuple[str, ...] = ()
    escalation_opened = False
    escalation_id: UUID | None = None

    if mandate.parent_mandate_id is not None:
        stored_mandate = ctx.app_state.mandate_store.get(mandate.mandate_id)
        assert stored_mandate is not None, (
            f"mandate {mandate.mandate_id} missing from the mandate store after decide() -- "
            "decide() always records a presented signed mandate before returning"
        )
        chain = build_delegation_chain(stored_mandate, ctx.app_state.mandate_store)
        focus_node = next(node for node in chain.nodes if node.mandate_id == mandate.mandate_id)
        containment_in_bounds = focus_node.in_bounds
        containment_reasons = tuple(focus_node.reasons)

        if containment_in_bounds is False:
            escalation = ctx.app_state.escalation_queue.open_escalation(
                session_id=trace.session_id,
                agent_id=trace.agent_id,
                reason=f"layer2.5 containment violation: {', '.join(containment_reasons)}",
                at=trace.started_at,
            )
            escalation_opened = True
            escalation_id = escalation.escalation_id
            logger.warning(
                "session %s: containment violation on checkout, escalation %s opened",
                trace.session_id,
                escalation_id,
            )

    if response.ensemble.source == SOURCE_BEHAVIORAL:
        # `decide()` itself already opened this escalation (it does so
        # unconditionally whenever Layer 3's source is behavioral, which
        # only ever occurs when the session was blocked) -- reported here
        # rather than re-derived, so the two ways checkout can end up in
        # the human-review queue (a behavioral flag or a containment
        # violation, above) are both visible on one verdict.
        escalation_opened = True

    return SentinelVerdict(
        session_id=trace.session_id,
        blocked=response.ensemble.blocked,
        source=response.ensemble.source,
        rules_fired=tuple(response.ensemble.rules_fired),
        behavioral_score=response.ensemble.behavioral_score,
        narrative=response.narrative.narrative if response.narrative is not None else None,
        containment_in_bounds=containment_in_bounds,
        containment_reasons=containment_reasons,
        escalation_opened=escalation_opened,
        escalation_id=escalation_id,
    )
