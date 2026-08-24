"""Shared session trace and ground-truth labeling types.

These types are consumed by the generator (which produces them), the mandate
and scope layers (which read the mandate/merchant/amount fields), the feature
extractor, and the eval harness (which reads the ground truth). They live
outside `/mandate` and `/generator` because both of those layers need to
import this module without importing each other.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EventType(str, Enum):
    """Stages of an agent-initiated commerce session.

    Mirrors the AP2-style flow (intent capture, mandate issuance, catalog and
    cart interaction, payment) referenced in Section 4 of the project brief,
    simplified to the granularity the behavioral layer needs.
    """

    INTENT_CAPTURED = "intent_captured"
    MANDATE_ISSUED = "mandate_issued"
    CATALOG_BROWSE = "catalog_browse"
    CART_BUILD = "cart_build"
    MANDATE_PRESENTED = "mandate_presented"
    PAYMENT_ATTEMPT = "payment_attempt"
    PAYMENT_RESULT = "payment_result"


class SessionEvent(BaseModel):
    """A single timestamped step within an agent session.

    Attributes:
        event_type: The stage of the commerce flow this event represents.
        timestamp: UTC time the event occurred.
        payload: Freeform, event-specific detail (e.g. items browsed, cart
            contents). Kept schema-light on purpose: the behavioral layer
            (Layer 3) derives aggregate features from sequences of these
            events rather than depending on rigid per-field payload shapes.
    """

    model_config = ConfigDict(frozen=True)

    event_type: EventType
    timestamp: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class SessionTrace(BaseModel):
    """The full record of one agent-initiated commerce session.

    Attributes:
        session_id: Unique identifier for this session.
        agent_id: Identity of the AI agent that ran the session.
        user_id: Identity of the human principal on whose behalf the agent
            claims to act.
        mandate_id: The mandate the agent presented to authorize the
            transaction, if any. None represents a session with no mandate
            presented at all (itself a scope-layer finding, not a crypto
            one).
        merchant_id: Specific merchant the transaction was placed with.
        merchant_category: Merchant category code / label (e.g. "grocery",
            "electronics").
        item_category: Category of the item(s) purchased.
        amount: Transaction amount.
        currency: ISO 4217 currency code.
        events: Chronologically ordered events within the session.
        started_at: UTC timestamp of the first event.
        completed_at: UTC timestamp of the last event.

    Raises:
        ValueError: If `events` is empty, if `completed_at` precedes
            `started_at`, or if `amount` is not positive. Session traces are
            inputs to a fraud detector; a malformed trace must fail loudly
            at construction time rather than silently propagate into
            feature extraction.
    """

    model_config = ConfigDict(frozen=True)

    session_id: UUID
    agent_id: str
    user_id: str
    mandate_id: UUID | None
    merchant_id: str
    merchant_category: str
    item_category: str
    amount: Decimal
    currency: str = Field(min_length=3, max_length=3)
    events: list[SessionEvent]
    started_at: datetime
    completed_at: datetime

    @model_validator(mode="after")
    def _check_consistency(self) -> SessionTrace:
        """Enforces temporal and structural invariants.

        Returns:
            The validated instance, unchanged.

        Raises:
            ValueError: If any invariant is violated.
        """
        if not self.events:
            raise ValueError(f"session {self.session_id} has zero events")
        if self.completed_at < self.started_at:
            raise ValueError(
                f"session {self.session_id} completed_at precedes started_at"
            )
        if self.amount <= 0:
            raise ValueError(f"session {self.session_id} amount must be positive")
        return self


class AttackClass(str, Enum):
    """The attack taxonomy from Section 3 of the project brief.

    MANDATE_CHAINING is the held-out class: it must never appear in any
    training or tuning split, only in the single final evaluation pass.
    """

    LEGITIMATE = "legitimate"
    MANDATE_REPLAY = "mandate_replay"
    SCOPE_VIOLATION = "scope_violation"
    AGENT_IMPERSONATION = "agent_impersonation"
    MANDATE_CHAINING = "mandate_chaining"  # held out, see Section 3


class LabeledSession(BaseModel):
    """A generated session paired with ground truth, for generator/eval use only.

    Do not pass this type, or any field derived from `attack_class` or
    `is_attack`, into feature extraction or the detector. Section 5's
    anti-rigging rule requires that no feature be a deterministic function of
    the label; the label lives on a separate wrapper type specifically so
    that passing a bare `SessionTrace` into `/features` is the only thing
    that type-checks, and leaking ground truth requires deliberately
    reaching into a wrapper object most detector code has no reason to touch.

    Attributes:
        trace: The session trace itself, the only field the detector may see.
        attack_class: Ground-truth attack category, including LEGITIMATE.
        is_attack: Convenience flag, equivalent to
            `attack_class != AttackClass.LEGITIMATE`.
        generator_seed: RNG seed used to produce this session, for
            reproducibility.
        generator_params_digest: Hash of the generator parameter set in
            effect when this session was produced, for the sensitivity
            analysis required in Section 5.
    """

    model_config = ConfigDict(frozen=True)

    trace: SessionTrace
    attack_class: AttackClass
    is_attack: bool
    generator_seed: int
    generator_params_digest: str

    @model_validator(mode="after")
    def _check_is_attack_matches_class(self) -> LabeledSession:
        """Ensures `is_attack` cannot drift from `attack_class`.

        Returns:
            The validated instance, unchanged.

        Raises:
            ValueError: If `is_attack` is inconsistent with `attack_class`.
        """
        expected = self.attack_class != AttackClass.LEGITIMATE
        if self.is_attack != expected:
            raise ValueError(
                f"is_attack={self.is_attack} inconsistent with "
                f"attack_class={self.attack_class}"
            )
        return self