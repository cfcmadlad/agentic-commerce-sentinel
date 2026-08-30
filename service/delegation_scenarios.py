"""Fixed delegation-chain demo scenarios for the frontend's Delegation view.

Three scenarios, each a real parent mandate plus one or two children --
built with the exact same demo-agent key material and deterministic-label
ID derivation `service/demo_scenarios.py` already established, so mandates
signed here verify against a real running service and export byte-for-byte
identically across processes.

None of these scenarios' child sessions are blocked by Layers 1-3: each
child's own transaction fits inside the *child's own* declared ceiling,
which is exactly the point. Layer 2.5 (containment, checked against the
*parent's* ceiling) is not part of the live `/sessions/decide` path (see
`docs/adr/0008-counterfactual-explanations.md`'s scope note and
`docs/adr/0011-delegation-graph-and-narration-chat.md`), so these scenarios
are a live, concrete demonstration of the exact gap
`docs/adr/0003-held-out-class-evaluation.md` and
`docs/adr/0004-delegation-chain-containment.md` already disclosed: an
over-scoped or fanned-out delegation chain that Layers 1-3 alone cannot
see, made visible here only because `GET /mandates/{id}/chain` computes
Layer 2.5's verdict as a separate, explicit read, not because the live
decision path caught it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import NAMESPACE_URL, UUID, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.schema import EventType, SessionEvent, SessionTrace
from mandate.schema import Mandate, MandateScope
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate
from service.schemas import DecideRequest

ANCHOR = datetime(2026, 2, 1, 9, 0, 0, tzinfo=UTC)

VALID_DELEGATION_CHILD_ID = UUID("a1a1a1a1-1111-4111-8111-111111111111")
OVER_SCOPED_CHILD_ID = UUID("b2b2b2b2-2222-4222-8222-222222222222")
FANOUT_SIBLING_A_ID = UUID("c3c3c3c3-3333-4333-8333-333333333333")
FANOUT_SIBLING_B_ID = UUID("c3c3c3c3-4444-4444-8444-444444444444")


def _stable_uuid(label: str) -> UUID:
    """Derives a fixed, deterministic UUID from a label string.

    Matches `service.demo_scenarios._stable_uuid` exactly, for the same
    reason: this module is called from both a live service process
    (nowhere yet -- these scenarios are export-only, see the module
    docstring) and `run_delegation_demo_export.py`, and both need to agree
    on every ID byte-for-byte.

    Args:
        label: A unique, stable label for the identity being derived.

    Returns:
        A UUID5 derived deterministically from the label.
    """
    return uuid5(NAMESPACE_URL, f"sentinel-delegation-scenario:{label}")


def _demo_keypair(index: int) -> tuple[Ed25519PrivateKey, str, str]:
    """Re-derives one of `service.state`'s own demo agent keypairs.

    Args:
        index: Demo agent index (0, 1, or 2).

    Returns:
        `(private_key, agent_id, key_id)`.
    """
    seed_bytes = hashlib.sha256(f"sentinel-demo-agent-{index}".encode("utf-8")).digest()
    private_key, public_key = keypair_from_seed_bytes(seed_bytes)
    agent_id = f"demo-agent-{index:02d}"
    key_id = key_id_for_public_key(public_key)
    return private_key, agent_id, key_id


def _events(start: datetime) -> list[SessionEvent]:
    """Builds a standard, unremarkable event lifecycle starting at `start`.

    Args:
        start: Timestamp of the first event.

    Returns:
        The ordered event list.
    """
    stages = [
        EventType.INTENT_CAPTURED,
        EventType.MANDATE_PRESENTED,
        EventType.CATALOG_BROWSE,
        EventType.CART_BUILD,
        EventType.PAYMENT_ATTEMPT,
        EventType.PAYMENT_RESULT,
    ]
    gaps = (18.0, 24.0, 21.0, 26.0, 15.0)
    timestamps = [start]
    for gap in gaps:
        timestamps.append(timestamps[-1] + timedelta(seconds=gap))
    return [SessionEvent(event_type=stage, timestamp=ts) for stage, ts in zip(stages, timestamps, strict=True)]


def _mandate(
    label: str,
    agent_id: str,
    user_id: str,
    key_id: str,
    max_amount: Decimal,
    parent_mandate_id: UUID | None = None,
) -> Mandate:
    """Builds one mandate scoped to grocery/packaged_food, issued at ANCHOR - 2h.

    Args:
        label: A stable label identifying this mandate (see `_stable_uuid`).
        agent_id: The agent this mandate authorizes.
        user_id: The human principal granting authority.
        key_id: Fingerprint of the key expected to sign this mandate.
        max_amount: Per-transaction spending ceiling.
        parent_mandate_id: If this is a delegated child, its parent's ID.

    Returns:
        The unsigned mandate.
    """
    valid_from = ANCHOR - timedelta(hours=2)
    valid_until = ANCHOR + timedelta(hours=6)
    return Mandate(
        mandate_id=_stable_uuid(f"mandate:{label}"),
        agent_id=agent_id,
        user_id=user_id,
        parent_mandate_id=parent_mandate_id,
        issued_at=valid_from,
        expires_at=valid_until + timedelta(hours=1),
        nonce=_stable_uuid(f"nonce:{label}").hex,
        scope=MandateScope(
            max_amount=max_amount,
            currency="INR",
            allowed_merchant_categories=frozenset({"grocery"}),
            allowed_item_categories=frozenset({"packaged_food"}),
            valid_from=valid_from,
            valid_until=valid_until,
            max_transaction_count=10,
        ),
        signer_key_id=key_id,
    )


def _trace(
    label: str, agent_id: str, user_id: str, mandate_id: UUID, amount: Decimal, session_id: UUID
) -> SessionTrace:
    """Builds one session trace presenting `mandate_id`, at ANCHOR.

    Args:
        label: A stable label for this session (used only for readability;
            `session_id` is what actually fixes the ID).
        agent_id: The agent that ran this session.
        user_id: The human principal on whose behalf the agent acted.
        mandate_id: The mandate presented.
        amount: The transaction amount.
        session_id: The fixed session ID the frontend keys by.

    Returns:
        The session trace.
    """
    events = _events(ANCHOR)
    return SessionTrace(
        session_id=session_id,
        agent_id=agent_id,
        user_id=user_id,
        mandate_id=mandate_id,
        merchant_id="freshmart-01",
        merchant_category="grocery",
        item_category="packaged_food",
        amount=amount,
        currency="INR",
        events=events,
        started_at=events[0].timestamp,
        completed_at=events[-1].timestamp,
    )


@dataclass(frozen=True)
class DelegationScenario:
    """One named delegation-chain scenario.

    Attributes:
        key: Stable machine-readable identifier (matches the frontend's
            scenario picker).
        label: Human-readable label.
        description: One-sentence plain-language framing.
        parent_request: The parent mandate's own decide request.
        child_requests: One decide request per child mandate (one for
            "valid"/"over-scoped", two siblings for "fanout").
        focus_mandate_id: Which mandate's chain the frontend should fetch
            and display -- the most recently added child.
    """

    key: str
    label: str
    description: str
    parent_request: DecideRequest
    child_requests: tuple[DecideRequest, ...]
    focus_mandate_id: UUID


def build_delegation_scenarios() -> tuple[DelegationScenario, ...]:
    """Builds the three fixed delegation-chain scenarios.

    Returns:
        The scenarios, in display order.
    """
    scenarios: list[DelegationScenario] = []

    # Scenario A: a child whose scope fits inside its parent's -- in bounds.
    key0, agent0, key_id0 = _demo_keypair(0)
    user0 = "demo-user-delegation-00"
    parent_a = _mandate("valid:parent", agent0, user0, key_id0, max_amount=Decimal("5000"))
    signed_parent_a = sign_mandate(parent_a, key0)
    parent_a_trace = _trace(
        "valid:parent", agent0, user0, parent_a.mandate_id, Decimal("1200.00"), _stable_uuid("session:valid:parent")
    )
    child_a = _mandate(
        "valid:child", agent0, user0, key_id0, max_amount=Decimal("2000"), parent_mandate_id=parent_a.mandate_id
    )
    signed_child_a = sign_mandate(child_a, key0)
    child_a_trace = _trace(
        "valid:child", agent0, user0, child_a.mandate_id, Decimal("1500.00"), VALID_DELEGATION_CHILD_ID
    )
    scenarios.append(
        DelegationScenario(
            key="valid_delegation",
            label="Valid delegation",
            description="A child mandate whose ceiling and window both fit inside its parent's.",
            parent_request=DecideRequest(trace=parent_a_trace, signed_mandate=signed_parent_a),
            child_requests=(DecideRequest(trace=child_a_trace, signed_mandate=signed_child_a),),
            focus_mandate_id=child_a.mandate_id,
        )
    )

    # Scenario B: a child mandate whose ceiling exceeds its parent's. Layers
    # 1-3 allow the child's own transaction (it fits the CHILD's own
    # ceiling) -- only the chain view's Layer 2.5 check sees the violation.
    key1, agent1, key_id1 = _demo_keypair(1)
    user1 = "demo-user-delegation-01"
    parent_b = _mandate("over_scoped:parent", agent1, user1, key_id1, max_amount=Decimal("1000"))
    signed_parent_b = sign_mandate(parent_b, key1)
    parent_b_trace = _trace(
        "over_scoped:parent",
        agent1,
        user1,
        parent_b.mandate_id,
        Decimal("400.00"),
        _stable_uuid("session:over_scoped:parent"),
    )
    child_b = _mandate(
        "over_scoped:child",
        agent1,
        user1,
        key_id1,
        max_amount=Decimal("5000"),
        parent_mandate_id=parent_b.mandate_id,
    )
    signed_child_b = sign_mandate(child_b, key1)
    child_b_trace = _trace(
        "over_scoped:child", agent1, user1, child_b.mandate_id, Decimal("3000.00"), OVER_SCOPED_CHILD_ID
    )
    scenarios.append(
        DelegationScenario(
            key="over_scoped_child",
            label="Over-scoped child",
            description=(
                "A delegated mandate whose own ceiling (5000) exceeds its parent's (1000). "
                "The transaction below stays within the CHILD's own ceiling, so Layers 1-3 allow "
                "it -- exactly the gap docs/adr/0003 and docs/adr/0004 already disclosed, made "
                "visible here because this view checks Layer 2.5 directly."
            ),
            parent_request=DecideRequest(trace=parent_b_trace, signed_mandate=signed_parent_b),
            child_requests=(DecideRequest(trace=child_b_trace, signed_mandate=signed_child_b),),
            focus_mandate_id=child_b.mandate_id,
        )
    )

    # Scenario C: two siblings, each individually within the parent's own
    # ceiling, but together exceeding it -- the fanout_structuring shape
    # docs/adr/0004 measured 75.46% recall on (the second-plus sibling is
    # caught by the offline containment evaluation; here too, only the
    # *second* sibling's chain view shows the violation, matching that
    # ADR's own finding that the first sibling in such a group is
    # indistinguishable from an ordinary well-scoped delegation).
    key2, agent2, key_id2 = _demo_keypair(2)
    user2 = "demo-user-delegation-02"
    parent_c = _mandate("fanout:parent", agent2, user2, key_id2, max_amount=Decimal("1000"))
    signed_parent_c = sign_mandate(parent_c, key2)
    parent_c_trace = _trace(
        "fanout:parent", agent2, user2, parent_c.mandate_id, Decimal("300.00"), _stable_uuid("session:fanout:parent")
    )
    sibling_a = _mandate(
        "fanout:sibling_a", agent2, user2, key_id2, max_amount=Decimal("700"), parent_mandate_id=parent_c.mandate_id
    )
    signed_sibling_a = sign_mandate(sibling_a, key2)
    sibling_a_trace = _trace(
        "fanout:sibling_a", agent2, user2, sibling_a.mandate_id, Decimal("500.00"), FANOUT_SIBLING_A_ID
    )
    sibling_b = _mandate(
        "fanout:sibling_b", agent2, user2, key_id2, max_amount=Decimal("600"), parent_mandate_id=parent_c.mandate_id
    )
    signed_sibling_b = sign_mandate(sibling_b, key2)
    sibling_b_trace = _trace(
        "fanout:sibling_b", agent2, user2, sibling_b.mandate_id, Decimal("450.00"), FANOUT_SIBLING_B_ID
    )
    scenarios.append(
        DelegationScenario(
            key="sibling_fanout",
            label="Sibling fan-out",
            description=(
                "Two siblings, 700 and 600, each individually under the parent's 1000 ceiling but "
                "700+600 together exceeding it. The second sibling's own transaction (450) still "
                "fits its own 600 ceiling, so Layers 1-3 allow it -- only the chain view's sibling-cap "
                "check (Layer 2.5) sees the fan-out."
            ),
            parent_request=DecideRequest(trace=parent_c_trace, signed_mandate=signed_parent_c),
            child_requests=(
                DecideRequest(trace=sibling_a_trace, signed_mandate=signed_sibling_a),
                DecideRequest(trace=sibling_b_trace, signed_mandate=signed_sibling_b),
            ),
            focus_mandate_id=sibling_b.mandate_id,
        )
    )

    return tuple(scenarios)
