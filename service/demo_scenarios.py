"""Fixed demo scenarios for the frontend's live demo view.

Builds five real `SessionTrace`/`SignedMandate` request bodies -- the same
five narrative scenarios the frontend's mock fixtures
(`frontend/src/mock/sessions.ts`) originally hard-coded -- as genuine inputs
a live `/sessions/decide` call can be made from. Each mandate is signed with
the exact key material `service/state.py` registers for its demo agents at
startup, so the signatures verify against a real running service.

Three of the five scenarios (`LEGITIMATE_ALLOWED_ID`, `MANDATE_REPLAY_ID`,
`BEHAVIORAL_ONLY_ID`) depend on causal history -- an agent or mandate's own
prior use -- to produce a meaningful behavioral score, the same way this
project's evaluation corpus does. `service/demo_seed.py` replays each
scenario's warm-up sessions through the real `/sessions/decide` code path
once, at service startup, so a live request for the "final" session below
reflects genuine accumulated state rather than a first-ever call with
nothing behind it.

The five fixed session IDs below match `frontend/src/mock/sessions.ts`'s
`MOCK_SESSION_LABELS` keys exactly, so the frontend's existing session
picker needs no changes -- only its data source does.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import NAMESPACE_URL, UUID, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.schema import EventType, SessionEvent, SessionTrace
from mandate.schema import Mandate, MandateScope, SignedMandate
from mandate.signing import canonical_bytes, key_id_for_public_key, keypair_from_seed_bytes, sign_mandate
from service.schemas import DecideRequest

# An arbitrary fixed instant, not wall-clock time: `service.main.decide`
# resolves mandate validity against `trace.started_at`, not the real current
# time, so these scenarios stay valid on every run regardless of when the
# service actually starts.
ANCHOR = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)

LEGITIMATE_ALLOWED_ID = UUID("11111111-1111-4111-8111-111111111111")
SCOPE_VIOLATION_ID = UUID("22222222-2222-4222-8222-222222222222")
MANDATE_REPLAY_ID = UUID("33333333-3333-4333-8333-333333333333")
BEHAVIORAL_ONLY_ID = UUID("44444444-4444-4444-8444-444444444444")
FORGED_SIGNATURE_ID = UUID("55555555-5555-4555-8555-555555555555")


def _stable_uuid(label: str) -> UUID:
    """Derives a fixed, deterministic UUID from a label string.

    `build_demo_scenarios` is called both by `service/demo_seed.py` (at
    server startup, to seed warm-up history) and by
    `run_live_demo_export.py` (to export the frontend's static request
    payloads) -- two entirely separate Python processes. A mandate or
    session ID drawn from `uuid4()` would differ between those two calls,
    so the exported "final" request's `mandate_id` would never match what
    the running service actually has history for. Deriving every ID from a
    fixed label instead guarantees both call sites agree byte-for-byte.

    Args:
        label: A unique, stable label for the identity being derived.

    Returns:
        A UUID5 derived deterministically from the label.
    """
    return uuid5(NAMESPACE_URL, f"sentinel-demo-scenario:{label}")


def _demo_keypair(index: int) -> tuple[Ed25519PrivateKey, str, str]:
    """Re-derives one of `service.state`'s own demo agent keypairs.

    Matches `service/state.py::_register_demo_agents` exactly, so a mandate
    signed here verifies against the keys a real running service registers
    at startup.

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


def _events(start: datetime, gaps: tuple[float, ...], include_browse: bool) -> list[SessionEvent]:
    """Builds a standard event lifecycle with the given inter-stage gaps.

    Args:
        start: Timestamp of the first event.
        gaps: Seconds between each consecutive pair of stages. Length must
            be exactly one less than the number of stages `include_browse`
            selects.
        include_browse: Whether to include the catalog-browse stage.

    Returns:
        The ordered event list.

    Raises:
        ValueError: If `gaps` does not match the stage count.
    """
    stages = [EventType.INTENT_CAPTURED, EventType.MANDATE_PRESENTED]
    if include_browse:
        stages.append(EventType.CATALOG_BROWSE)
    stages += [EventType.CART_BUILD, EventType.PAYMENT_ATTEMPT, EventType.PAYMENT_RESULT]
    if len(gaps) != len(stages) - 1:
        raise ValueError(f"expected {len(stages) - 1} gaps for {len(stages)} stages, got {len(gaps)}")
    timestamps = [start]
    for gap in gaps:
        timestamps.append(timestamps[-1] + timedelta(seconds=gap))
    return [
        SessionEvent(event_type=stage, timestamp=ts) for stage, ts in zip(stages, timestamps, strict=True)
    ]


def _mandate(
    label: str,
    agent_id: str,
    user_id: str,
    key_id: str,
    max_amount: Decimal,
    merchant_categories: frozenset[str],
    item_categories: frozenset[str],
    valid_from: datetime,
    valid_until: datetime,
    max_transaction_count: int = 10,
) -> Mandate:
    """Builds one mandate with the given scope, issued at the window's start.

    Args:
        label: A stable label identifying this mandate, so its ID and nonce
            are deterministic across processes (see `_stable_uuid`).
        agent_id: The agent this mandate authorizes.
        user_id: The human principal granting authority.
        key_id: Fingerprint of the key expected to sign this mandate.
        max_amount: Per-transaction spending ceiling.
        merchant_categories: Allowed merchant category codes.
        item_categories: Allowed item categories.
        valid_from: Start of the authorized transaction time window.
        valid_until: End of the authorized transaction time window.
        max_transaction_count: Maximum number of redemptions allowed.
    """
    return Mandate(
        mandate_id=_stable_uuid(f"mandate:{label}"),
        agent_id=agent_id,
        user_id=user_id,
        issued_at=valid_from,
        expires_at=valid_until + timedelta(hours=1),
        nonce=_stable_uuid(f"nonce:{label}").hex,
        scope=MandateScope(
            max_amount=max_amount,
            currency="INR",
            allowed_merchant_categories=merchant_categories,
            allowed_item_categories=item_categories,
            valid_from=valid_from,
            valid_until=valid_until,
            max_transaction_count=max_transaction_count,
        ),
        signer_key_id=key_id,
    )


def _trace(
    label: str,
    agent_id: str,
    user_id: str,
    mandate_id: UUID | None,
    merchant_id: str,
    merchant_category: str,
    item_category: str,
    amount: Decimal,
    events: list[SessionEvent],
    session_id: UUID | None = None,
) -> SessionTrace:
    """Builds one session trace from a prebuilt event list.

    Args:
        label: A stable label identifying this session, used to derive its
            ID deterministically when `session_id` is not given explicitly
            (see `_stable_uuid`).
        agent_id: The agent that ran this session.
        user_id: The human principal on whose behalf the agent acted.
        mandate_id: The mandate presented, or None for no mandate.
        merchant_id: The specific merchant the transaction was placed with.
        merchant_category: The merchant's category code.
        item_category: The purchased item's category.
        amount: The transaction amount.
        events: The session's chronologically ordered lifecycle events.
        session_id: Fixed session ID to use instead of one derived from
            `label`, for the sessions the frontend's picker keys by ID.
    """
    return SessionTrace(
        session_id=session_id or _stable_uuid(f"session:{label}"),
        agent_id=agent_id,
        user_id=user_id,
        mandate_id=mandate_id,
        merchant_id=merchant_id,
        merchant_category=merchant_category,
        item_category=item_category,
        amount=amount,
        currency="INR",
        events=events,
        started_at=events[0].timestamp,
        completed_at=events[-1].timestamp,
    )


@dataclass(frozen=True)
class DemoScenario:
    """One named demo scenario: optional warm-up history, then the session shown.

    Attributes:
        label: Human-readable label, matching the frontend's session picker.
        warmup: Prior sessions to replay first, so the final session's
            causal features reflect genuine accumulated history. Empty for
            scenarios the deterministic rules layers catch regardless of
            history.
        final: The request whose response the demo actually displays.
    """

    label: str
    warmup: tuple[DecideRequest, ...]
    final: DecideRequest


def build_demo_scenarios() -> dict[UUID, DemoScenario]:
    """Builds the five fixed demo scenarios, keyed by their fixed session ID.

    Returns:
        Every scenario, in the same order and under the same session IDs as
        `frontend/src/mock/sessions.ts`'s `MOCK_SESSION_LABELS`.
    """
    scenarios: dict[UUID, DemoScenario] = {}

    # Scenario 1: legitimate, allowed. An established agent's ordinary session.
    key0, agent0, key_id0 = _demo_keypair(0)
    user0 = "demo-user-00"
    m1 = _mandate(
        "legitimate:m1",
        agent0, user0, key_id0,
        max_amount=Decimal("3000"),
        merchant_categories=frozenset({"grocery"}),
        item_categories=frozenset({"packaged_food", "produce"}),
        valid_from=ANCHOR - timedelta(hours=2),
        valid_until=ANCHOR + timedelta(hours=6),
    )
    signed_m1 = sign_mandate(m1, key0)
    warmup1 = []
    for i, gap_offset in enumerate([-90, -70, -50, -30]):
        start = ANCHOR + timedelta(minutes=gap_offset)
        events = _events(start, (18.0, 24.0, 21.0, 26.0, 15.0), include_browse=True)
        trace = _trace(
            f"legitimate:warmup:{i}",
            agent0, user0, m1.mandate_id, "freshmart-01", "grocery", "packaged_food",
            Decimal("450.00") + Decimal(i * 75), events,
        )
        warmup1.append(DecideRequest(trace=trace, signed_mandate=signed_m1))
    final1_events = _events(ANCHOR, (19.0, 22.0, 20.0, 24.0, 16.0), include_browse=True)
    final1_trace = _trace(
        "legitimate:final",
        agent0, user0, m1.mandate_id, "freshmart-01", "grocery", "packaged_food",
        Decimal("620.00"), final1_events, session_id=LEGITIMATE_ALLOWED_ID,
    )
    scenarios[LEGITIMATE_ALLOWED_ID] = DemoScenario(
        label="Legitimate — allowed",
        warmup=tuple(warmup1),
        final=DecideRequest(trace=final1_trace, signed_mandate=signed_m1),
    )

    # Scenario 2: scope violation, amount over ceiling. Same established
    # agent, a fresh mandate with a low ceiling the agent then exceeds.
    m2 = _mandate(
        "scope_violation:m2",
        agent0, user0, key_id0,
        max_amount=Decimal("2000"),
        merchant_categories=frozenset({"grocery"}),
        item_categories=frozenset({"packaged_food", "produce"}),
        valid_from=ANCHOR - timedelta(hours=1),
        valid_until=ANCHOR + timedelta(hours=6),
    )
    signed_m2 = sign_mandate(m2, key0)
    final2_events = _events(
        ANCHOR + timedelta(minutes=5), (17.0, 25.0, 19.0, 23.0, 18.0), include_browse=True
    )
    final2_trace = _trace(
        "scope_violation:final",
        agent0, user0, m2.mandate_id, "freshmart-01", "grocery", "packaged_food",
        Decimal("2450.00"), final2_events, session_id=SCOPE_VIOLATION_ID,
    )
    scenarios[SCOPE_VIOLATION_ID] = DemoScenario(
        label="Scope violation — amount over ceiling (Layer 2)",
        warmup=(),
        final=DecideRequest(trace=final2_trace, signed_mandate=signed_m2),
    )

    # Scenario 3: mandate replay, rapid reuse. One legitimate prior use, then
    # the same mandate presented again far sooner than the legitimate reuse
    # distribution would ever produce.
    key1, agent1, key_id1 = _demo_keypair(1)
    user1 = "demo-user-01"
    m3 = _mandate(
        "mandate_replay:m3",
        agent1, user1, key_id1,
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"phones", "laptops"}),
        valid_from=ANCHOR - timedelta(hours=1),
        valid_until=ANCHOR + timedelta(hours=6),
    )
    signed_m3 = sign_mandate(m3, key1)
    prior3_events = _events(ANCHOR, (20.0, 30.0, 22.0, 28.0, 17.0), include_browse=True)
    prior3_trace = _trace(
        "mandate_replay:prior",
        agent1, user1, m3.mandate_id, "techbazaar-04", "electronics", "phones",
        Decimal("1800.00"), prior3_events,
    )
    final3_start = prior3_events[-1].timestamp + timedelta(seconds=75)
    final3_events = _events(final3_start, (3.0, 4.0, 3.0, 4.0), include_browse=False)
    final3_trace = _trace(
        "mandate_replay:final",
        agent1, user1, m3.mandate_id, "techbazaar-04", "electronics", "phones",
        Decimal("1800.00"), final3_events, session_id=MANDATE_REPLAY_ID,
    )
    scenarios[MANDATE_REPLAY_ID] = DemoScenario(
        label="Mandate replay — rapid reuse (Layer 3, rules-invisible)",
        warmup=(DecideRequest(trace=prior3_trace, signed_mandate=signed_m3),),
        final=DecideRequest(trace=final3_trace, signed_mandate=signed_m3),
    )

    # Scenario 4: agent impersonation, behavioral only. An agent's own
    # established, jittery cadence, then one session paced like a script.
    key2, agent2, key_id2 = _demo_keypair(2)
    user2 = "demo-user-02"
    m4 = _mandate(
        "behavioral_only:m4",
        agent2, user2, key_id2,
        max_amount=Decimal("4000"),
        merchant_categories=frozenset({"fashion"}),
        item_categories=frozenset({"apparel"}),
        valid_from=ANCHOR - timedelta(hours=2),
        valid_until=ANCHOR + timedelta(hours=6),
    )
    signed_m4 = sign_mandate(m4, key2)
    warmup4 = []
    for i, (gap_offset, gaps) in enumerate(
        [
            (-80, (14.0, 35.0, 19.0, 41.0, 12.0)),
            (-60, (22.0, 18.0, 33.0, 16.0, 27.0)),
            (-40, (16.0, 29.0, 24.0, 20.0, 31.0)),
        ]
    ):
        start = ANCHOR + timedelta(minutes=gap_offset)
        events = _events(start, gaps, include_browse=True)
        trace = _trace(
            f"behavioral_only:warmup:{i}",
            agent2, user2, m4.mandate_id, "trendline-09", "fashion", "apparel",
            Decimal("900.00") + Decimal(i * 60), events,
        )
        warmup4.append(DecideRequest(trace=trace, signed_mandate=signed_m4))
    final4_events = _events(ANCHOR, (2.5, 2.5, 2.0, 2.5), include_browse=False)
    final4_trace = _trace(
        "behavioral_only:final",
        agent2, user2, m4.mandate_id, "trendline-09", "fashion", "apparel",
        Decimal("950.00"), final4_events, session_id=BEHAVIORAL_ONLY_ID,
    )
    scenarios[BEHAVIORAL_ONLY_ID] = DemoScenario(
        label="Agent impersonation — behavioral only (Layer 3, rules-invisible)",
        warmup=tuple(warmup4),
        final=DecideRequest(trace=final4_trace, signed_mandate=signed_m4),
    )

    # Scenario 5: agent impersonation, forged signature. A mandate that
    # claims demo-agent-00's key but is actually signed by an unregistered
    # key -- caught by Layer 1 before Layer 3 is ever consulted.
    forged_key, _ = keypair_from_seed_bytes(hashlib.sha256(b"unregistered-forger").digest())
    m5 = Mandate(
        mandate_id=_stable_uuid("mandate:forged_signature:m5"),
        agent_id=agent0,
        user_id=user0,
        issued_at=ANCHOR - timedelta(minutes=30),
        expires_at=ANCHOR + timedelta(hours=6),
        nonce=_stable_uuid("nonce:forged_signature:m5").hex,
        scope=MandateScope(
            max_amount=Decimal("3000"),
            currency="INR",
            allowed_merchant_categories=frozenset({"grocery"}),
            allowed_item_categories=frozenset({"packaged_food"}),
            valid_from=ANCHOR - timedelta(minutes=30),
            valid_until=ANCHOR + timedelta(hours=6),
            max_transaction_count=10,
        ),
        signer_key_id=key_id0,
    )
    forged_signature_bytes = forged_key.sign(canonical_bytes(m5))
    signed_m5 = SignedMandate(mandate=m5, signature=base64.b64encode(forged_signature_bytes).decode("ascii"))
    final5_events = _events(ANCHOR + timedelta(minutes=2), (18.0, 24.0, 20.0, 22.0, 17.0), include_browse=True)
    final5_trace = _trace(
        "forged_signature:final",
        agent0, user0, m5.mandate_id, "freshmart-01", "grocery", "packaged_food",
        Decimal("500.00"), final5_events, session_id=FORGED_SIGNATURE_ID,
    )
    scenarios[FORGED_SIGNATURE_ID] = DemoScenario(
        label="Agent impersonation — forged signature (Layer 1)",
        warmup=(),
        final=DecideRequest(trace=final5_trace, signed_mandate=signed_m5),
    )

    return scenarios
