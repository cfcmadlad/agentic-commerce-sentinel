"""Generates synthetic legitimate agent-initiated commerce sessions.

Each session is a full, internally consistent flow: an agent, acting for a
fixed home user, is issued (or reuses) a signed mandate scoped to one
merchant category, then completes a session whose amount, merchant, and
item category all fall inside that mandate's scope. This is deliberately
the easy case — Day 2 builds the attack generator that violates exactly the
invariants this module is careful to uphold, which is what makes those
violations meaningful signal rather than arbitrary noise.

Reproducibility: every random draw goes through a single
`numpy.random.Generator` seeded from the caller's `seed` argument, so a
given `(n_sessions, seed)` pair always produces byte-identical output.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from uuid import UUID

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.schema import AttackClass, EventType, LabeledSession, SessionEvent, SessionTrace
from generator.config import (
    AGENT_POOL_SIZE,
    CATEGORY_CONFIGS,
    CURRENCY,
    GENERATION_ANCHOR,
    MAX_AMOUNT_MULTIPLE_OF_MEDIAN,
    MAX_EVENT_GAP_SECONDS,
    MAX_MANDATE_LIFETIME_DAYS,
    MAX_MANDATE_TRANSACTION_COUNT,
    MAX_SCOPE_CEILING_MULTIPLE,
    MIN_AMOUNT_MULTIPLE_OF_MEDIAN,
    MIN_EVENT_GAP_SECONDS,
    MIN_MANDATE_LIFETIME_DAYS,
    MIN_MANDATE_TRANSACTION_COUNT,
    MIN_RECURRING_REUSE_GAP_HOURS,
    MIN_SCOPE_CEILING_MULTIPLE,
    RECURRING_MANDATE_PROBABILITY,
    SESSION_HORIZON_DAYS,
    CategoryConfig,
    compute_params_digest,
)
from mandate.schema import Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate
from mandate.verification import AgentKeyRegistry, MandateLedger

AMOUNT_QUANTIZE = Decimal("0.01")


def _rng_uuid(rng: np.random.Generator) -> UUID:
    """Derives a UUID from the seeded generator, instead of `uuid.uuid4`.

    `uuid.uuid4()` reads OS entropy directly and is not reproducible across
    runs regardless of any seed passed elsewhere; every ID in this
    generator must route through `rng` for a given seed to reproduce
    byte-identical output.

    Args:
        rng: Seeded random generator.

    Returns:
        A UUID built from 16 random bytes drawn from `rng`.
    """
    return UUID(bytes=rng.bytes(16))


def _rng_nonce(rng: np.random.Generator) -> str:
    """Derives a mandate nonce from the seeded generator.

    Args:
        rng: Seeded random generator.

    Returns:
        A 32-character hex string, well above `Mandate.nonce`'s minimum
        length.
    """
    return rng.bytes(16).hex()


@dataclass(frozen=True)
class AgentProfile:
    """A simulated agent identity and its behavioral tendencies.

    Attributes:
        agent_id: Unique agent identifier.
        private_key: The agent's Ed25519 signing key.
        home_user_id: The single human principal this agent acts for. Real
            agent deployments are scoped to one user's account, so sessions
            never mix users onto the same agent.
        preferred_categories: The merchant categories this agent transacts
            in, weighted toward realism (a grocery-shopping agent does not
            also buy electronics).
    """

    agent_id: str
    private_key: Ed25519PrivateKey
    home_user_id: str
    preferred_categories: tuple[CategoryConfig, ...]


@dataclass(frozen=True)
class LegitimateGeneratorOutput:
    """Everything produced by one generator run.

    Attributes:
        labeled_sessions: The generated sessions, each labeled LEGITIMATE.
        signed_mandates: Every mandate issued during generation, keyed by
            mandate_id, including mandates reused across multiple sessions.
        registry: Public keys for every simulated agent, pre-populated so a
            downstream verifier can check these sessions without a separate
            setup step.
        ledger: Usage counts reflecting every mandate redemption recorded
            during generation, so a downstream verifier sees accurate
            remaining budgets rather than starting from a ledger that
            thinks every mandate is unused.
        seed: The seed used, for reproducibility.
        params_digest: Digest of the generator parameters in effect.
    """

    labeled_sessions: tuple[LabeledSession, ...]
    signed_mandates: dict[UUID, SignedMandate]
    registry: AgentKeyRegistry
    ledger: MandateLedger
    seed: int
    params_digest: str


def _build_agent_pool(
    rng: np.random.Generator, registry: AgentKeyRegistry
) -> list[AgentProfile]:
    """Builds the simulated agent population and registers their keys.

    Args:
        rng: Seeded random generator.
        registry: Registry to populate with each agent's public key.

    Returns:
        The agent pool.
    """
    agents: list[AgentProfile] = []
    for i in range(AGENT_POOL_SIZE):
        private_key, public_key = keypair_from_seed_bytes(rng.bytes(32))
        agent_id = f"agent-{i:03d}"
        key_id = key_id_for_public_key(public_key)
        registry.register(agent_id, key_id, public_key)

        num_categories = 1 if rng.random() < 0.7 else 2
        chosen = rng.choice(
            np.array(CATEGORY_CONFIGS, dtype=object), size=num_categories, replace=False
        )
        agents.append(
            AgentProfile(
                agent_id=agent_id,
                private_key=private_key,
                home_user_id=f"user-{rng.integers(0, 500):04d}",
                preferred_categories=tuple(chosen),
            )
        )
    return agents


def _pick_category(rng: np.random.Generator, agent: AgentProfile) -> CategoryConfig:
    """Chooses a merchant category for the agent's next session.

    Args:
        rng: Seeded random generator.
        agent: The agent generating a session.

    Returns:
        One of the agent's preferred categories, weighted by each
        category's configured GMV weight.
    """
    weights = np.array([c.gmv_weight for c in agent.preferred_categories])
    weights = weights / weights.sum()
    index = rng.choice(len(agent.preferred_categories), p=weights)
    return agent.preferred_categories[index]


def _sample_amount(
    rng: np.random.Generator, category: CategoryConfig, ceiling: Decimal | None = None
) -> Decimal:
    """Samples a transaction amount for a category from a clipped log-normal.

    Args:
        rng: Seeded random generator.
        category: The category whose median/sigma parameterize the draw.
        ceiling: If given, the amount is capped at 98% of this value, so a
            reused mandate's remaining budget is respected with margin.

    Returns:
        A positive amount, quantized to 2 decimal places.
    """
    median = float(category.amount_median)
    draw = rng.lognormal(mean=np.log(median), sigma=category.amount_sigma)
    low = median * MIN_AMOUNT_MULTIPLE_OF_MEDIAN
    high = median * MAX_AMOUNT_MULTIPLE_OF_MEDIAN
    draw = float(np.clip(draw, low, high))
    if ceiling is not None:
        draw = min(draw, float(ceiling) * 0.98)
    return Decimal(str(round(draw, 2))).quantize(AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP)


def _issue_mandate(
    rng: np.random.Generator, agent: AgentProfile, category: CategoryConfig, issued_at: datetime
) -> tuple[SignedMandate, Decimal]:
    """Issues and signs a fresh mandate scoped to one category for an agent.

    Args:
        rng: Seeded random generator.
        agent: The agent this mandate authorizes.
        category: The merchant category the mandate is scoped to.
        issued_at: When the mandate is signed.

    Returns:
        A tuple of (signed mandate, the transaction amount this mandate's
        ceiling was derived from). The caller must use this exact amount
        for the session that triggers issuance, rather than sampling a new
        one — a second independent draw is not guaranteed to fall under the
        ceiling computed from the first.
    """
    base_amount = _sample_amount(rng, category)
    ceiling_multiple = rng.uniform(MIN_SCOPE_CEILING_MULTIPLE, MAX_SCOPE_CEILING_MULTIPLE)
    max_amount = (base_amount * Decimal(str(ceiling_multiple))).quantize(
        AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP
    )

    lifetime_days = int(rng.integers(MIN_MANDATE_LIFETIME_DAYS, MAX_MANDATE_LIFETIME_DAYS + 1))
    valid_until = issued_at + timedelta(days=lifetime_days)

    restrict_to_single_merchant = rng.random() < 0.5
    allowed_merchant_ids = (
        frozenset({str(rng.choice(np.array(category.merchant_ids)))})
        if restrict_to_single_merchant
        else None
    )

    scope = MandateScope(
        max_amount=max_amount,
        currency=CURRENCY,
        allowed_merchant_ids=allowed_merchant_ids,
        allowed_merchant_categories=frozenset({category.name}),
        allowed_item_categories=frozenset(category.item_categories),
        valid_from=issued_at,
        valid_until=valid_until,
        max_transaction_count=int(
            rng.integers(MIN_MANDATE_TRANSACTION_COUNT, MAX_MANDATE_TRANSACTION_COUNT + 1)
        ),
    )
    key_id = key_id_for_public_key(agent.private_key.public_key())
    mandate = Mandate(
        mandate_id=_rng_uuid(rng),
        agent_id=agent.agent_id,
        user_id=agent.home_user_id,
        parent_mandate_id=None,
        issued_at=issued_at,
        expires_at=valid_until,
        nonce=_rng_nonce(rng),
        scope=scope,
        signer_key_id=key_id,
    )
    return sign_mandate(mandate, agent.private_key), base_amount


def _build_events(
    rng: np.random.Generator, started_at: datetime
) -> tuple[list[SessionEvent], datetime]:
    """Builds a realistic event sequence for one session.

    Args:
        rng: Seeded random generator.
        started_at: Timestamp of the first event.

    Returns:
        A tuple of (events, completed_at), where completed_at is the
        timestamp of the final event.
    """
    stages = (
        EventType.INTENT_CAPTURED,
        EventType.MANDATE_PRESENTED,
        EventType.CATALOG_BROWSE,
        EventType.CART_BUILD,
        EventType.PAYMENT_ATTEMPT,
        EventType.PAYMENT_RESULT,
    )
    events: list[SessionEvent] = []
    current = started_at
    for stage in stages:
        events.append(SessionEvent(event_type=stage, timestamp=current, payload={}))
        gap = rng.integers(MIN_EVENT_GAP_SECONDS, MAX_EVENT_GAP_SECONDS + 1)
        current = current + timedelta(seconds=int(gap))
    return events, events[-1].timestamp


def generate_legitimate_sessions(n_sessions: int, seed: int) -> LegitimateGeneratorOutput:
    """Generates a batch of synthetic legitimate agent sessions.

    Args:
        n_sessions: Number of sessions to generate. Must be positive.
        seed: Seed for the internal random generator; the same seed always
            produces the same output.

    Returns:
        The generated sessions plus the supporting registry and ledger
        state needed to verify them.

    Raises:
        ValueError: If `n_sessions` is not positive.
    """
    if n_sessions <= 0:
        raise ValueError(f"n_sessions must be positive, got {n_sessions}")

    rng = np.random.default_rng(seed)
    registry = AgentKeyRegistry()
    ledger = MandateLedger()
    signed_mandates: dict[UUID, SignedMandate] = {}
    standing_mandate: dict[str, SignedMandate] = {}
    last_used_at: dict[UUID, datetime] = {}

    agents = _build_agent_pool(rng, registry)
    horizon_start = GENERATION_ANCHOR - timedelta(days=SESSION_HORIZON_DAYS)

    labeled_sessions: list[LabeledSession] = []
    params_digest = compute_params_digest()

    for _ in range(n_sessions):
        agent = agents[rng.integers(0, len(agents))]
        offset_seconds = rng.uniform(0, SESSION_HORIZON_DAYS * 24 * 3600)
        session_start = horizon_start + timedelta(seconds=float(offset_seconds))

        existing = standing_mandate.get(agent.agent_id)
        can_reuse = (
            existing is not None
            and rng.random() < RECURRING_MANDATE_PROBABILITY
            and ledger.usage_count(existing.mandate.mandate_id)
            < existing.mandate.scope.max_transaction_count
            and session_start
            >= last_used_at.get(existing.mandate.mandate_id, existing.mandate.issued_at)
            + timedelta(hours=MIN_RECURRING_REUSE_GAP_HOURS)
            and session_start <= existing.mandate.scope.valid_until
        )

        if can_reuse and existing is not None:
            signed = existing
            category_name = next(iter(signed.mandate.scope.allowed_merchant_categories))
            category = next(c for c in CATEGORY_CONFIGS if c.name == category_name)
            amount = _sample_amount(rng, category, ceiling=signed.mandate.scope.max_amount)
        else:
            category = _pick_category(rng, agent)
            signed, amount = _issue_mandate(rng, agent, category, issued_at=session_start)
            signed_mandates[signed.mandate.mandate_id] = signed
            standing_mandate[agent.agent_id] = signed

        scope = signed.mandate.scope
        merchant_id = (
            str(rng.choice(np.array(list(scope.allowed_merchant_ids))))
            if scope.allowed_merchant_ids
            else str(rng.choice(np.array(category.merchant_ids)))
        )
        item_category = str(rng.choice(np.array(category.item_categories)))

        events, completed_at = _build_events(rng, session_start)
        trace = SessionTrace(
            session_id=_rng_uuid(rng),
            agent_id=agent.agent_id,
            user_id=agent.home_user_id,
            mandate_id=signed.mandate.mandate_id,
            merchant_id=merchant_id,
            merchant_category=category.name,
            item_category=item_category,
            amount=amount,
            currency=CURRENCY,
            events=events,
            started_at=session_start,
            completed_at=completed_at,
        )
        labeled_sessions.append(
            LabeledSession(
                trace=trace,
                attack_class=AttackClass.LEGITIMATE,
                is_attack=False,
                generator_seed=seed,
                generator_params_digest=params_digest,
            )
        )
        ledger.record_usage(signed.mandate.mandate_id)
        last_used_at[signed.mandate.mandate_id] = session_start
        signed_mandates.setdefault(signed.mandate.mandate_id, signed)

    labeled_sessions.sort(key=lambda s: s.trace.started_at)

    return LegitimateGeneratorOutput(
        labeled_sessions=tuple(labeled_sessions),
        signed_mandates=signed_mandates,
        registry=registry,
        ledger=ledger,
        seed=seed,
        params_digest=params_digest,
    )