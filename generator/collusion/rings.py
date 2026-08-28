"""Plants coordinated multi-agent patterns: three malicious archetypes, two hard negatives.

Every session any of these builders produces is individually well-formed,
correctly signed, and inside its own mandate's scope -- Layers 1, 2, and 2.5
have no structural reason to object to any single one. The coordination is
the only thing wrong, and it is only visible across sessions and agents,
which is exactly the gap `collusion/` exists to close (and exactly why this
is a different class of coverage from Milestone C's disclosed single-session
gap or Milestone G's single-chain gap -- see `docs/adr/0006`).

Three malicious archetypes, isolating one signal each:

- `shared_fingerprint_ring` -- several "distinct" agent identities that share
  one device fingerprint, otherwise transacting with different merchants at
  uncorrelated times. Isolates the fingerprint signal alone.
- `cross_agent_structuring` -- several agents, each individually
  unremarkable, converging on one counterparty inside a tight coordinated
  window with amounts that sum to something no single session shows.
  Isolates the structuring signal alone.
- `counterparty_ring` -- several agents transacting with an overlapping set
  of shared counterparties inside a coordinated window, with no shared
  fingerprint and no single dominant counterparty. Isolates ring topology
  from either of the two signals above.

Two legitimate negative archetypes, deliberately hard, per this milestone's
own brief ("rings must not fire on ordinary shared-infrastructure cases...
a first-class false-positive class, not an afterthought"):

- `legitimate_household` -- a small group genuinely sharing one device (a
  family), but transacting independently: different merchants, uncorrelated
  timing.
- `legitimate_shared_gateway` -- a larger group of agents that all happen to
  use one popular merchant, but are otherwise completely independent:
  distinct fingerprints, timing spread widely and uncorrelated.

Reproducibility: every random draw for one archetype builder comes from a
single seeded `numpy.random.Generator`; `generate_ring_groups` derives one
independent stream per group from the caller's seed, mirroring
`generator/attacks/corpus.py`'s `SEED_OFFSET_*` pattern so groups do not make
correlated choices that would show up as spurious structure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from uuid import UUID

import numpy as np

from common.schema import SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint, generate_fingerprint
from generator.collusion.schema import (
    ARCHETYPE_COUNTERPARTY_RING,
    ARCHETYPE_CROSS_AGENT_STRUCTURING,
    ARCHETYPE_LEGITIMATE_HOUSEHOLD,
    ARCHETYPE_LEGITIMATE_SHARED_GATEWAY,
    ARCHETYPE_SHARED_FINGERPRINT_RING,
    GeneratedRingPiece,
    RingGroup,
    RingParticipant,
)
from generator.config import CATEGORY_CONFIGS, CURRENCY, GENERATION_ANCHOR, CategoryConfig
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.rng import rng_nonce, rng_uuid
from mandate.schema import Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate

logger = logging.getLogger(__name__)

# --- Shared construction constants ---------------------------------------
AMOUNT_QUANTIZE = Decimal("0.01")
ED25519_SEED_BYTES = 32
MIN_EVENT_GAP_SECONDS = 2
MAX_EVENT_GAP_SECONDS = 45
MANDATE_LIFETIME_DAYS = 14
MANDATE_TRANSACTION_COUNT = 3
# Mandate ceiling as a multiple of the session amount, matching
# generator/config.py's own MIN/MAX_SCOPE_CEILING_MULTIPLE range -- a ring
# participant's own mandate looks exactly as ordinary as any legitimate one.
MIN_SCOPE_CEILING_MULTIPLE = 1.15
MAX_SCOPE_CEILING_MULTIPLE = 3.0

# Sessions (outside a deliberately coordinated window) are spread uniformly
# across this many days ending at GENERATION_ANCHOR, matching
# generator/config.py's own horizon so ring sessions interleave naturally
# with the baseline legitimate population.
SESSION_HORIZON_DAYS = 30

# --- shared_fingerprint_ring -----------------------------------------------
# At collusion/scoring.py::FINGERPRINT_SIZE_SATURATION (6), so this
# archetype fully saturates the size-driven fingerprint signal -- a real
# distinguishing feature from legitimate_household's realistic family size,
# not merely a difference the generator asserts, see docs/adr/0006.
SHARED_FINGERPRINT_RING_SIZE = 6

# --- cross_agent_structuring -----------------------------------------------
STRUCTURING_RING_SIZE = 5
# Coordinated window every structuring participant's session falls inside.
# Comfortably inside collusion/graph.py's own DEFAULT_COORDINATION_WINDOW (15
# minutes), so this archetype's whole group reliably lands in one detected
# burst rather than depending on the two windows staying loosely aligned.
STRUCTURING_WINDOW = timedelta(minutes=8)
# Each participant's own amount, as a fraction of the category median --
# comfortably inside the ordinary single-session amount range (legitimate
# sessions clip as low as 0.15x and as high as 6x the median, per
# generator/config.py), so no individual session looks large on its own,
# while STRUCTURING_RING_SIZE participants summing this fraction each
# clears collusion/scoring.py's own structuring threshold -- calibrated
# against a real evaluation run, not picked by inspection, see docs/adr/0006.
STRUCTURING_PER_AGENT_AMOUNT_FRACTION = Decimal("0.8")

# --- counterparty_ring -----------------------------------------------------
COUNTERPARTY_RING_SIZE = 5
COUNTERPARTY_RING_MERCHANT_POOL_SIZE = 3
COUNTERPARTY_RING_MERCHANTS_PER_AGENT = 2
# Comfortably inside collusion/graph.py's own DEFAULT_COORDINATION_WINDOW,
# same reasoning as STRUCTURING_WINDOW above.
COUNTERPARTY_RING_WINDOW = timedelta(minutes=8)

# --- legitimate_household ---------------------------------------------------
HOUSEHOLD_SIZE = 3

# --- legitimate_shared_gateway ----------------------------------------------
SHARED_GATEWAY_SIZE = 20

_CATEGORY_BY_NAME: dict[str, CategoryConfig] = {c.name: c for c in CATEGORY_CONFIGS}


def _quantize(amount: Decimal) -> Decimal:
    """Rounds an amount to the nearest paisa.

    Args:
        amount: The amount to quantize.

    Returns:
        `amount` rounded half-up to two decimal places.
    """
    return amount.quantize(AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP)


def _build_participant(rng: np.random.Generator, label: str) -> RingParticipant:
    """Builds one genuinely distinct, independently keyed agent identity.

    Args:
        rng: Seeded random generator.
        label: A corpus-unique label, embedded in the agent and user IDs.

    Returns:
        The new participant.
    """
    private_key, _ = keypair_from_seed_bytes(rng.bytes(ED25519_SEED_BYTES))
    return RingParticipant(
        agent_id=f"ring-agent-{label}", private_key=private_key, user_id=f"ring-user-{label}"
    )


def _issue_mandate(
    rng: np.random.Generator,
    participant: RingParticipant,
    category: CategoryConfig,
    issued_at: datetime,
    amount: Decimal,
    merchant_id: str | None,
) -> SignedMandate:
    """Issues and signs an ordinary, correctly scoped mandate for one participant.

    Args:
        rng: Seeded random generator.
        participant: The agent this mandate authorizes.
        category: The merchant category the mandate is scoped to.
        issued_at: When the mandate is signed.
        amount: The transaction amount the mandate must cover; the ceiling
            is set to a multiple of this, matching the legitimate
            generator's own convention of never sitting at the exact edge.
        merchant_id: If given, the mandate is pinned to this one merchant.
            None means "any merchant within the category."

    Returns:
        The signed mandate.
    """
    ceiling_multiple = rng.uniform(MIN_SCOPE_CEILING_MULTIPLE, MAX_SCOPE_CEILING_MULTIPLE)
    max_amount = _quantize(amount * Decimal(str(ceiling_multiple)))
    valid_until = issued_at + timedelta(days=MANDATE_LIFETIME_DAYS)
    scope = MandateScope(
        max_amount=max_amount,
        currency=CURRENCY,
        allowed_merchant_ids=frozenset({merchant_id}) if merchant_id is not None else None,
        allowed_merchant_categories=frozenset({category.name}),
        allowed_item_categories=frozenset(category.item_categories),
        valid_from=issued_at,
        valid_until=valid_until,
        max_transaction_count=MANDATE_TRANSACTION_COUNT,
    )
    key_id = key_id_for_public_key(participant.private_key.public_key())
    mandate = Mandate(
        mandate_id=rng_uuid(rng),
        agent_id=participant.agent_id,
        user_id=participant.user_id,
        parent_mandate_id=None,
        issued_at=issued_at,
        expires_at=valid_until,
        nonce=rng_nonce(rng),
        scope=scope,
        signer_key_id=key_id,
    )
    return sign_mandate(mandate, participant.private_key)


def _build_session(
    rng: np.random.Generator,
    participant: RingParticipant,
    mandate: SignedMandate,
    merchant_id: str,
    merchant_category: str,
    item_category: str,
    amount: Decimal,
    started_at: datetime,
) -> SessionTrace:
    """Builds a session with an ordinary legitimate-looking event flow.

    Args:
        rng: Seeded random generator.
        participant: The agent presenting the session.
        mandate: The mandate this session presents.
        merchant_id: Merchant the session transacts with.
        merchant_category: Merchant category code.
        item_category: Item category purchased.
        amount: Transaction amount.
        started_at: Timestamp of the session's first event.

    Returns:
        The constructed session trace.
    """
    events, completed_at = build_events(
        rng, started_at, LEGITIMATE_LIFECYCLE, MIN_EVENT_GAP_SECONDS, MAX_EVENT_GAP_SECONDS
    )
    return SessionTrace(
        session_id=rng_uuid(rng),
        agent_id=participant.agent_id,
        user_id=participant.user_id,
        mandate_id=mandate.mandate.mandate_id,
        merchant_id=merchant_id,
        merchant_category=merchant_category,
        item_category=item_category,
        amount=_quantize(amount),
        currency=CURRENCY,
        events=events,
        started_at=started_at,
        completed_at=completed_at,
    )


@dataclass(frozen=True)
class _SessionSpec:
    """Everything needed to build one participant's session and mandate."""

    participant: RingParticipant
    category: CategoryConfig
    merchant_id: str
    item_category: str
    amount: Decimal
    started_at: datetime
    fingerprint: DeviceFingerprint


def _realize(rng: np.random.Generator, group: RingGroup, specs: tuple[_SessionSpec, ...]) -> GeneratedRingPiece:
    """Turns a list of session specs into signed mandates, sessions, and fingerprints.

    Args:
        rng: Seeded random generator.
        group: The ground-truth label for this piece.
        specs: One spec per session to build.

    Returns:
        The realized piece.
    """
    participants = tuple({spec.participant.agent_id: spec.participant for spec in specs}.values())
    sessions: list[SessionTrace] = []
    signed_mandates: dict[UUID, SignedMandate] = {}
    fingerprints: dict[UUID, DeviceFingerprint] = {}
    for spec in specs:
        mandate = _issue_mandate(
            rng, spec.participant, spec.category, spec.started_at, spec.amount, spec.merchant_id
        )
        session = _build_session(
            rng, spec.participant, mandate, spec.merchant_id, spec.category.name,
            spec.item_category, spec.amount, spec.started_at,
        )
        sessions.append(session)
        signed_mandates[session.session_id] = mandate
        fingerprints[session.session_id] = spec.fingerprint
    return GeneratedRingPiece(
        group=group, participants=participants, sessions=tuple(sessions),
        signed_mandates=signed_mandates, fingerprints=fingerprints,
    )


def _random_offset(rng: np.random.Generator, horizon_days: int) -> timedelta:
    """Draws a uniformly random offset within a horizon ending at the anchor.

    Args:
        rng: Seeded random generator.
        horizon_days: Width of the horizon, in days.

    Returns:
        A random timedelta before `GENERATION_ANCHOR`.
    """
    seconds = float(rng.uniform(0, horizon_days * 24 * 3600))
    return timedelta(seconds=seconds)


def build_shared_fingerprint_ring(rng: np.random.Generator, group_id: str) -> GeneratedRingPiece:
    """Plants several distinct agents sharing one device fingerprint.

    Args:
        rng: Seeded random generator.
        group_id: Unique identifier for this group.

    Returns:
        The generated piece, `is_ring=True`.
    """
    shared_fp = generate_fingerprint(rng)
    categories = list(CATEGORY_CONFIGS)
    specs = []
    for i in range(SHARED_FINGERPRINT_RING_SIZE):
        participant = _build_participant(rng, f"{group_id}-{i}")
        category = categories[int(rng.integers(len(categories)))]
        merchant_id = str(rng.choice(np.array(category.merchant_ids)))
        item_category = str(rng.choice(np.array(category.item_categories)))
        median = float(category.amount_median)
        amount = Decimal(str(round(float(rng.lognormal(np.log(median), category.amount_sigma)), 2)))
        started_at = GENERATION_ANCHOR - _random_offset(rng, SESSION_HORIZON_DAYS)
        specs.append(
            _SessionSpec(participant, category, merchant_id, item_category, amount, started_at, shared_fp)
        )
    group = RingGroup(
        group_id=group_id, archetype=ARCHETYPE_SHARED_FINGERPRINT_RING, is_ring=True,
        agent_ids=frozenset(spec.participant.agent_id for spec in specs),
    )
    return _realize(rng, group, tuple(specs))


def build_cross_agent_structuring(rng: np.random.Generator, group_id: str) -> GeneratedRingPiece:
    """Plants several agents converging small amounts on one counterparty in a tight window.

    Args:
        rng: Seeded random generator.
        group_id: Unique identifier for this group.

    Returns:
        The generated piece, `is_ring=True`.
    """
    category = CATEGORY_CONFIGS[int(rng.integers(len(CATEGORY_CONFIGS)))]
    merchant_id = str(rng.choice(np.array(category.merchant_ids)))
    item_category = str(rng.choice(np.array(category.item_categories)))
    window_start = GENERATION_ANCHOR - _random_offset(rng, SESSION_HORIZON_DAYS)

    specs = []
    for i in range(STRUCTURING_RING_SIZE):
        participant = _build_participant(rng, f"{group_id}-{i}")
        amount = Decimal(str(category.amount_median)) * STRUCTURING_PER_AGENT_AMOUNT_FRACTION
        offset_seconds = float(rng.uniform(0, STRUCTURING_WINDOW.total_seconds()))
        started_at = window_start + timedelta(seconds=offset_seconds)
        fingerprint = generate_fingerprint(rng)  # each participant has its own distinct device
        specs.append(
            _SessionSpec(participant, category, merchant_id, item_category, amount, started_at, fingerprint)
        )
    group = RingGroup(
        group_id=group_id, archetype=ARCHETYPE_CROSS_AGENT_STRUCTURING, is_ring=True,
        agent_ids=frozenset(spec.participant.agent_id for spec in specs),
    )
    return _realize(rng, group, tuple(specs))


def build_counterparty_ring(rng: np.random.Generator, group_id: str) -> GeneratedRingPiece:
    """Plants several agents transacting with an overlapping set of merchants in a coordinated window.

    Args:
        rng: Seeded random generator.
        group_id: Unique identifier for this group.

    Returns:
        The generated piece, `is_ring=True`.
    """
    category = CATEGORY_CONFIGS[int(rng.integers(len(CATEGORY_CONFIGS)))]
    pool_size = min(COUNTERPARTY_RING_MERCHANT_POOL_SIZE, len(category.merchant_ids))
    merchant_pool = list(
        rng.choice(np.array(category.merchant_ids), size=pool_size, replace=False)
    )
    window_start = GENERATION_ANCHOR - _random_offset(rng, SESSION_HORIZON_DAYS)

    specs = []
    for i in range(COUNTERPARTY_RING_SIZE):
        participant = _build_participant(rng, f"{group_id}-{i}")
        n_merchants = min(COUNTERPARTY_RING_MERCHANTS_PER_AGENT, len(merchant_pool))
        agent_merchants = rng.choice(np.array(merchant_pool), size=n_merchants, replace=False)
        fingerprint = generate_fingerprint(rng)
        for merchant_id in agent_merchants:
            item_category = str(rng.choice(np.array(category.item_categories)))
            median = float(category.amount_median)
            amount = Decimal(str(round(float(rng.lognormal(np.log(median), category.amount_sigma)), 2)))
            offset_seconds = float(rng.uniform(0, COUNTERPARTY_RING_WINDOW.total_seconds()))
            started_at = window_start + timedelta(seconds=offset_seconds)
            specs.append(
                _SessionSpec(
                    participant, category, str(merchant_id), item_category, amount, started_at, fingerprint
                )
            )
    group = RingGroup(
        group_id=group_id, archetype=ARCHETYPE_COUNTERPARTY_RING, is_ring=True,
        agent_ids=frozenset(spec.participant.agent_id for spec in specs),
    )
    return _realize(rng, group, tuple(specs))


def build_legitimate_household(rng: np.random.Generator, group_id: str) -> GeneratedRingPiece:
    """Plants a small group genuinely sharing one device, transacting independently otherwise.

    A hard negative: fingerprint sharing alone, with no coordination in
    timing or counterparty, must not be indistinguishable from
    `build_shared_fingerprint_ring`'s planted ring.

    Args:
        rng: Seeded random generator.
        group_id: Unique identifier for this group.

    Returns:
        The generated piece, `is_ring=False`.
    """
    shared_fp = generate_fingerprint(rng)
    categories = list(CATEGORY_CONFIGS)
    specs = []
    for i in range(HOUSEHOLD_SIZE):
        participant = _build_participant(rng, f"{group_id}-{i}")
        category = categories[int(rng.integers(len(categories)))]
        merchant_id = str(rng.choice(np.array(category.merchant_ids)))
        item_category = str(rng.choice(np.array(category.item_categories)))
        median = float(category.amount_median)
        amount = Decimal(str(round(float(rng.lognormal(np.log(median), category.amount_sigma)), 2)))
        # Independent, uncorrelated timing across the full horizon -- no
        # coordination beyond the one shared device.
        started_at = GENERATION_ANCHOR - _random_offset(rng, SESSION_HORIZON_DAYS)
        specs.append(
            _SessionSpec(participant, category, merchant_id, item_category, amount, started_at, shared_fp)
        )
    group = RingGroup(
        group_id=group_id, archetype=ARCHETYPE_LEGITIMATE_HOUSEHOLD, is_ring=False,
        agent_ids=frozenset(spec.participant.agent_id for spec in specs),
    )
    return _realize(rng, group, tuple(specs))


def build_legitimate_shared_gateway(rng: np.random.Generator, group_id: str) -> GeneratedRingPiece:
    """Plants many agents that happen to use one popular merchant, otherwise fully independent.

    A hard negative: many unrelated agents sharing one popular counterparty
    -- exactly what a real merchant gateway's genuine traffic looks like --
    must not be indistinguishable from `build_counterparty_ring`'s planted
    ring.

    Args:
        rng: Seeded random generator.
        group_id: Unique identifier for this group.

    Returns:
        The generated piece, `is_ring=False`.
    """
    category = CATEGORY_CONFIGS[int(rng.integers(len(CATEGORY_CONFIGS)))]
    popular_merchant = str(rng.choice(np.array(category.merchant_ids)))

    specs = []
    for i in range(SHARED_GATEWAY_SIZE):
        participant = _build_participant(rng, f"{group_id}-{i}")
        item_category = str(rng.choice(np.array(category.item_categories)))
        median = float(category.amount_median)
        amount = Decimal(str(round(float(rng.lognormal(np.log(median), category.amount_sigma)), 2)))
        # Independent, uncorrelated timing across the full horizon -- no
        # coordinated window, no shared device.
        started_at = GENERATION_ANCHOR - _random_offset(rng, SESSION_HORIZON_DAYS)
        fingerprint = generate_fingerprint(rng)
        specs.append(
            _SessionSpec(
                participant, category, popular_merchant, item_category, amount, started_at, fingerprint
            )
        )
    group = RingGroup(
        group_id=group_id, archetype=ARCHETYPE_LEGITIMATE_SHARED_GATEWAY, is_ring=False,
        agent_ids=frozenset(spec.participant.agent_id for spec in specs),
    )
    return _realize(rng, group, tuple(specs))


# Weighted so the resulting corpus contains meaningfully more malicious
# rings than of any single negative-case type, while still generating a
# real population of both.
_MALICIOUS_BUILDERS = (
    build_shared_fingerprint_ring, build_cross_agent_structuring, build_counterparty_ring,
)


def generate_ring_groups(
    n_malicious_rings: int,
    n_household_negatives: int,
    n_shared_gateway_negatives: int,
    seed: int,
) -> tuple[GeneratedRingPiece, ...]:
    """Generates every planted ring and hard-negative group for one corpus.

    Malicious archetypes are drawn round-robin across the three builders, so
    a given `n_malicious_rings` is split as evenly as possible across
    `shared_fingerprint_ring`, `cross_agent_structuring`, and
    `counterparty_ring`.

    Args:
        n_malicious_rings: Total planted malicious rings to generate. Must
            be non-negative.
        n_household_negatives: Legitimate household groups to generate.
            Must be non-negative.
        n_shared_gateway_negatives: Legitimate shared-gateway groups to
            generate. Must be non-negative.
        seed: Seed for the internal random generator; the same inputs
            always produce byte-identical output.

    Returns:
        Every generated piece, malicious rings first, then household
        negatives, then shared-gateway negatives.

    Raises:
        ValueError: If any count is negative.
    """
    for label, value in (
        ("n_malicious_rings", n_malicious_rings),
        ("n_household_negatives", n_household_negatives),
        ("n_shared_gateway_negatives", n_shared_gateway_negatives),
    ):
        if value < 0:
            raise ValueError(f"{label} must be non-negative, got {value}")

    pieces: list[GeneratedRingPiece] = []
    for i in range(n_malicious_rings):
        builder = _MALICIOUS_BUILDERS[i % len(_MALICIOUS_BUILDERS)]
        group_rng = np.random.default_rng(seed + i)
        pieces.append(builder(group_rng, f"ring-{i:03d}"))

    household_offset = n_malicious_rings
    for i in range(n_household_negatives):
        group_rng = np.random.default_rng(seed + household_offset + i)
        pieces.append(build_legitimate_household(group_rng, f"household-{i:03d}"))

    gateway_offset = household_offset + n_household_negatives
    for i in range(n_shared_gateway_negatives):
        group_rng = np.random.default_rng(seed + gateway_offset + i)
        pieces.append(build_legitimate_shared_gateway(group_rng, f"gateway-{i:03d}"))

    logger.info(
        "collusion generator: %d malicious rings, %d household negatives, %d shared-gateway negatives",
        n_malicious_rings, n_household_negatives, n_shared_gateway_negatives,
    )
    return tuple(pieces)
