"""Mandate chaining / privilege-escalation attack generator.

Taxonomy definition (the only brief this module was given): an agent uses a
legitimate, small, properly-scoped mandate to bootstrap a larger,
unauthorized action, exploiting the *delegation* relationship between
mandates rather than forging or misusing a single one directly. Concretely,
`Mandate.parent_mandate_id` lets a mandate declare that it derives its
authority from an existing mandate (delegation / sub-mandate issuance) — a
real pattern in delegated-authorization systems, where an orchestrating
agent holding a modest grant mints narrower, scoped-down mandates for
sub-agents or for its own successive actions. Every variant below is a way
that derivation link can be abused to walk *away* from, rather than only
narrower than, the authority the parent actually granted. Each variant is
built so that the child mandate is legitimately signed (a real registered
key, produced by `mandate.signing.sign_mandate`) and every field except the
one dimension the variant is named for is copied unchanged from the parent
mandate or from a real donor session generated under it. That mirrors how
`generator/attacks/common.py` frames mandate replay and scope violation:
the exploit is that the *authorization* is wrong, not that the session looks
unusual, so nothing here diverges from ordinary session shape or pacing
unless the variant's own claim requires it (only `temporal_outlive` moves a
session's timing outside a mandate's natural window, and it does so because
that is the entire property being exercised).

Sub-variants:

* `budget_escalation` — a child mandate chained from a small parent
  declares a `scope.max_amount` many times the parent's own ceiling,
  and the session it accompanies spends an amount that would have been
  well over the parent's limit but sits inside the child's. This is the
  most direct reading of "bootstrap a larger action from a smaller one":
  nothing about the parent mandate bounds what a derived mandate may claim,
  so the chain is used purely to inflate the number, not to narrow it.
  Non-trivial to construct because the child must still be a fully valid,
  signed `Mandate` on its own — the escalation has to live entirely in the
  numeric relationship between two otherwise well-formed documents, not in
  any structural defect either one has by itself.

* `breadth_escalation` — the child mandate authorizes merchant/item
  categories the parent never covered (and, since the child is meant to
  look like an unremarkable small-ticket mandate, also drops any
  merchant-ID pin the parent carried, widening "one specific merchant" to
  "the whole category"). This is distinct from `budget_escalation` because
  the ceiling is left untouched — the escalation is entirely in *where* the
  authority reaches, which a detector that only compares amounts across a
  chain would miss entirely. Realistic delegated-authorization analogue:
  an OAuth token-exchange step that hands back a token scoped to resources
  the original grant never listed.

* `temporal_outlive` — the child's validity window extends past the
  parent's own `expires_at`, and the accompanying session is placed after
  the parent has lapsed but while the child is still nominally valid. The
  delegated authority outlives the authority it was derived from, which is
  a real bug class in cascaded token systems (a long-lived refresh token
  minted from a short-lived session token that itself has since been
  revoked). Constructing this requires holding every other field — amount,
  categories, agent — fixed to the parent's own values, so the *only*
  thing distinguishing the attack from a legitimate reuse is a timestamp
  relationship the schema does not itself enforce across the parent/child
  link.

* `unauthorized_subdelegation` — the child names a different `agent_id`
  than the parent mandate's holder: a second agent, with its own
  independently registered signing key, presents a mandate chained from
  the first agent's grant. The signature is completely genuine (signed by
  that second agent's real key), which is what separates this from
  `agent_impersonation` — nothing is forged or stolen here. The violation
  is that the *hop itself* — agent A's mandate begetting a mandate for
  agent B — was never something the user (`user_id`, held fixed across the
  chain) actually consented to; only the fact of a `parent_mandate_id`
  link makes the hand-off look sanctioned. This is the closest analogue to
  a "confused deputy" pattern in delegated authorization: B is not lying
  about who it is, it is exploiting that no one checks whether A was ever
  allowed to hand authority to B in the first place.

* `fanout_structuring` — a single modest parent mandate is used to mint
  several sibling child mandates (each individually unremarkable — every
  child's own ceiling is comfortably *below* the parent's) whose combined
  authorized value is a large multiple of anything the parent alone was
  ever sized for. No single child, inspected on its own, looks escalated;
  the escalation is only visible by summing everything chained from one
  parent. This is structurally different from the other four variants
  (which each distort one field of one child) and mirrors financial
  structuring/smurfing: many small, individually-plausible authorizations
  laundering one large one, using the chaining relationship as the thread
  that ties them together.

Defense-only: every mandate and key produced here comes from
`mandate.signing.keypair_from_seed_bytes` / the legitimate corpus's own
already-registered agent keys, and every session is only ever valid inside
this project's own synthetic key registry and mandate ledger. Nothing in
this module is a technique against a real payment system.

Reproducibility: every random draw — which parent, which sibling agent,
which extra category, every derived ID and nonce, every timestamp jitter —
comes from the single seeded `numpy.random.Generator` this module
constructs from the caller's `seed`. No `uuid.uuid4()`, no `random` module,
no wall-clock read; all timestamps are computed offsets from timestamps
already present in the donor mandate/session being extended.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from uuid import UUID

import numpy as np

from common.schema import AttackClass, SessionTrace
from generator.attacks.common import AttackWorld, GeneratedAttack, agent_by_id, label_attack, pick_weighted
from generator.config import CATEGORY_CONFIGS, DEFAULT_GENERATOR_CONFIG, CategoryConfig, digest_payload
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.legitimate import AgentProfile
from generator.rng import rng_nonce, rng_uuid
from mandate.schema import MIN_MANDATE_AMOUNT, Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, sign_mandate

logger = logging.getLogger(__name__)

# --- Shared construction constants ------------------------------------------

# Amounts are quantized to paise, matching the rest of the generator suite.
AMOUNT_QUANTIZE = Decimal("0.01")

# How soon after a parent mandate's own issuance a child chained from it is
# minted. Small and fixed so the chain reads as "derived shortly after",
# never as "derived so late the parent context is irrelevant."
CHAIN_ISSUE_DELAY = timedelta(minutes=5)

# A parent must have at least this much of its own lifetime remaining for a
# child (plus its accompanying session) to fit inside without a synthetic
# world's edge-case mandate producing an internally inconsistent chain.
MIN_PARENT_LIFETIME = timedelta(hours=1)

# --- budget_escalation --------------------------------------------------
BUDGET_ESCALATION_MULTIPLE = Decimal("6.0")
BUDGET_ESCALATION_SESSION_MULTIPLE = Decimal("3.0")

# --- breadth_escalation --------------------------------------------------
# Session amount as a fraction of the (unchanged) parent ceiling, so a
# breadth-escalation session is a plausible small purchase in the newly
# reachable category rather than also testing the amount dimension.
BREADTH_SESSION_AMOUNT_FRACTION = Decimal("0.5")

# --- temporal_outlive --------------------------------------------------
TEMPORAL_OUTLIVE_EXTRA = timedelta(days=14)
TEMPORAL_OUTLIVE_SESSION_LAG = timedelta(hours=6)

# --- fanout_structuring --------------------------------------------------
FANOUT_GROUP_SIZE = 4
MIN_FANOUT_GROUP_SIZE = 2
# Each sibling's own ceiling, as a fraction of the parent's — deliberately
# below 1.0 so no single child looks escalated on its own.
FANOUT_CHILD_AMOUNT_FRACTION = Decimal("0.75")
FANOUT_SESSION_AMOUNT_FRACTION = Decimal("0.9")
FANOUT_SIBLING_STAGGER = timedelta(minutes=3)

VARIANT_BUDGET_ESCALATION = "budget_escalation"
VARIANT_BREADTH_ESCALATION = "breadth_escalation"
VARIANT_TEMPORAL_OUTLIVE = "temporal_outlive"
VARIANT_UNAUTHORIZED_SUBDELEGATION = "unauthorized_subdelegation"
VARIANT_FANOUT_STRUCTURING = "fanout_structuring"

_VARIANT_WEIGHTS: dict[str, float] = {
    VARIANT_BUDGET_ESCALATION: 1.0,
    VARIANT_BREADTH_ESCALATION: 1.0,
    VARIANT_TEMPORAL_OUTLIVE: 1.0,
    VARIANT_UNAUTHORIZED_SUBDELEGATION: 1.0,
    VARIANT_FANOUT_STRUCTURING: 1.0,
}

_FULL_CATEGORY_BY_NAME: dict[str, CategoryConfig] = {c.name: c for c in CATEGORY_CONFIGS}

_EVENT_GAP_BOUNDS = (
    DEFAULT_GENERATOR_CONFIG.min_event_gap_seconds,
    DEFAULT_GENERATOR_CONFIG.max_event_gap_seconds,
)


@dataclass(frozen=True)
class _ParentCandidate:
    """A legitimate mandate eligible to serve as a chaining attack's root.

    Attributes:
        signed: The parent mandate, exactly as issued in the legitimate
            corpus.
        agent: The agent profile that holds the parent mandate.
        donor: A real legitimate session that presented the parent mandate,
            supplying a scope-consistent merchant/category/item template.
    """

    signed: SignedMandate
    agent: AgentProfile
    donor: SessionTrace


def _quantize(amount: Decimal) -> Decimal:
    """Rounds an amount to the nearest paisa.

    Args:
        amount: The amount to quantize.

    Returns:
        `amount` rounded half-up to two decimal places.
    """
    return amount.quantize(AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP)


def _eligible_parents(world: AttackWorld) -> list[_ParentCandidate]:
    """Finds legitimate mandates with enough donor material to chain from.

    Args:
        world: The indexed legitimate corpus.

    Returns:
        Eligible parent candidates, in a deterministic (mandate-ID-sorted)
        order.
    """
    candidates: list[_ParentCandidate] = []
    for mandate_id in sorted(world.output.signed_mandates, key=str):
        signed = world.output.signed_mandates[mandate_id]
        sessions = world.session_by_mandate.get(mandate_id)
        if not sessions:
            continue
        lifetime = signed.mandate.expires_at - signed.mandate.issued_at
        if lifetime <= MIN_PARENT_LIFETIME:
            continue
        try:
            agent = agent_by_id(world, signed.mandate.agent_id)
        except KeyError:
            continue
        donor = min(sessions, key=lambda session: (session.started_at, str(session.session_id)))
        candidates.append(_ParentCandidate(signed=signed, agent=agent, donor=donor))
    return candidates


def _breadth_eligible(candidates: list[_ParentCandidate]) -> list[_ParentCandidate]:
    """Narrows candidates to parents that leave at least one category unclaimed.

    Args:
        candidates: The general eligible-parent pool.

    Returns:
        Candidates whose `allowed_merchant_categories` is a strict subset of
        the full category universe, so a breadth-escalation child has a
        genuinely new category to reach into.
    """
    full = frozenset(_FULL_CATEGORY_BY_NAME)
    return [c for c in candidates if c.signed.mandate.scope.allowed_merchant_categories < full]


def _choose(rng: np.random.Generator, items: list[_ParentCandidate]) -> _ParentCandidate:
    """Deterministically draws one candidate from a list via the seeded RNG.

    Args:
        rng: Seeded random generator.
        items: Non-empty candidate pool.

    Returns:
        The chosen candidate.
    """
    index = int(rng.integers(len(items)))
    return items[index]


def _params_digest() -> str:
    """Hashes this module's tunable constants into a stable identifier.

    Returns:
        A hex SHA-256 digest, populating
        `LabeledSession.generator_params_digest` for every attack this
        module produces.
    """
    payload: dict[str, object] = {
        "chaining_attack_constants": {
            "budget_escalation_multiple": str(BUDGET_ESCALATION_MULTIPLE),
            "budget_escalation_session_multiple": str(BUDGET_ESCALATION_SESSION_MULTIPLE),
            "breadth_session_amount_fraction": str(BREADTH_SESSION_AMOUNT_FRACTION),
            "temporal_outlive_extra_days": TEMPORAL_OUTLIVE_EXTRA.days,
            "temporal_outlive_session_lag_seconds": TEMPORAL_OUTLIVE_SESSION_LAG.total_seconds(),
            "fanout_group_size": FANOUT_GROUP_SIZE,
            "fanout_child_amount_fraction": str(FANOUT_CHILD_AMOUNT_FRACTION),
            "fanout_session_amount_fraction": str(FANOUT_SESSION_AMOUNT_FRACTION),
            "fanout_sibling_stagger_seconds": FANOUT_SIBLING_STAGGER.total_seconds(),
            "chain_issue_delay_seconds": CHAIN_ISSUE_DELAY.total_seconds(),
            "min_parent_lifetime_seconds": MIN_PARENT_LIFETIME.total_seconds(),
        }
    }
    return digest_payload(payload)


def _sign_child(
    rng: np.random.Generator,
    signer: AgentProfile,
    parent: SignedMandate,
    agent_id: str,
    user_id: str,
    issued_at: datetime,
    expires_at: datetime,
    scope: MandateScope,
) -> SignedMandate:
    """Builds and signs a mandate chained from a parent via `parent_mandate_id`.

    Args:
        rng: Seeded random generator, source of the child's ID and nonce.
        signer: The agent whose key actually produces the signature. This
            may be the parent's own holder (self-issued escalation) or a
            different registered agent (`unauthorized_subdelegation`); the
            signature is genuine either way.
        parent: The legitimate mandate this child declares as its parent.
        agent_id: `agent_id` to stamp on the child mandate.
        user_id: `user_id` to stamp on the child mandate.
        issued_at: Issuance timestamp for the child.
        expires_at: Expiry timestamp for the child.
        scope: The (possibly escalated) scope to attach.

    Returns:
        The signed child mandate.
    """
    mandate = Mandate(
        mandate_id=rng_uuid(rng),
        agent_id=agent_id,
        user_id=user_id,
        parent_mandate_id=parent.mandate.mandate_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=rng_nonce(rng),
        scope=scope,
        signer_key_id=key_id_for_public_key(signer.private_key.public_key()),
    )
    return sign_mandate(mandate, signer.private_key)


def _build_session(
    rng: np.random.Generator,
    agent_id: str,
    user_id: str,
    mandate_id: UUID,
    merchant_id: str,
    merchant_category: str,
    item_category: str,
    amount: Decimal,
    currency: str,
    started_at: datetime,
) -> SessionTrace:
    """Builds a session trace with an ordinary legitimate-looking event flow.

    Args:
        rng: Seeded random generator, source of the session ID and
            inter-event jitter.
        agent_id: Agent presenting the session.
        user_id: Principal the session claims to act for.
        mandate_id: The (child, escalated) mandate presented.
        merchant_id: Merchant the session transacts with.
        merchant_category: Merchant category code.
        item_category: Item category purchased.
        amount: Transaction amount.
        currency: ISO 4217 currency code.
        started_at: Timestamp of the session's first event.

    Returns:
        The constructed session trace. Event composition and pacing follow
        `LEGITIMATE_LIFECYCLE` under the same jitter bounds the legitimate
        generator uses, so nothing about the session's shape signals the
        attack — only the mandate it presents does.
    """
    events, completed_at = build_events(rng, started_at, LEGITIMATE_LIFECYCLE, *_EVENT_GAP_BOUNDS)
    return SessionTrace(
        session_id=rng_uuid(rng),
        agent_id=agent_id,
        user_id=user_id,
        mandate_id=mandate_id,
        merchant_id=merchant_id,
        merchant_category=merchant_category,
        item_category=item_category,
        amount=_quantize(amount),
        currency=currency,
        events=events,
        started_at=started_at,
        completed_at=completed_at,
    )


def _build_budget_escalation(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
) -> list[GeneratedAttack]:
    """Builds one budget-escalation attack: a chained mandate with an inflated ceiling.

    Args:
        candidates: Eligible parent mandates to chain from.
        rng: Seeded random generator.
        seed: The caller's seed, carried into the label for reproducibility.
        params_digest: Digest of this module's tunable constants.

    Returns:
        A single-element list containing the generated attack.
    """
    parent_c = _choose(rng, candidates)
    parent = parent_c.signed
    scope = parent.mandate.scope

    issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY
    child_scope = MandateScope(
        max_amount=scope.max_amount * BUDGET_ESCALATION_MULTIPLE,
        currency=scope.currency,
        allowed_merchant_ids=scope.allowed_merchant_ids,
        allowed_merchant_categories=scope.allowed_merchant_categories,
        allowed_item_categories=scope.allowed_item_categories,
        valid_from=issued_at,
        valid_until=parent.mandate.expires_at,
        max_transaction_count=scope.max_transaction_count,
    )
    child = _sign_child(
        rng,
        signer=parent_c.agent,
        parent=parent,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        issued_at=issued_at,
        expires_at=parent.mandate.expires_at,
        scope=child_scope,
    )

    started_at = issued_at + CHAIN_ISSUE_DELAY
    session = _build_session(
        rng,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        mandate_id=child.mandate.mandate_id,
        merchant_id=parent_c.donor.merchant_id,
        merchant_category=parent_c.donor.merchant_category,
        item_category=parent_c.donor.item_category,
        amount=scope.max_amount * BUDGET_ESCALATION_SESSION_MULTIPLE,
        currency=parent_c.donor.currency,
        started_at=started_at,
    )
    labeled = label_attack(session, AttackClass.MANDATE_CHAINING, seed, params_digest)
    return [GeneratedAttack(labeled=labeled, signed_mandate=child, variant=VARIANT_BUDGET_ESCALATION)]


def _build_breadth_escalation(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
) -> list[GeneratedAttack]:
    """Builds one breadth-escalation attack: a chained mandate reaching new categories.

    Args:
        candidates: Parents with at least one category left unclaimed (see
            `_breadth_eligible`).
        rng: Seeded random generator.
        seed: The caller's seed.
        params_digest: Digest of this module's tunable constants.

    Returns:
        A single-element list containing the generated attack.

    Raises:
        ValueError: If `candidates` is empty.
    """
    if not candidates:
        raise ValueError("no breadth-eligible parents available")
    parent_c = _choose(rng, candidates)
    parent = parent_c.signed
    scope = parent.mandate.scope

    unclaimed = sorted(frozenset(_FULL_CATEGORY_BY_NAME) - scope.allowed_merchant_categories)
    extra_name = unclaimed[int(rng.integers(len(unclaimed)))]
    extra_category = _FULL_CATEGORY_BY_NAME[extra_name]
    extra_item = extra_category.item_categories[int(rng.integers(len(extra_category.item_categories)))]
    extra_merchant = extra_category.merchant_ids[int(rng.integers(len(extra_category.merchant_ids)))]

    issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY
    child_scope = MandateScope(
        max_amount=scope.max_amount,
        currency=scope.currency,
        # Widening one specific merchant into "the whole category" is part
        # of the breadth escalation: a mandate that reaches new categories
        # but still pins the old merchant ID would not actually be usable
        # in the new category at all.
        allowed_merchant_ids=None,
        allowed_merchant_categories=scope.allowed_merchant_categories | {extra_name},
        allowed_item_categories=scope.allowed_item_categories | {extra_item},
        valid_from=issued_at,
        valid_until=parent.mandate.expires_at,
        max_transaction_count=scope.max_transaction_count,
    )
    child = _sign_child(
        rng,
        signer=parent_c.agent,
        parent=parent,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        issued_at=issued_at,
        expires_at=parent.mandate.expires_at,
        scope=child_scope,
    )

    started_at = issued_at + CHAIN_ISSUE_DELAY
    session = _build_session(
        rng,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        mandate_id=child.mandate.mandate_id,
        merchant_id=extra_merchant,
        merchant_category=extra_name,
        item_category=extra_item,
        amount=scope.max_amount * BREADTH_SESSION_AMOUNT_FRACTION,
        currency=parent_c.donor.currency,
        started_at=started_at,
    )
    labeled = label_attack(session, AttackClass.MANDATE_CHAINING, seed, params_digest)
    return [GeneratedAttack(labeled=labeled, signed_mandate=child, variant=VARIANT_BREADTH_ESCALATION)]


def _build_temporal_outlive(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
) -> list[GeneratedAttack]:
    """Builds one temporal-outlive attack: authority surviving its own parent's expiry.

    Args:
        candidates: Eligible parent mandates to chain from.
        rng: Seeded random generator.
        seed: The caller's seed.
        params_digest: Digest of this module's tunable constants.

    Returns:
        A single-element list containing the generated attack.
    """
    parent_c = _choose(rng, candidates)
    parent = parent_c.signed
    scope = parent.mandate.scope

    issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY
    child_expires_at = parent.mandate.expires_at + TEMPORAL_OUTLIVE_EXTRA
    child_scope = MandateScope(
        max_amount=scope.max_amount,
        currency=scope.currency,
        allowed_merchant_ids=scope.allowed_merchant_ids,
        allowed_merchant_categories=scope.allowed_merchant_categories,
        allowed_item_categories=scope.allowed_item_categories,
        valid_from=issued_at,
        valid_until=child_expires_at,
        max_transaction_count=scope.max_transaction_count,
    )
    child = _sign_child(
        rng,
        signer=parent_c.agent,
        parent=parent,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        issued_at=issued_at,
        expires_at=child_expires_at,
        scope=child_scope,
    )

    # The defining property: the session happens after the parent's own
    # authority has lapsed, while the chained child is still nominally
    # valid.
    started_at = parent.mandate.expires_at + TEMPORAL_OUTLIVE_SESSION_LAG
    session = _build_session(
        rng,
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        mandate_id=child.mandate.mandate_id,
        merchant_id=parent_c.donor.merchant_id,
        merchant_category=parent_c.donor.merchant_category,
        item_category=parent_c.donor.item_category,
        amount=parent_c.donor.amount,
        currency=parent_c.donor.currency,
        started_at=started_at,
    )
    labeled = label_attack(session, AttackClass.MANDATE_CHAINING, seed, params_digest)
    return [GeneratedAttack(labeled=labeled, signed_mandate=child, variant=VARIANT_TEMPORAL_OUTLIVE)]


def _build_unauthorized_subdelegation(
    world: AttackWorld,
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
) -> list[GeneratedAttack]:
    """Builds one subdelegation attack: authority handed to an agent the user never named.

    Args:
        world: The indexed legitimate corpus, source of the sibling agent
            pool the parent's authority is diverted to.
        candidates: Eligible parent mandates to chain from.
        rng: Seeded random generator.
        seed: The caller's seed.
        params_digest: Digest of this module's tunable constants.

    Returns:
        A single-element list containing the generated attack.

    Raises:
        ValueError: If the world's agent pool has fewer than two agents.
    """
    parent_c = _choose(rng, candidates)
    parent = parent_c.signed
    scope = parent.mandate.scope

    others = sorted(
        (a for a in world.output.agents if a.agent_id != parent_c.agent.agent_id),
        key=lambda a: a.agent_id,
    )
    if not others:
        raise ValueError("world has no second agent available for subdelegation")
    delegate = others[int(rng.integers(len(others)))]

    issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY
    # Scope is held identical to the parent's on every other dimension: the
    # only thing this variant claims is that authority moved to a new
    # agent identity without the user ever sanctioning that hop.
    child_scope = MandateScope(
        max_amount=scope.max_amount,
        currency=scope.currency,
        allowed_merchant_ids=scope.allowed_merchant_ids,
        allowed_merchant_categories=scope.allowed_merchant_categories,
        allowed_item_categories=scope.allowed_item_categories,
        valid_from=issued_at,
        valid_until=parent.mandate.expires_at,
        max_transaction_count=scope.max_transaction_count,
    )
    child = _sign_child(
        rng,
        signer=delegate,
        parent=parent,
        agent_id=delegate.agent_id,
        # user_id is held fixed to the parent's own principal: the child
        # still claims to act for the same human, which is exactly what
        # makes the hand-off to a never-authorized agent invisible without
        # inspecting the chain.
        user_id=parent.mandate.user_id,
        issued_at=issued_at,
        expires_at=parent.mandate.expires_at,
        scope=child_scope,
    )

    started_at = issued_at + CHAIN_ISSUE_DELAY
    session = _build_session(
        rng,
        agent_id=delegate.agent_id,
        user_id=parent.mandate.user_id,
        mandate_id=child.mandate.mandate_id,
        merchant_id=parent_c.donor.merchant_id,
        merchant_category=parent_c.donor.merchant_category,
        item_category=parent_c.donor.item_category,
        amount=parent_c.donor.amount,
        currency=parent_c.donor.currency,
        started_at=started_at,
    )
    labeled = label_attack(session, AttackClass.MANDATE_CHAINING, seed, params_digest)
    return [
        GeneratedAttack(labeled=labeled, signed_mandate=child, variant=VARIANT_UNAUTHORIZED_SUBDELEGATION)
    ]


def _build_fanout_structuring(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
    group_size: int,
) -> list[GeneratedAttack]:
    """Builds a fan-out structuring group: several unremarkable siblings from one parent.

    Args:
        candidates: Eligible parent mandates to chain from.
        rng: Seeded random generator.
        seed: The caller's seed.
        params_digest: Digest of this module's tunable constants.
        group_size: Number of sibling children to mint, at least
            `MIN_FANOUT_GROUP_SIZE`.

    Returns:
        `group_size` generated attacks, each an individually unremarkable
        child mandate chained from the same parent; their combined ceilings
        sum to well over the parent's own.
    """
    parent_c = _choose(rng, candidates)
    parent = parent_c.signed
    scope = parent.mandate.scope
    child_amount = scope.max_amount * FANOUT_CHILD_AMOUNT_FRACTION
    child_amount = max(child_amount, MIN_MANDATE_AMOUNT)

    attacks: list[GeneratedAttack] = []
    for sibling_index in range(group_size):
        issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY + sibling_index * FANOUT_SIBLING_STAGGER
        child_scope = MandateScope(
            max_amount=child_amount,
            currency=scope.currency,
            allowed_merchant_ids=scope.allowed_merchant_ids,
            allowed_merchant_categories=scope.allowed_merchant_categories,
            allowed_item_categories=scope.allowed_item_categories,
            valid_from=issued_at,
            valid_until=parent.mandate.expires_at,
            max_transaction_count=1,
        )
        child = _sign_child(
            rng,
            signer=parent_c.agent,
            parent=parent,
            agent_id=parent.mandate.agent_id,
            user_id=parent.mandate.user_id,
            issued_at=issued_at,
            expires_at=parent.mandate.expires_at,
            scope=child_scope,
        )
        started_at = issued_at + CHAIN_ISSUE_DELAY
        session = _build_session(
            rng,
            agent_id=parent.mandate.agent_id,
            user_id=parent.mandate.user_id,
            mandate_id=child.mandate.mandate_id,
            merchant_id=parent_c.donor.merchant_id,
            merchant_category=parent_c.donor.merchant_category,
            item_category=parent_c.donor.item_category,
            amount=child_amount * FANOUT_SESSION_AMOUNT_FRACTION,
            currency=parent_c.donor.currency,
            started_at=started_at,
        )
        labeled = label_attack(session, AttackClass.MANDATE_CHAINING, seed, params_digest)
        attacks.append(
            GeneratedAttack(labeled=labeled, signed_mandate=child, variant=VARIANT_FANOUT_STRUCTURING)
        )
    return attacks


def generate_mandate_chaining_attacks(
    world: AttackWorld, n_attacks: int, seed: int
) -> tuple[GeneratedAttack, ...]:
    """Generates mandate-chaining / privilege-escalation attack sessions.

    Args:
        world: The indexed legitimate corpus to build attacks against.
        n_attacks: Total number of attack sessions to produce. Must be
            positive.
        seed: Seed for the internal random generator; the same
            `(world, n_attacks, seed)` triple always produces
            byte-identical output.

    Returns:
        Exactly `n_attacks` generated attacks, each labeled
        `AttackClass.MANDATE_CHAINING`, drawn across the five sub-variants
        documented in this module's docstring.

    Raises:
        ValueError: If `n_attacks` is not positive, or if `world` contains
            no legitimate mandate eligible to serve as a chaining root (no
            mandate with both a donor session and enough remaining lifetime
            to derive a child from).
    """
    if n_attacks <= 0:
        raise ValueError(f"n_attacks must be positive, got {n_attacks}")

    candidates = _eligible_parents(world)
    if not candidates:
        raise ValueError("world contains no mandate eligible to chain an attack from")
    breadth_candidates = _breadth_eligible(candidates)

    rng = np.random.default_rng(seed)
    params_digest = _params_digest()

    attacks: list[GeneratedAttack] = []
    while len(attacks) < n_attacks:
        remaining = n_attacks - len(attacks)
        weights = dict(_VARIANT_WEIGHTS)
        if remaining < MIN_FANOUT_GROUP_SIZE:
            weights.pop(VARIANT_FANOUT_STRUCTURING, None)
        if not breadth_candidates:
            weights.pop(VARIANT_BREADTH_ESCALATION, None)
        if len(world.output.agents) < 2:
            weights.pop(VARIANT_UNAUTHORIZED_SUBDELEGATION, None)
        variant = pick_weighted(rng, weights)

        if variant == VARIANT_BUDGET_ESCALATION:
            attacks.extend(_build_budget_escalation(candidates, rng, seed, params_digest))
        elif variant == VARIANT_BREADTH_ESCALATION:
            attacks.extend(_build_breadth_escalation(breadth_candidates, rng, seed, params_digest))
        elif variant == VARIANT_TEMPORAL_OUTLIVE:
            attacks.extend(_build_temporal_outlive(candidates, rng, seed, params_digest))
        elif variant == VARIANT_UNAUTHORIZED_SUBDELEGATION:
            attacks.extend(
                _build_unauthorized_subdelegation(world, candidates, rng, seed, params_digest)
            )
        else:
            group_size = min(FANOUT_GROUP_SIZE, remaining)
            attacks.extend(
                _build_fanout_structuring(candidates, rng, seed, params_digest, group_size)
            )

    logger.info(
        "mandate chaining: generated %d attacks from %d eligible parents", len(attacks), len(candidates)
    )
    return tuple(attacks)


__all__ = ["generate_mandate_chaining_attacks"]
