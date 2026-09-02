"""Legitimate delegation-chain traffic: real narrower children, never an attack.

Every mandate-chaining attack variant in `generator/attacks/chaining.py`
escalates a delegated mandate *wider* than its parent along exactly one
dimension. This module builds the mirror case containment must never fire
on: a delegated mandate that stays a genuine subset of its parent on every
dimension `containment/engine.py::_check_scope_subset` checks. Without this,
containment's own "zero false positives" claim measures nothing --
`generate_legitimate_delegation_sessions` is what makes it a real,
falsifiable measurement instead of a structural non-event (see
`docs/adr/0004-delegation-chain-containment.md`'s addendum).

Three shapes, chosen to exercise the two rules a narrower-but-imprecise
generator would most plausibly false-positive on:

* `narrower_with_allowlist` -- child keeps the parent's own explicit
  `allowed_merchant_ids` restriction (drawn from parents that have one), so
  the merchant-ID subset check sees `child <= parent` on a real,
  non-trivial set, not just `None <= None`.
* `narrower_no_allowlist` -- child leaves `allowed_merchant_ids` unset,
  drawn only from parents that *also* leave it unset, so the child is a
  genuine subset (unrestricted-within-category is not a widening when the
  parent was already unrestricted-within-category). This is the shape most
  likely to trip `_merchant_ids_subset`'s "child is None, parent is not"
  branch if that branch or its caller ever regresses -- but it must never
  actually reach that branch here, since these parents are pre-filtered to
  `allowed_merchant_ids is None`.
* `sibling_fanout` -- several children chained from one parent whose
  combined ceilings stay comfortably under the parent's own cap (unlike
  `chaining.py`'s `fanout_structuring`, which is sized to exceed it), to
  exercise `ContainmentGate`'s running sibling ledger under legitimate
  multi-child use.

Every session here is labeled `AttackClass.LEGITIMATE` (`is_attack=False`);
`generator.attacks.common.label_attack` refuses that label by design, so
labeling is done directly. Defense-only, same as every other generator in
this package: nothing here is a technique against a real payment system,
only synthetic traffic this project scores its own detector against.

Reproducibility: every random draw comes from the single seeded
`numpy.random.Generator` this module constructs from the caller's `seed`,
matching `chaining.py`'s own discipline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from uuid import UUID

import numpy as np

from common.schema import AttackClass, LabeledSession, SessionTrace
from generator.attacks.common import AttackWorld, agent_by_id, pick_weighted
from generator.config import DEFAULT_GENERATOR_CONFIG, digest_payload
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.legitimate import AgentProfile
from generator.rng import rng_nonce, rng_uuid
from mandate.schema import MIN_MANDATE_AMOUNT, Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, sign_mandate

logger = logging.getLogger(__name__)

AMOUNT_QUANTIZE = Decimal("0.01")

# Mirrors chaining.py's own CHAIN_ISSUE_DELAY / MIN_PARENT_LIFETIME choices --
# a legitimate delegation is minted shortly after its parent and needs the
# same minimum remaining lifetime to fit a child (plus session) inside.
CHAIN_ISSUE_DELAY = timedelta(minutes=5)
MIN_PARENT_LIFETIME = timedelta(hours=1)

# Child ceiling as a fraction of the parent's, comfortably narrower.
NARROWER_CHILD_AMOUNT_FRACTION = Decimal("0.4")
NARROWER_SESSION_AMOUNT_FRACTION = Decimal("0.8")

# Sibling group sizing: each child's ceiling times the group size stays
# under this fraction of the parent's cap, so the summed commitment never
# approaches the sibling-cap boundary by construction.
SIBLING_GROUP_SIZE = 3
SIBLING_CHILD_AMOUNT_FRACTION = Decimal("0.2")
SIBLING_SESSION_AMOUNT_FRACTION = Decimal("0.8")
SIBLING_STAGGER = timedelta(minutes=3)

_EVENT_GAP_BOUNDS = (
    DEFAULT_GENERATOR_CONFIG.min_event_gap_seconds,
    DEFAULT_GENERATOR_CONFIG.max_event_gap_seconds,
)

VARIANT_NARROWER_WITH_ALLOWLIST = "narrower_with_allowlist"
VARIANT_NARROWER_NO_ALLOWLIST = "narrower_no_allowlist"
VARIANT_SIBLING_FANOUT = "sibling_fanout"

_VARIANT_WEIGHTS: dict[str, float] = {
    VARIANT_NARROWER_WITH_ALLOWLIST: 1.0,
    VARIANT_NARROWER_NO_ALLOWLIST: 1.0,
    VARIANT_SIBLING_FANOUT: 1.0,
}


@dataclass(frozen=True)
class GeneratedLegitimateDelegation:
    """One synthetic, genuinely-in-bounds delegated mandate plus its session.

    Attributes:
        labeled: The session and its ground-truth label (always legitimate).
        signed_mandate: The signed child mandate this session presents.
        variant: Which of the three shapes above produced this session,
            carried the same way `GeneratedAttack.variant` is, for
            diagnostic breakdown -- never fed to feature extraction.
    """

    labeled: LabeledSession
    signed_mandate: SignedMandate
    variant: str


@dataclass(frozen=True)
class _ParentCandidate:
    """A legitimate mandate eligible to serve as a legitimate delegation's root."""

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


def _eligible_parents(world: AttackWorld, *, require_allowlist: bool | None) -> list[_ParentCandidate]:
    """Finds legitimate mandates with enough donor material to delegate from.

    Args:
        world: The indexed legitimate corpus.
        require_allowlist: If True, only parents with an explicit
            `allowed_merchant_ids` restriction. If False, only parents
            without one. If None, no filter on this dimension.

    Returns:
        Eligible parent candidates, in a deterministic (mandate-ID-sorted)
        order.
    """
    candidates: list[_ParentCandidate] = []
    for mandate_id in sorted(world.output.signed_mandates, key=str):
        signed = world.output.signed_mandates[mandate_id]
        scope = signed.mandate.scope
        if require_allowlist is True and scope.allowed_merchant_ids is None:
            continue
        if require_allowlist is False and scope.allowed_merchant_ids is not None:
            continue
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


def _choose_with_capacity(
    rng: np.random.Generator,
    items: list[_ParentCandidate],
    committed: dict[UUID, Decimal],
    fraction_needed: Decimal,
) -> _ParentCandidate | None:
    """Draws one candidate with at least `fraction_needed` of its own cap still uncommitted.

    Without this, two independently-drawn legitimate delegations can both
    pick the same parent (`_choose` draws with replacement from a finite
    eligible pool) and, individually well-scoped, still sum to more than
    that parent ever authorized -- which `ContainmentGate`'s real sibling
    ledger then correctly rejects. That is containment doing its job, not a
    false positive; the fix belongs here; keeping every legitimate-
    delegation session inside what its parent actually has left is what
    makes this generator produce traffic a synthetic-but-honest delegator
    would actually send. Expressed as a fraction of each candidate's own
    cap, not a fixed amount, since candidates have different ceilings and
    the amount this call will go on to request is itself a fraction of
    whichever parent gets chosen.

    Args:
        rng: Seeded random generator.
        items: Candidate pool to draw from.
        committed: Running per-parent commitment total from earlier draws
            in this same generation run, keyed by parent mandate ID.
        fraction_needed: The fraction of a candidate's own cap about to be
            committed against it.

    Returns:
        A candidate with enough remaining capacity, or `None` if every
        candidate in `items` is already too committed.
    """
    # A small fixed margin above the raw fraction, absorbing the half-paisa
    # `_quantize` (ROUND_HALF_UP) can add to the amount actually committed
    # -- without it, a candidate sitting exactly at the boundary this
    # unquantized comparison allows can still be pushed a hair over its
    # real cap once quantized, which containment then (correctly) rejects.
    margin = Decimal("1.00")
    eligible = [
        c for c in items
        if c.signed.mandate.scope.max_amount - committed.get(c.signed.mandate.mandate_id, Decimal("0"))
        >= fraction_needed * c.signed.mandate.scope.max_amount + margin
    ]
    if not eligible:
        return None
    return _choose(rng, eligible)


def _params_digest() -> str:
    """Hashes this module's tunable constants into a stable identifier.

    Returns:
        A hex SHA-256 digest, populating
        `LabeledSession.generator_params_digest` for every session this
        module produces.
    """
    payload: dict[str, object] = {
        "legitimate_delegation_constants": {
            "narrower_child_amount_fraction": str(NARROWER_CHILD_AMOUNT_FRACTION),
            "narrower_session_amount_fraction": str(NARROWER_SESSION_AMOUNT_FRACTION),
            "sibling_group_size": SIBLING_GROUP_SIZE,
            "sibling_child_amount_fraction": str(SIBLING_CHILD_AMOUNT_FRACTION),
            "sibling_session_amount_fraction": str(SIBLING_SESSION_AMOUNT_FRACTION),
            "sibling_stagger_seconds": SIBLING_STAGGER.total_seconds(),
            "chain_issue_delay_seconds": CHAIN_ISSUE_DELAY.total_seconds(),
            "min_parent_lifetime_seconds": MIN_PARENT_LIFETIME.total_seconds(),
        }
    }
    return digest_payload(payload)


def _sign_child(
    rng: np.random.Generator,
    signer: AgentProfile,
    parent: SignedMandate,
    expires_at: datetime,
    scope: MandateScope,
) -> SignedMandate:
    """Builds and signs a mandate chained from a parent via `parent_mandate_id`.

    Self-issued only (child `agent_id`/`user_id` match the parent's): this
    module tests scope narrowing, not the agent-identity dimension
    `unauthorized_subdelegation` already covers on the attack side.

    Args:
        rng: Seeded random generator, source of the child's ID and nonce.
        signer: The agent whose key signs the child (same as the parent's).
        parent: The legitimate mandate this child declares as its parent.
        expires_at: Expiry timestamp for the child.
        scope: The (narrowed) scope to attach.

    Returns:
        The signed child mandate.
    """
    mandate = Mandate(
        mandate_id=rng_uuid(rng),
        agent_id=parent.mandate.agent_id,
        user_id=parent.mandate.user_id,
        parent_mandate_id=parent.mandate.mandate_id,
        issued_at=scope.valid_from,
        expires_at=expires_at,
        nonce=rng_nonce(rng),
        scope=scope,
        signer_key_id=key_id_for_public_key(signer.private_key.public_key()),
    )
    return sign_mandate(mandate, signer.private_key)


def _build_session(
    rng: np.random.Generator,
    parent_c: _ParentCandidate,
    mandate_id: UUID,
    amount: Decimal,
    started_at: datetime,
) -> SessionTrace:
    """Builds a session trace with an ordinary legitimate event flow.

    Args:
        rng: Seeded random generator, source of the session ID and jitter.
        parent_c: The parent candidate this session's mandate is chained
            from -- supplies the donor merchant/category template.
        mandate_id: The (narrowed) child mandate ID presented.
        amount: Transaction amount.
        started_at: Timestamp of the session's first event.

    Returns:
        The constructed session trace.
    """
    events, completed_at = build_events(rng, started_at, LEGITIMATE_LIFECYCLE, *_EVENT_GAP_BOUNDS)
    return SessionTrace(
        session_id=rng_uuid(rng),
        agent_id=parent_c.signed.mandate.agent_id,
        user_id=parent_c.signed.mandate.user_id,
        mandate_id=mandate_id,
        merchant_id=parent_c.donor.merchant_id,
        merchant_category=parent_c.donor.merchant_category,
        item_category=parent_c.donor.item_category,
        amount=_quantize(amount),
        currency=parent_c.donor.currency,
        events=events,
        started_at=started_at,
        completed_at=completed_at,
    )


def _label(trace: SessionTrace, seed: int, params_digest: str) -> LabeledSession:
    """Wraps a trace with a ground-truth legitimate label.

    Args:
        trace: The generated session.
        seed: The generator seed that produced this session.
        params_digest: Digest of the generator parameters in effect.

    Returns:
        The labeled session, `is_attack=False`.
    """
    return LabeledSession(
        trace=trace,
        attack_class=AttackClass.LEGITIMATE,
        is_attack=False,
        generator_seed=seed,
        generator_params_digest=params_digest,
    )


def _build_narrower_child(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
    variant: str,
    committed: dict[UUID, Decimal],
) -> GeneratedLegitimateDelegation | None:
    """Builds one narrower-child legitimate delegation.

    Args:
        candidates: Eligible parent mandates to delegate from, already
            filtered by allowlist presence for the requested variant.
        rng: Seeded random generator.
        seed: The caller's seed, carried into the label.
        params_digest: Digest of this module's tunable constants.
        variant: `VARIANT_NARROWER_WITH_ALLOWLIST` or
            `VARIANT_NARROWER_NO_ALLOWLIST`.
        committed: Running per-parent commitment ledger, updated in place on
            success -- see `_choose_with_capacity`.

    Returns:
        The generated legitimate delegation, or `None` if every candidate
        is already too committed to take this delegation's share.
    """
    parent_c = _choose_with_capacity(rng, candidates, committed, NARROWER_CHILD_AMOUNT_FRACTION)
    if parent_c is None:
        return None
    parent = parent_c.signed
    scope = parent.mandate.scope

    issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY
    child_amount = max(
        _quantize(scope.max_amount * NARROWER_CHILD_AMOUNT_FRACTION), MIN_MANDATE_AMOUNT
    )
    committed[parent.mandate.mandate_id] = committed.get(parent.mandate.mandate_id, Decimal("0")) + child_amount
    child_scope = MandateScope(
        max_amount=child_amount,
        currency=scope.currency,
        allowed_merchant_ids=scope.allowed_merchant_ids,
        allowed_merchant_categories=scope.allowed_merchant_categories,
        allowed_item_categories=scope.allowed_item_categories,
        valid_from=issued_at,
        valid_until=parent.mandate.expires_at,
        max_transaction_count=scope.max_transaction_count,
    )
    child = _sign_child(
        rng, signer=parent_c.agent, parent=parent, expires_at=parent.mandate.expires_at, scope=child_scope
    )

    started_at = issued_at + CHAIN_ISSUE_DELAY
    session = _build_session(
        rng, parent_c, child.mandate.mandate_id, child_amount * NARROWER_SESSION_AMOUNT_FRACTION, started_at
    )
    labeled = _label(session, seed, params_digest)
    return GeneratedLegitimateDelegation(labeled=labeled, signed_mandate=child, variant=variant)


def _build_sibling_fanout(
    candidates: list[_ParentCandidate],
    rng: np.random.Generator,
    seed: int,
    params_digest: str,
    committed: dict[UUID, Decimal],
) -> list[GeneratedLegitimateDelegation] | None:
    """Builds a legitimate sibling group, combined ceiling well under the parent's cap.

    Args:
        candidates: Eligible parent mandates to delegate from.
        rng: Seeded random generator.
        seed: The caller's seed.
        params_digest: Digest of this module's tunable constants.
        committed: Running per-parent commitment ledger, updated in place on
            success -- see `_choose_with_capacity`.

    Returns:
        `SIBLING_GROUP_SIZE` generated legitimate delegations chained from
        the same parent, or `None` if every candidate is already too
        committed to take this whole group's combined share.
    """
    group_fraction = SIBLING_CHILD_AMOUNT_FRACTION * SIBLING_GROUP_SIZE
    parent_c = _choose_with_capacity(rng, candidates, committed, group_fraction)
    if parent_c is None:
        return None
    parent = parent_c.signed
    scope = parent.mandate.scope
    child_amount = max(
        _quantize(scope.max_amount * SIBLING_CHILD_AMOUNT_FRACTION), MIN_MANDATE_AMOUNT
    )
    committed[parent.mandate.mandate_id] = (
        committed.get(parent.mandate.mandate_id, Decimal("0")) + child_amount * SIBLING_GROUP_SIZE
    )

    results: list[GeneratedLegitimateDelegation] = []
    for sibling_index in range(SIBLING_GROUP_SIZE):
        issued_at = parent.mandate.issued_at + CHAIN_ISSUE_DELAY + sibling_index * SIBLING_STAGGER
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
            expires_at=parent.mandate.expires_at,
            scope=child_scope,
        )
        started_at = issued_at + CHAIN_ISSUE_DELAY
        session = _build_session(
            rng,
            parent_c,
            child.mandate.mandate_id,
            child_amount * SIBLING_SESSION_AMOUNT_FRACTION,
            started_at,
        )
        labeled = _label(session, seed, params_digest)
        results.append(
            GeneratedLegitimateDelegation(
                labeled=labeled, signed_mandate=child, variant=VARIANT_SIBLING_FANOUT
            )
        )
    return results


def generate_legitimate_delegation_sessions(
    world: AttackWorld, n_sessions: int, seed: int
) -> tuple[GeneratedLegitimateDelegation, ...]:
    """Generates legitimate, narrower-than-parent delegation sessions.

    Args:
        world: The indexed legitimate corpus to build delegations against.
        n_sessions: Target number of delegation sessions to produce (the
            sibling-fanout variant produces `SIBLING_GROUP_SIZE` per draw, so
            the realized count may exceed this by up to that group size).
            Must be positive.
        seed: Seed for the internal random generator; the same
            `(world, n_sessions, seed)` triple always produces
            byte-identical output.

    Returns:
        At least `n_sessions` generated legitimate delegations, each a real
        subset of its parent's scope on every dimension containment checks,
        labeled `AttackClass.LEGITIMATE`.

    Raises:
        ValueError: If `n_sessions` is not positive, or if `world` contains
            no legitimate mandate eligible to serve as a delegation root for
            one of the required variants.
    """
    if n_sessions <= 0:
        raise ValueError(f"n_sessions must be positive, got {n_sessions}")

    with_allowlist = _eligible_parents(world, require_allowlist=True)
    without_allowlist = _eligible_parents(world, require_allowlist=False)
    if not with_allowlist:
        raise ValueError("world contains no legitimate mandate with an explicit merchant allowlist")
    if not without_allowlist:
        raise ValueError("world contains no legitimate mandate without an explicit merchant allowlist")

    rng = np.random.default_rng(seed)
    params_digest = _params_digest()

    # Tracks how much of each parent's own cap earlier draws in this run
    # have already committed, so no combination of independently-drawn
    # legitimate delegations here ever asks a parent for more than it
    # actually has left -- see `_choose_with_capacity`.
    committed: dict[UUID, Decimal] = {}
    results: list[GeneratedLegitimateDelegation] = []
    consecutive_exhausted = 0
    max_consecutive_exhausted = max(len(with_allowlist), len(without_allowlist)) + 100
    while len(results) < n_sessions:
        variant = pick_weighted(rng, _VARIANT_WEIGHTS)
        if variant == VARIANT_NARROWER_WITH_ALLOWLIST:
            narrower = _build_narrower_child(with_allowlist, rng, seed, params_digest, variant, committed)
            produced: list[GeneratedLegitimateDelegation] = [narrower] if narrower is not None else []
        elif variant == VARIANT_NARROWER_NO_ALLOWLIST:
            narrower = _build_narrower_child(without_allowlist, rng, seed, params_digest, variant, committed)
            produced = [narrower] if narrower is not None else []
        else:
            fanout = _build_sibling_fanout(without_allowlist, rng, seed, params_digest, committed)
            produced = fanout if fanout is not None else []

        if not produced:
            consecutive_exhausted += 1
            if consecutive_exhausted > max_consecutive_exhausted:
                raise ValueError(
                    f"eligible parent pool exhausted after {len(results)}/{n_sessions} legitimate "
                    "delegation sessions; increase n_legitimate in the underlying corpus"
                )
            continue
        consecutive_exhausted = 0
        results.extend(produced)

    logger.info(
        "legitimate delegation: generated %d sessions from %d/%d eligible parents (with/without allowlist)",
        len(results), len(with_allowlist), len(without_allowlist),
    )
    return tuple(results)


__all__ = ["generate_legitimate_delegation_sessions", "GeneratedLegitimateDelegation"]
