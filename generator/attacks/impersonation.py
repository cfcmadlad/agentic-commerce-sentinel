"""Attack class 3: agent impersonation.

Four variants:
- unregistered_key: impostor mints its own keypair, self-signs a mandate.
  Caught by Layer 1 (no registered key for that agent_id/key_id).
- forged_signature: genuine mandate copied with an inflated scope, original
  signature kept. Caught by Layer 1 (signature no longer matches content).
- agent_binding_mismatch: a different agent presents someone else's genuine,
  valid mandate. Crypto passes; only Layer 2's binding check catches it.
- behavioral_only: the real agent's real mandate, fully in scope. Nothing
  cryptographic or scope-related is wrong — only pacing (fast, near-uniform,
  browse often skipped) gives it away. Layers 1 and 2 both pass it; this is
  the variant Layer 3 exists for.

Behavioral markers overlap the legitimate distribution on purpose (scripted
pacing shares its lower bound with legitimate timing; browse-skip is
probabilistic, not certain) so the class isn't trivially separable.

Defense-only: synthetic sessions against this project's own detector.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

import numpy as np

from common.schema import AttackClass, EventType, SessionTrace
from generator.attack_config import (
    IMPERSONATION_MIX_AGENT_BINDING_MISMATCH,
    IMPERSONATION_MIX_BEHAVIORAL_ONLY,
    IMPERSONATION_MIX_FORGED_SIGNATURE,
    IMPERSONATION_MIX_UNREGISTERED_KEY,
    MAX_SCRIPTED_EVENT_GAP_SECONDS,
    MIN_SCRIPTED_EVENT_GAP_SECONDS,
    SKIP_BROWSE_PROBABILITY,
)
from generator.attacks.common import AttackWorld, GeneratedAttack, label_attack, pick_weighted
from generator.config import (
    MAX_EVENT_GAP_SECONDS,
    MAX_MANDATE_LIFETIME_DAYS,
    MIN_EVENT_GAP_SECONDS,
    MIN_MANDATE_LIFETIME_DAYS,
)
from generator.events import LEGITIMATE_LIFECYCLE, build_events
from generator.legitimate import AMOUNT_QUANTIZE, ED25519_SEED_BYTES
from generator.rng import rng_nonce, rng_uuid
from mandate.schema import Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate

logger = logging.getLogger(__name__)

VARIANT_UNREGISTERED_KEY = "unregistered_key"
VARIANT_FORGED_SIGNATURE = "forged_signature"
VARIANT_AGENT_BINDING_MISMATCH = "agent_binding_mismatch"
VARIANT_BEHAVIORAL_ONLY = "behavioral_only"

_VARIANT_WEIGHTS = {
    VARIANT_UNREGISTERED_KEY: IMPERSONATION_MIX_UNREGISTERED_KEY,
    VARIANT_FORGED_SIGNATURE: IMPERSONATION_MIX_FORGED_SIGNATURE,
    VARIANT_AGENT_BINDING_MISMATCH: IMPERSONATION_MIX_AGENT_BINDING_MISMATCH,
    VARIANT_BEHAVIORAL_ONLY: IMPERSONATION_MIX_BEHAVIORAL_ONLY,
}

# Ceiling multiplier for a forged mandate copy — large enough the forgery is
# worth attempting; the signature check stops it, not the edit's size.
FORGED_CEILING_MULTIPLE = Decimal("6")


def _scripted_stages(rng: np.random.Generator) -> tuple[EventType, ...]:
    """Picks lifecycle stages for a scripted client, browse omitted probabilistically.

    Args:
        rng: Seeded random generator.

    Returns:
        The stage sequence.
    """
    if rng.random() < SKIP_BROWSE_PROBABILITY:
        return tuple(s for s in LEGITIMATE_LIFECYCLE if s is not EventType.CATALOG_BROWSE)
    return LEGITIMATE_LIFECYCLE


def _self_signed_mandate(
    rng: np.random.Generator, donor_trace: SessionTrace, issued_at: datetime
) -> SignedMandate:
    """Mints a mandate signed by a key no registry knows about.

    Args:
        rng: Seeded random generator.
        donor_trace: A genuine session to copy merchant/category/amount from.
        issued_at: Claimed issuance time.

    Returns:
        The self-signed mandate.
    """
    private_key, public_key = keypair_from_seed_bytes(rng.bytes(ED25519_SEED_BYTES))
    lifetime_days = int(rng.integers(MIN_MANDATE_LIFETIME_DAYS, MAX_MANDATE_LIFETIME_DAYS + 1))
    valid_until = issued_at + timedelta(days=lifetime_days)
    ceiling = (donor_trace.amount * Decimal("2")).quantize(
        AMOUNT_QUANTIZE, rounding=ROUND_HALF_UP
    )
    scope = MandateScope(
        max_amount=ceiling,
        currency=donor_trace.currency,
        allowed_merchant_ids=None,
        allowed_merchant_categories=frozenset({donor_trace.merchant_category}),
        allowed_item_categories=frozenset({donor_trace.item_category}),
        valid_from=issued_at,
        valid_until=valid_until,
        max_transaction_count=1,
    )
    mandate = Mandate(
        mandate_id=rng_uuid(rng),
        agent_id=donor_trace.agent_id,
        user_id=donor_trace.user_id,
        parent_mandate_id=None,
        issued_at=issued_at,
        expires_at=valid_until,
        nonce=rng_nonce(rng),
        scope=scope,
        signer_key_id=key_id_for_public_key(public_key),
    )
    return sign_mandate(mandate, private_key)


def _forged_mandate(signed: SignedMandate) -> SignedMandate:
    """Inflates a genuine mandate's ceiling while keeping the original signature.

    Args:
        signed: The genuine mandate to tamper with.

    Returns:
        A mandate whose content no longer matches its signature.
    """
    inflated_scope = signed.mandate.scope.model_copy(
        update={"max_amount": signed.mandate.scope.max_amount * FORGED_CEILING_MULTIPLE}
    )
    tampered = signed.mandate.model_copy(update={"scope": inflated_scope})
    return signed.model_copy(update={"mandate": tampered})


def _in_window_start(rng: np.random.Generator, world: AttackWorld, signed: SignedMandate) -> datetime:
    """Picks a session start inside a mandate's still-valid window.

    Args:
        rng: Seeded random generator.
        world: The indexed legitimate corpus.
        signed: The mandate the session will present.

    Returns:
        A timestamp between the mandate's last legitimate use and expiry.
    """
    last_used = world.mandate_last_used_at[signed.mandate.mandate_id]
    window_end = signed.mandate.scope.valid_until
    span = max((window_end - last_used).total_seconds() - 60.0, 1.0)
    return last_used + timedelta(seconds=float(rng.uniform(0, span)))


def _eligible_mandates(world: AttackWorld, variant: str) -> list[SignedMandate]:
    """Selects mandates a given impersonation variant can target.

    Args:
        world: The indexed legitimate corpus.
        variant: One of the module's VARIANT_* constants.

    Returns:
        Candidate signed mandates, possibly empty.

    Raises:
        ValueError: If `variant` is unknown.
    """
    if variant not in _VARIANT_WEIGHTS:
        raise ValueError(f"unknown impersonation variant {variant!r}")

    if variant == VARIANT_UNREGISTERED_KEY:
        # Only needs a donor session, not budget headroom on a reusable mandate.
        return [
            world.output.signed_mandates[mandate_id]
            for mandate_id in sorted(world.session_by_mandate, key=str)
        ]
    return [
        world.output.signed_mandates[mandate_id]
        for mandate_id in sorted(world.session_by_mandate, key=str)
        if world.mandate_use_count.get(mandate_id, 0)
        < world.output.signed_mandates[mandate_id].mandate.scope.max_transaction_count
    ]


def _build_impersonation(
    rng: np.random.Generator, world: AttackWorld, signed: SignedMandate, variant: str, seed: int
) -> GeneratedAttack:
    """Builds one impersonation session and any mandate material it introduces.

    Args:
        rng: Seeded random generator.
        world: The indexed legitimate corpus.
        signed: The genuine mandate this variant builds from.
        variant: One of the module's VARIANT_* constants.
        seed: Generator seed, recorded on the label.

    Returns:
        The generated attack.

    Raises:
        ValueError: If `variant` is unknown.
    """
    donor_sessions = world.session_by_mandate[signed.mandate.mandate_id]
    donor = donor_sessions[int(rng.integers(0, len(donor_sessions)))]
    session_start = _in_window_start(rng, world, signed)

    presented: SignedMandate | None = None
    presented_mandate_id = signed.mandate.mandate_id
    acting_agent_id = donor.agent_id
    stages = LEGITIMATE_LIFECYCLE
    min_gap, max_gap = MIN_EVENT_GAP_SECONDS, MAX_EVENT_GAP_SECONDS

    if variant == VARIANT_UNREGISTERED_KEY:
        presented = _self_signed_mandate(rng, donor, session_start)
        presented_mandate_id = presented.mandate.mandate_id
        stages = _scripted_stages(rng)
        min_gap, max_gap = MIN_SCRIPTED_EVENT_GAP_SECONDS, MAX_SCRIPTED_EVENT_GAP_SECONDS
    elif variant == VARIANT_FORGED_SIGNATURE:
        presented = _forged_mandate(signed)
        presented_mandate_id = presented.mandate.mandate_id
        stages = _scripted_stages(rng)
        min_gap, max_gap = MIN_SCRIPTED_EVENT_GAP_SECONDS, MAX_SCRIPTED_EVENT_GAP_SECONDS
    elif variant == VARIANT_AGENT_BINDING_MISMATCH:
        # Acting agent drawn from the same pool, so agent_id itself is uninformative.
        others = [a for a in world.output.agents if a.agent_id != signed.mandate.agent_id]
        acting_agent_id = others[int(rng.integers(0, len(others)))].agent_id
    elif variant == VARIANT_BEHAVIORAL_ONLY:
        stages = _scripted_stages(rng)
        min_gap, max_gap = MIN_SCRIPTED_EVENT_GAP_SECONDS, MAX_SCRIPTED_EVENT_GAP_SECONDS
    else:
        raise ValueError(f"unknown impersonation variant {variant!r}")

    events, completed_at = build_events(rng, session_start, stages, min_gap, max_gap)
    trace = SessionTrace(
        session_id=rng_uuid(rng),
        agent_id=acting_agent_id,
        user_id=donor.user_id,
        mandate_id=presented_mandate_id,
        merchant_id=donor.merchant_id,
        merchant_category=donor.merchant_category,
        item_category=donor.item_category,
        amount=donor.amount,
        currency=donor.currency,
        events=events,
        started_at=session_start,
        completed_at=completed_at,
    )
    return GeneratedAttack(
        labeled=label_attack(trace, AttackClass.AGENT_IMPERSONATION, seed, world.output.params_digest),
        signed_mandate=presented,
        variant=variant,
    )


def generate_impersonation_attacks(
    world: AttackWorld, n_attacks: int, seed: int
) -> tuple[GeneratedAttack, ...]:
    """Generates agent-impersonation attack sessions against a legitimate corpus.

    Args:
        world: The indexed legitimate corpus to build attacks against.
        n_attacks: Number of attack sessions to produce. Must be positive.
        seed: Seed for this generator's random draws.

    Returns:
        The generated attacks, in generation order.

    Raises:
        ValueError: If `n_attacks` is not positive, or no mandate in the
            world is eligible for any variant.
    """
    if n_attacks <= 0:
        raise ValueError(f"n_attacks must be positive, got {n_attacks}")

    rng = np.random.default_rng(seed)
    candidates_by_variant = {v: _eligible_mandates(world, v) for v in _VARIANT_WEIGHTS}
    available = {v: w for v, w in _VARIANT_WEIGHTS.items() if candidates_by_variant[v]}
    if not available:
        raise ValueError(
            "no mandate in the legitimate corpus is eligible for any impersonation "
            "variant; generate a larger legitimate corpus first"
        )
    for variant in _VARIANT_WEIGHTS:
        if variant not in available:
            logger.warning("impersonation variant %s has no eligible mandates, skipped", variant)

    attacks: list[GeneratedAttack] = []
    for _ in range(n_attacks):
        variant = pick_weighted(rng, available)
        pool = candidates_by_variant[variant]
        signed = pool[int(rng.integers(0, len(pool)))]
        attacks.append(_build_impersonation(rng, world, signed, variant, seed))

    return tuple(attacks)