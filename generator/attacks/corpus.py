"""Assembles a mixed evaluation corpus from legitimate and attack traffic.

Corpus is chronologically ordered: Layer 1's budget check is stateful, so a
replay attack against a spent mandate is only detectable if the verifier has
already processed the legitimate sessions that spent it.

Held-out class: AttackClass.MANDATE_CHAINING is never generated here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from common.schema import AttackClass, LabeledSession
from detect.resolution import InMemoryMandateResolver
from generator.attack_config import (
    DEFAULT_ATTACK_CONFIG,
    AttackConfig,
    combined_params_digest,
)
from generator.attacks.common import GeneratedAttack, build_world
from generator.attacks.impersonation import generate_impersonation_attacks
from generator.attacks.replay import generate_replay_attacks
from generator.attacks.scope_violation import generate_scope_violation_attacks
from generator.config import DEFAULT_GENERATOR_CONFIG, GeneratorConfig
from generator.legitimate import generate_legitimate_sessions
from mandate.verification import AgentKeyRegistry

logger = logging.getLogger(__name__)

# Seed offsets so the three attack generators draw independent random streams
# rather than making correlated choices (same donor mandates, same variant
# order) that would show up as spurious structure a model could latch onto.
SEED_OFFSET_REPLAY = 1_000
SEED_OFFSET_SCOPE = 2_000
SEED_OFFSET_IMPERSONATION = 3_000


@dataclass(frozen=True)
class EvaluationCorpus:
    """A chronologically ordered mix of legitimate and attack sessions.

    Attributes:
        labeled_sessions: Every session, sorted by start time.
        resolver: Resolves the mandate document each session presented.
        registry: Public keys for the legitimate agent pool. Does not
            contain keys minted by impersonation attacks — that absence is
            what Layer 1 detects.
        variant_by_session: Attack sub-variant per session, for the gate
            report's per-variant breakdown. Ground-truth metadata; must
            never reach a feature extractor or detector.
        attack_base_rate: Realized fraction of attack sessions.
        seed: The corpus seed.
        generator_config: Legitimate-traffic parameters this corpus was built
            under.
        attack_config: Attack-generation parameters this corpus was built
            under.
        params_digest: Digest covering both parameter sets, so a sensitivity
            grid point is identifiable from the corpus alone.
    """

    labeled_sessions: tuple[LabeledSession, ...]
    resolver: InMemoryMandateResolver
    registry: AgentKeyRegistry
    variant_by_session: dict[UUID, str]
    attack_base_rate: float
    seed: int
    generator_config: GeneratorConfig
    attack_config: AttackConfig
    params_digest: str


def _split_attack_counts(n_attacks: int, config: AttackConfig) -> dict[AttackClass, int]:
    """Divides an attack budget across the three training classes.

    Args:
        n_attacks: Total attack sessions to produce.
        config: Attack parameters supplying the class mix.

    Returns:
        Per-class counts summing to `n_attacks`. Scope violation absorbs the
        rounding remainder since it carries the largest configured share.
    """
    replay = int(n_attacks * config.class_mix_mandate_replay)
    impersonation = int(n_attacks * config.class_mix_agent_impersonation)
    scope = n_attacks - replay - impersonation
    return {
        AttackClass.MANDATE_REPLAY: replay,
        AttackClass.SCOPE_VIOLATION: scope,
        AttackClass.AGENT_IMPERSONATION: impersonation,
    }


def build_evaluation_corpus(
    n_legitimate: int,
    seed: int,
    attack_base_rate: float | None = None,
    generator_config: GeneratorConfig = DEFAULT_GENERATOR_CONFIG,
    attack_config: AttackConfig = DEFAULT_ATTACK_CONFIG,
) -> EvaluationCorpus:
    """Generates legitimate traffic and the three training attack classes together.

    Args:
        n_legitimate: Number of legitimate sessions. Must be positive.
        seed: Corpus seed; the same seed always produces the same corpus.
        attack_base_rate: Target attack fraction, overriding
            `attack_config.attack_base_rate` when given. Must be in (0, 1).
        generator_config: Legitimate-traffic parameters. The default
            reproduces the parameter set every reported headline number was
            measured under.
        attack_config: Attack-generation parameters, same default contract.

    Returns:
        The assembled corpus.

    Raises:
        ValueError: If `n_legitimate` is not positive, `attack_base_rate` is
            outside (0, 1), or the attack budget rounds to zero for any
            class — an empty attack class gives an undefined per-class
            recall that's easy to misread as zero.
    """
    if n_legitimate <= 0:
        raise ValueError(f"n_legitimate must be positive, got {n_legitimate}")
    rate = attack_config.attack_base_rate if attack_base_rate is None else attack_base_rate
    if not 0.0 < rate < 1.0:
        raise ValueError(f"attack_base_rate must be in (0, 1), got {rate}")

    n_attacks = round(n_legitimate * rate / (1.0 - rate))
    counts = _split_attack_counts(n_attacks, attack_config)
    empty = [cls.value for cls, count in counts.items() if count < 1]
    if empty:
        raise ValueError(
            f"attack budget of {n_attacks} leaves these classes empty: {empty}; "
            f"increase n_legitimate or attack_base_rate"
        )

    legitimate = generate_legitimate_sessions(n_legitimate, seed=seed, config=generator_config)
    world = build_world(legitimate)

    # Attack sessions are stamped with a digest covering both halves: a grid
    # point that varies only attack parameters produces an identical
    # legitimate substrate, and a generator-only digest could not tell the two
    # corpora apart.
    digest = combined_params_digest(generator_config, attack_config)

    attacks: list[GeneratedAttack] = []
    attacks.extend(
        generate_replay_attacks(
            world,
            counts[AttackClass.MANDATE_REPLAY],
            seed=seed + SEED_OFFSET_REPLAY,
            config=attack_config,
            params_digest=digest,
        )
    )
    attacks.extend(
        generate_scope_violation_attacks(
            world,
            counts[AttackClass.SCOPE_VIOLATION],
            seed=seed + SEED_OFFSET_SCOPE,
            config=attack_config,
            params_digest=digest,
        )
    )
    attacks.extend(
        generate_impersonation_attacks(
            world,
            counts[AttackClass.AGENT_IMPERSONATION],
            seed=seed + SEED_OFFSET_IMPERSONATION,
            config=attack_config,
            params_digest=digest,
        )
    )

    presented = {}
    for labeled in legitimate.labeled_sessions:
        mandate_id = labeled.trace.mandate_id
        if mandate_id is not None:
            presented[labeled.trace.session_id] = legitimate.signed_mandates[mandate_id]

    variant_by_session: dict[UUID, str] = {}
    for attack in attacks:
        trace = attack.labeled.trace
        variant_by_session[trace.session_id] = attack.variant
        if attack.signed_mandate is not None:
            presented[trace.session_id] = attack.signed_mandate
        elif trace.mandate_id is not None:
            presented[trace.session_id] = legitimate.signed_mandates[trace.mandate_id]

    all_sessions = list(legitimate.labeled_sessions) + [a.labeled for a in attacks]
    # Tie-broken by session ID: ordering must be total and reproducible when
    # an attack shares a start timestamp with a legitimate session.
    all_sessions.sort(key=lambda s: (s.trace.started_at, str(s.trace.session_id)))

    realized_rate = len(attacks) / len(all_sessions)
    logger.info(
        "corpus: %d sessions, %d attacks, realized base rate %.4f",
        len(all_sessions), len(attacks), realized_rate,
    )

    return EvaluationCorpus(
        labeled_sessions=tuple(all_sessions),
        resolver=InMemoryMandateResolver(presented),
        registry=legitimate.registry,
        variant_by_session=variant_by_session,
        attack_base_rate=realized_rate,
        seed=seed,
        generator_config=generator_config,
        attack_config=attack_config,
        params_digest=digest,
    )