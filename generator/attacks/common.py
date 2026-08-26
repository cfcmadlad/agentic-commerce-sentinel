"""Shared types and helpers for the attack generators.

Every attack generator in this package follows the same contract: it takes an
already-generated legitimate corpus as its world (dependency injection, not a
module-level singleton), draws all randomness from one seeded
`numpy.random.Generator`, and returns `GeneratedAttack` records without
mutating the legitimate corpus, its registry, or its ledger. Mutating the
world would make attack generation order-dependent and silently break the
reproducibility guarantee the legitimate generator establishes.

Defense-only note: everything in this package produces synthetic sessions
that violate this project's own mandate schema so that this project's own
detector can be measured against them. Nothing here is a technique against a
real payment system.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import numpy as np

from common.schema import AttackClass, LabeledSession, SessionTrace
from generator.legitimate import AgentProfile, LegitimateGeneratorOutput
from mandate.schema import SignedMandate


@dataclass(frozen=True)
class GeneratedAttack:
    """One synthetic attack session plus the material a verifier needs for it.

    Attributes:
        labeled: The session and its ground-truth label.
        signed_mandate: The mandate this session presents, if the attack
            introduces one the legitimate corpus does not already contain
            (for example a self-signed mandate from an unregistered key).
            None when the session presents a mandate already in the corpus.
        variant: Sub-variant identifier within the attack class, carried so
            the evaluation can break recall down per variant rather than only
            per class. This is diagnostic metadata for the eval harness and
            must never reach feature extraction.
    """

    labeled: LabeledSession
    signed_mandate: SignedMandate | None
    variant: str


@dataclass(frozen=True)
class AttackWorld:
    """A read-only view of the legitimate corpus that attacks are built against.

    Attributes:
        output: The legitimate generator run being attacked.
        mandate_last_used_at: For each mandate, the start time of the most
            recent legitimate session that presented it. Rapid-reuse replay
            needs this to place itself plausibly close behind a real use.
        mandate_use_count: For each mandate, how many legitimate sessions
            presented it, so budget-exhaustion replay can select a mandate
            that is genuinely spent rather than one that merely looks it.
        session_by_mandate: Legitimate sessions grouped by the mandate they
            presented, so an attack can copy a real session's in-scope
            merchant and item category instead of inventing plausible-looking
            values that might not match the mandate.
    """

    output: LegitimateGeneratorOutput
    mandate_last_used_at: dict[UUID, datetime]
    mandate_use_count: dict[UUID, int]
    session_by_mandate: dict[UUID, list[SessionTrace]]


def build_world(output: LegitimateGeneratorOutput) -> AttackWorld:
    """Indexes a legitimate corpus into the lookups the attack generators need.

    Args:
        output: A completed legitimate generator run.

    Returns:
        The indexed world.

    Raises:
        ValueError: If the corpus contains no sessions. Generating attacks
            against an empty world would silently produce zero attacks, which
            would then quietly corrupt every downstream metric.
    """
    if not output.labeled_sessions:
        raise ValueError("cannot build an attack world from an empty legitimate corpus")

    last_used: dict[UUID, datetime] = {}
    use_count: dict[UUID, int] = {}
    by_mandate: dict[UUID, list[SessionTrace]] = {}

    for labeled in output.labeled_sessions:
        trace = labeled.trace
        if trace.mandate_id is None:
            continue
        previous = last_used.get(trace.mandate_id)
        if previous is None or trace.started_at > previous:
            last_used[trace.mandate_id] = trace.started_at
        use_count[trace.mandate_id] = use_count.get(trace.mandate_id, 0) + 1
        by_mandate.setdefault(trace.mandate_id, []).append(trace)

    return AttackWorld(
        output=output,
        mandate_last_used_at=last_used,
        mandate_use_count=use_count,
        session_by_mandate=by_mandate,
    )


def pick_weighted(rng: np.random.Generator, weights: dict[str, float]) -> str:
    """Draws one key from a weight map, normalizing the weights first.

    Args:
        rng: Seeded random generator.
        weights: Map of choice name to relative weight. Weights need not sum
            to 1 and must all be non-negative with a positive total.

    Returns:
        The selected key.

    Raises:
        ValueError: If the map is empty, any weight is negative, or the
            weights sum to zero. Each of these would otherwise surface as an
            opaque numpy error deep inside a generator.
    """
    if not weights:
        raise ValueError("weights must be non-empty")
    names = sorted(weights)
    values = np.array([weights[name] for name in names], dtype=float)
    if (values < 0).any():
        raise ValueError(f"weights must be non-negative, got {weights}")
    total = values.sum()
    if total <= 0:
        raise ValueError(f"weights must sum to a positive value, got {weights}")
    return str(rng.choice(names, p=values / total))


def agent_by_id(world: AttackWorld, agent_id: str) -> AgentProfile:
    """Looks up an agent profile in the world by its identifier.

    Args:
        world: The indexed legitimate corpus.
        agent_id: The agent identifier to resolve.

    Returns:
        The matching agent profile.

    Raises:
        KeyError: If no such agent exists in the pool. A mandate referencing
            an agent outside the pool means the world and the corpus have
            drifted apart, which must fail loudly rather than be papered over.
    """
    for agent in world.output.agents:
        if agent.agent_id == agent_id:
            return agent
    raise KeyError(f"agent {agent_id!r} is not in the generated agent pool")


def label_attack(
    trace: SessionTrace, attack_class: AttackClass, seed: int, params_digest: str
) -> LabeledSession:
    """Wraps a trace with its ground-truth attack label.

    Args:
        trace: The generated session.
        attack_class: The ground-truth class. Must not be LEGITIMATE.
        seed: The generator seed that produced this session.
        params_digest: Digest of the generator parameters in effect.

    Returns:
        The labeled session.

    Raises:
        ValueError: If `attack_class` is LEGITIMATE, which would produce a
            mislabeled attack in the corpus.
    """
    if attack_class is AttackClass.LEGITIMATE:
        raise ValueError("label_attack must not be used to label legitimate sessions")
    return LabeledSession(
        trace=trace,
        attack_class=attack_class,
        is_attack=True,
        generator_seed=seed,
        generator_params_digest=params_digest,
    )