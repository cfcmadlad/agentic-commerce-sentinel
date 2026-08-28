"""Assembles a mixed corpus: ordinary legitimate traffic, planted rings, and hard negatives.

Chronologically ordered, matching every other evaluation corpus in this
project. Reuses `generator.legitimate.generate_legitimate_sessions` for the
ordinary independent-agent population rather than reinventing it -- this is
the same legitimate traffic every other milestone's numbers are measured
against, just with a synthetic device fingerprint attached to each session
(see `generator/collusion/__init__.py` for why that is a session-keyed
mapping rather than a schema change).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

import numpy as np

from common.schema import SessionTrace
from detect.resolution import InMemoryMandateResolver
from generator.collusion.fingerprint import DeviceFingerprint, generate_fingerprint
from generator.collusion.rings import generate_ring_groups
from generator.collusion.schema import RingGroup
from generator.config import DEFAULT_GENERATOR_CONFIG, GeneratorConfig
from generator.legitimate import generate_legitimate_sessions
from mandate.schema import SignedMandate
from mandate.signing import key_id_for_public_key
from mandate.verification import AgentKeyRegistry

logger = logging.getLogger(__name__)

# Seed offsets so the baseline legitimate population, the per-session
# fingerprint draws, and the ring-group generator each draw from genuinely
# independent RNG streams -- not merely different call sequences from an
# identical seed value, which is exactly the class of mandate-ID-collision
# bug docs/adr/0003's addendum and docs/adr/0004 document being found and
# fixed in generator/attacks/held_out.py. Large and widely spaced so a
# realistic number of ring groups (each consuming its own seed+offset,
# see generator/collusion/rings.py::generate_ring_groups) can never reach
# into another stream's range.
SEED_OFFSET_FINGERPRINT = 500_000
SEED_OFFSET_RINGS = 1_000_000


@dataclass(frozen=True)
class CollusionCorpus:
    """A chronologically ordered mix of ordinary traffic, planted rings, and hard negatives.

    Attributes:
        sessions: Every session, sorted by start time.
        fingerprints: Device fingerprint observed for each session, keyed by
            session ID -- covers every session in the corpus, baseline
            included.
        registry: Public keys for every agent in the corpus, baseline and
            ring participants alike.
        resolver: Resolves the mandate document each session presented.
        groups: Ground truth for every planted ring and hard-negative group
            (`RingGroup.is_ring` distinguishes them). Does not include the
            ordinary baseline population -- see `baseline_agent_ids`.
        baseline_agent_ids: The ordinary, independent legitimate agents in
            this corpus, no group structure attached. Ground-truth metadata;
            must never reach a detector.
        seed: The corpus seed.
    """

    sessions: tuple[SessionTrace, ...]
    fingerprints: dict[UUID, DeviceFingerprint]
    registry: AgentKeyRegistry
    resolver: InMemoryMandateResolver
    groups: tuple[RingGroup, ...]
    baseline_agent_ids: frozenset[str]
    seed: int


def build_collusion_corpus(
    n_baseline_legitimate: int,
    n_malicious_rings: int,
    n_household_negatives: int,
    n_shared_gateway_negatives: int,
    seed: int,
    generator_config: GeneratorConfig = DEFAULT_GENERATOR_CONFIG,
) -> CollusionCorpus:
    """Generates ordinary legitimate traffic together with planted rings and hard negatives.

    Args:
        n_baseline_legitimate: Ordinary, independent legitimate sessions.
            Must be positive.
        n_malicious_rings: Planted malicious ring groups, split round-robin
            across the three archetypes. Must be non-negative.
        n_household_negatives: Legitimate household hard-negative groups.
            Must be non-negative.
        n_shared_gateway_negatives: Legitimate shared-gateway hard-negative
            groups. Must be non-negative.
        seed: Corpus seed; the same seed always produces the same corpus.
        generator_config: Legitimate-traffic parameters for the baseline
            population.

    Returns:
        The assembled corpus.

    Raises:
        ValueError: If `n_baseline_legitimate` is not positive, or as
            propagated from `generate_ring_groups` for a negative count.
    """
    if n_baseline_legitimate <= 0:
        raise ValueError(f"n_baseline_legitimate must be positive, got {n_baseline_legitimate}")

    legitimate = generate_legitimate_sessions(n_baseline_legitimate, seed=seed, config=generator_config)

    fp_rng = np.random.default_rng(seed + SEED_OFFSET_FINGERPRINT)
    fingerprints: dict[UUID, DeviceFingerprint] = {
        labeled.trace.session_id: generate_fingerprint(fp_rng)
        for labeled in legitimate.labeled_sessions
    }

    presented: dict[UUID, SignedMandate] = {}
    for labeled in legitimate.labeled_sessions:
        mandate_id = labeled.trace.mandate_id
        if mandate_id is not None:
            presented[labeled.trace.session_id] = legitimate.signed_mandates[mandate_id]

    ring_pieces = generate_ring_groups(
        n_malicious_rings, n_household_negatives, n_shared_gateway_negatives,
        seed=seed + SEED_OFFSET_RINGS,
    )

    registry = legitimate.registry
    all_sessions: list[SessionTrace] = [labeled.trace for labeled in legitimate.labeled_sessions]
    groups: list[RingGroup] = []
    for piece in ring_pieces:
        all_sessions.extend(piece.sessions)
        fingerprints.update(piece.fingerprints)
        presented.update(piece.signed_mandates)
        groups.append(piece.group)
        for participant in piece.participants:
            key_id = key_id_for_public_key(participant.private_key.public_key())
            registry.register(participant.agent_id, key_id, participant.private_key.public_key())

    all_sessions.sort(key=lambda s: (s.started_at, str(s.session_id)))
    baseline_agent_ids = frozenset(agent.agent_id for agent in legitimate.agents)

    logger.info(
        "collusion corpus: %d sessions (%d baseline, %d ring groups)",
        len(all_sessions), n_baseline_legitimate, len(groups),
    )

    return CollusionCorpus(
        sessions=tuple(all_sessions),
        fingerprints=fingerprints,
        registry=registry,
        resolver=InMemoryMandateResolver(presented),
        groups=tuple(groups),
        baseline_agent_ids=baseline_agent_ids,
        seed=seed,
    )
