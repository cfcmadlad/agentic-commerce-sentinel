"""Ground-truth types for the collusion generator.

`RingGroup` is this package's equivalent of `common.schema.LabeledSession`:
ground truth wrapped separately from the data a detector actually sees, so
passing it into `collusion/` code is never the type that type-checks by
accident. Nothing in `collusion/graph.py`, `collusion/community.py`,
`collusion/scoring.py`, or `collusion/detect.py` imports this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.schema import SessionTrace
from generator.collusion.fingerprint import DeviceFingerprint
from mandate.schema import SignedMandate

# Ground-truth archetype names, one per generator variant.
ARCHETYPE_SHARED_FINGERPRINT_RING = "shared_fingerprint_ring"
ARCHETYPE_CROSS_AGENT_STRUCTURING = "cross_agent_structuring"
ARCHETYPE_COUNTERPARTY_RING = "counterparty_ring"
ARCHETYPE_LEGITIMATE_HOUSEHOLD = "legitimate_household"
ARCHETYPE_LEGITIMATE_SHARED_GATEWAY = "legitimate_shared_gateway"
ARCHETYPE_INDEPENDENT_BASELINE = "independent_baseline"


@dataclass(frozen=True)
class RingParticipant:
    """One synthetic agent identity participating in a generated group.

    Attributes:
        agent_id: Unique agent identifier.
        private_key: The agent's own Ed25519 signing key -- every
            participant is a genuinely distinct, independently keyed
            identity, matching how a real Sybil pattern works: the fraud is
            in the coordination between identities, not in any identity
            being forged.
        user_id: The human principal this agent claims to act for. Each
            participant gets its own distinct user, so a group cannot be
            told apart from independent agents by binding checks alone.
    """

    agent_id: str
    private_key: Ed25519PrivateKey
    user_id: str


@dataclass(frozen=True)
class RingGroup:
    """Ground truth for one generated group of agents.

    Attributes:
        group_id: Identifier for this group, unique within one corpus.
        archetype: Which generator variant produced it -- one of the
            `ARCHETYPE_*` constants.
        is_ring: True for a planted malicious ring, False for a legitimate
            shared-infrastructure negative case or an independent baseline
            agent. The ground truth `collusion/`'s evaluation is scored
            against.
        agent_ids: Every agent belonging to this group.
    """

    group_id: str
    archetype: str
    is_ring: bool
    agent_ids: frozenset[str]


@dataclass(frozen=True)
class GeneratedRingPiece:
    """One archetype generator's complete output: sessions plus ground truth.

    Attributes:
        group: The ground-truth label for this piece.
        participants: Every agent identity belonging to this piece.
        sessions: Every session this piece's participants generated.
        signed_mandates: The mandate each session presents, keyed by session
            ID -- each session in a ring piece gets its own freshly issued
            mandate; nothing here is reused across sessions the way a
            recurring legitimate mandate is.
        fingerprints: The device fingerprint observed for each session,
            keyed by session ID.
    """

    group: RingGroup
    participants: tuple[RingParticipant, ...]
    sessions: tuple[SessionTrace, ...]
    signed_mandates: dict[UUID, SignedMandate]
    fingerprints: dict[UUID, DeviceFingerprint]
