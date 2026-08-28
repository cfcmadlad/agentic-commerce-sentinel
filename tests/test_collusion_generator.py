"""Tests for `generator.collusion.rings` and `generator.collusion.corpus`."""

from __future__ import annotations

import numpy as np
import pytest

from generator.collusion.corpus import build_collusion_corpus
from generator.collusion.rings import (
    HOUSEHOLD_SIZE,
    SHARED_FINGERPRINT_RING_SIZE,
    SHARED_GATEWAY_SIZE,
    build_counterparty_ring,
    build_cross_agent_structuring,
    build_legitimate_household,
    build_legitimate_shared_gateway,
    build_shared_fingerprint_ring,
    generate_ring_groups,
)
from generator.collusion.schema import (
    ARCHETYPE_COUNTERPARTY_RING,
    ARCHETYPE_CROSS_AGENT_STRUCTURING,
    ARCHETYPE_LEGITIMATE_HOUSEHOLD,
    ARCHETYPE_LEGITIMATE_SHARED_GATEWAY,
    ARCHETYPE_SHARED_FINGERPRINT_RING,
)


def test_shared_fingerprint_ring_shares_exactly_one_fingerprint() -> None:
    """Every session in this archetype must carry the identical fingerprint."""
    piece = build_shared_fingerprint_ring(np.random.default_rng(1), "g")
    assert piece.group.archetype == ARCHETYPE_SHARED_FINGERPRINT_RING
    assert piece.group.is_ring
    assert len(piece.group.agent_ids) == SHARED_FINGERPRINT_RING_SIZE
    fingerprints = set(piece.fingerprints.values())
    assert len(fingerprints) == 1


def test_shared_fingerprint_ring_agents_are_genuinely_distinct() -> None:
    """Every participant must have its own signing key, not a shared or forged one."""
    piece = build_shared_fingerprint_ring(np.random.default_rng(1), "g")
    keys = {p.private_key.private_bytes_raw() for p in piece.participants}
    assert len(keys) == len(piece.participants)


def test_cross_agent_structuring_sessions_fall_in_one_window() -> None:
    """Every participant's session must land inside the same coordinated window."""
    piece = build_cross_agent_structuring(np.random.default_rng(2), "g")
    assert piece.group.archetype == ARCHETYPE_CROSS_AGENT_STRUCTURING
    assert piece.group.is_ring
    timestamps = sorted(s.started_at for s in piece.sessions)
    assert (timestamps[-1] - timestamps[0]).total_seconds() < 3600  # comfortably under an hour


def test_cross_agent_structuring_shares_one_merchant() -> None:
    """The whole point of this archetype is convergence on one counterparty."""
    piece = build_cross_agent_structuring(np.random.default_rng(2), "g")
    merchants = {s.merchant_id for s in piece.sessions}
    assert len(merchants) == 1


def test_cross_agent_structuring_no_shared_fingerprint() -> None:
    """This archetype isolates the structuring signal -- no device is shared."""
    piece = build_cross_agent_structuring(np.random.default_rng(2), "g")
    assert len(set(piece.fingerprints.values())) == len(piece.sessions)


def test_counterparty_ring_uses_overlapping_but_not_identical_merchants() -> None:
    """A richer topology than a single shared merchant -- several overlapping counterparties."""
    piece = build_counterparty_ring(np.random.default_rng(3), "g")
    assert piece.group.archetype == ARCHETYPE_COUNTERPARTY_RING
    assert piece.group.is_ring
    merchants = {s.merchant_id for s in piece.sessions}
    assert 1 < len(merchants) <= 3


def test_legitimate_household_shares_fingerprint_but_not_timing_or_merchant() -> None:
    """The hard negative: fingerprint sharing alone, no coordination otherwise."""
    piece = build_legitimate_household(np.random.default_rng(4), "g")
    assert piece.group.archetype == ARCHETYPE_LEGITIMATE_HOUSEHOLD
    assert not piece.group.is_ring
    assert len(piece.group.agent_ids) == HOUSEHOLD_SIZE
    assert len(set(piece.fingerprints.values())) == 1
    timestamps = sorted(s.started_at for s in piece.sessions)
    assert (timestamps[-1] - timestamps[0]).total_seconds() > 3600  # spread wide, not coordinated


def test_legitimate_household_smaller_than_shared_fingerprint_ring() -> None:
    """A realistic family size must sit well below the ring archetype's headcount."""
    assert HOUSEHOLD_SIZE < SHARED_FINGERPRINT_RING_SIZE


def test_legitimate_shared_gateway_has_no_shared_fingerprint() -> None:
    """Many independent agents at one popular merchant -- no device is shared."""
    piece = build_legitimate_shared_gateway(np.random.default_rng(5), "g")
    assert piece.group.archetype == ARCHETYPE_LEGITIMATE_SHARED_GATEWAY
    assert not piece.group.is_ring
    assert len(piece.group.agent_ids) == SHARED_GATEWAY_SIZE
    assert len(set(piece.fingerprints.values())) == len(piece.sessions)


def test_legitimate_shared_gateway_all_use_the_same_merchant() -> None:
    """This is what makes it a hard negative: real counterparty overlap, no coordination."""
    piece = build_legitimate_shared_gateway(np.random.default_rng(5), "g")
    merchants = {s.merchant_id for s in piece.sessions}
    assert len(merchants) == 1


def test_generate_ring_groups_produces_the_requested_counts() -> None:
    """Every requested group must actually be produced, split round-robin across malicious archetypes."""
    pieces = generate_ring_groups(
        n_malicious_rings=6, n_household_negatives=2, n_shared_gateway_negatives=1, seed=42
    )
    archetypes = [p.group.archetype for p in pieces]
    assert archetypes.count(ARCHETYPE_SHARED_FINGERPRINT_RING) == 2
    assert archetypes.count(ARCHETYPE_CROSS_AGENT_STRUCTURING) == 2
    assert archetypes.count(ARCHETYPE_COUNTERPARTY_RING) == 2
    assert archetypes.count(ARCHETYPE_LEGITIMATE_HOUSEHOLD) == 2
    assert archetypes.count(ARCHETYPE_LEGITIMATE_SHARED_GATEWAY) == 1


def test_generate_ring_groups_rejects_negative_counts() -> None:
    """A negative count is a caller error, not silently clamped to zero."""
    with pytest.raises(ValueError, match="non-negative"):
        generate_ring_groups(n_malicious_rings=-1, n_household_negatives=0, n_shared_gateway_negatives=0, seed=1)


def test_generate_ring_groups_is_reproducible() -> None:
    """The same seed must produce byte-identical group membership."""
    first = generate_ring_groups(4, 1, 1, seed=7)
    second = generate_ring_groups(4, 1, 1, seed=7)
    assert [p.group.agent_ids for p in first] == [p.group.agent_ids for p in second]


def test_all_groups_have_distinct_agent_ids_across_the_corpus() -> None:
    """No agent identity may accidentally be shared across two unrelated groups."""
    pieces = generate_ring_groups(n_malicious_rings=6, n_household_negatives=2, n_shared_gateway_negatives=2, seed=42)
    all_agent_ids: list[str] = []
    for piece in pieces:
        all_agent_ids.extend(piece.group.agent_ids)
    assert len(all_agent_ids) == len(set(all_agent_ids))


def test_build_collusion_corpus_combines_baseline_and_ring_groups() -> None:
    """The assembled corpus must contain both the baseline population and every ring group."""
    corpus = build_collusion_corpus(
        n_baseline_legitimate=500, n_malicious_rings=3, n_household_negatives=1,
        n_shared_gateway_negatives=1, seed=42,
    )
    assert len(corpus.groups) == 5
    assert len(corpus.baseline_agent_ids) > 0
    assert len(corpus.fingerprints) == len(corpus.sessions)
    assert corpus.sessions == tuple(sorted(corpus.sessions, key=lambda s: s.started_at))


def test_build_collusion_corpus_rejects_non_positive_baseline() -> None:
    """A corpus with no baseline traffic at all is a caller error."""
    with pytest.raises(ValueError, match="positive"):
        build_collusion_corpus(
            n_baseline_legitimate=0, n_malicious_rings=1, n_household_negatives=0,
            n_shared_gateway_negatives=0, seed=1,
        )


def test_build_collusion_corpus_is_reproducible() -> None:
    """The same seed must produce a byte-identical session count and group structure."""
    first = build_collusion_corpus(500, 3, 1, 1, seed=42)
    second = build_collusion_corpus(500, 3, 1, 1, seed=42)
    assert len(first.sessions) == len(second.sessions)
    assert [g.agent_ids for g in first.groups] == [g.agent_ids for g in second.groups]
