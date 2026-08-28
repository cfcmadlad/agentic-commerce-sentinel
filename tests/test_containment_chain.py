"""Tests for `containment.chain`: ancestor-chain resolution, cycles, and depth."""

from __future__ import annotations

import pytest

from containment.chain import resolve_ancestor_chain
from containment.store import InMemoryMandateChainStore
from mandate.signing import generate_keypair
from tests.factories import build_mandate, random_uuid


def test_root_mandate_raises() -> None:
    """A mandate with no parent has nothing for the chain walker to resolve."""
    private_key, _ = generate_keypair()
    root = build_mandate(private_key, parent_mandate_id=None)
    store = InMemoryMandateChainStore({})
    with pytest.raises(ValueError, match="no parent"):
        resolve_ancestor_chain(root, store)


def test_single_level_resolves_immediate_parent() -> None:
    """A direct child resolves exactly one ancestor: its own parent."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child = build_mandate(private_key, parent_mandate_id=parent.mandate_id)
    store = InMemoryMandateChainStore({parent.mandate_id: parent})

    resolution = resolve_ancestor_chain(child, store)

    assert not resolution.broken
    assert resolution.immediate_parent == parent
    assert resolution.ancestors == (parent,)


def test_multi_level_resolves_full_ancestor_list() -> None:
    """A grandchild resolves both its parent and grandparent, in walk order."""
    private_key, _ = generate_keypair()
    grandparent = build_mandate(private_key)
    parent = build_mandate(private_key, parent_mandate_id=grandparent.mandate_id)
    child = build_mandate(private_key, parent_mandate_id=parent.mandate_id)
    store = InMemoryMandateChainStore(
        {grandparent.mandate_id: grandparent, parent.mandate_id: parent}
    )

    resolution = resolve_ancestor_chain(child, store, max_depth=3)

    assert not resolution.broken
    assert resolution.immediate_parent == parent
    assert resolution.ancestors == (parent, grandparent)


def test_self_reference_is_a_cycle() -> None:
    """A mandate declaring itself as its own parent must be rejected as a cycle."""
    private_key, _ = generate_keypair()
    mandate_id = random_uuid()
    looping = build_mandate(private_key, mandate_id=mandate_id, parent_mandate_id=mandate_id)
    store = InMemoryMandateChainStore({mandate_id: looping})

    resolution = resolve_ancestor_chain(looping, store)

    assert resolution.broken
    assert resolution.cycle_detected
    assert not resolution.depth_exceeded
    assert not resolution.unresolvable


def test_two_mandate_cycle_is_detected() -> None:
    """A pointing to B pointing back to A must be rejected, not looped forever."""
    private_key, _ = generate_keypair()
    id_a = random_uuid()
    id_b = random_uuid()
    mandate_a = build_mandate(private_key, mandate_id=id_a, parent_mandate_id=id_b)
    mandate_b = build_mandate(private_key, mandate_id=id_b, parent_mandate_id=id_a)
    store = InMemoryMandateChainStore({id_a: mandate_a, id_b: mandate_b})

    resolution = resolve_ancestor_chain(mandate_a, store, max_depth=10)

    assert resolution.cycle_detected


def test_depth_exceeded_when_chain_longer_than_max_depth() -> None:
    """A chain deeper than the configured bound must fail closed on depth."""
    private_key, _ = generate_keypair()
    mandates = []
    previous_id = None
    for _ in range(5):
        mandate = build_mandate(private_key, parent_mandate_id=previous_id)
        mandates.append(mandate)
        previous_id = mandate.mandate_id
    store = InMemoryMandateChainStore({m.mandate_id: m for m in mandates})

    resolution = resolve_ancestor_chain(mandates[-1], store, max_depth=2)

    assert resolution.broken
    assert resolution.depth_exceeded
    assert not resolution.cycle_detected


def test_unresolvable_when_parent_missing_from_store() -> None:
    """A parent_mandate_id the store has no record of must fail closed, not silently stop."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=random_uuid())
    store = InMemoryMandateChainStore({})

    resolution = resolve_ancestor_chain(child, store)

    assert resolution.broken
    assert resolution.unresolvable
    assert resolution.immediate_parent is None
