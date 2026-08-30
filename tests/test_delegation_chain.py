"""Tests for `service.delegation_chain.build_delegation_chain`."""

from __future__ import annotations

from decimal import Decimal

from containment.store import MutableMandateChainStore
from mandate.signing import generate_keypair
from service.delegation_chain import build_delegation_chain
from tests.factories import build_mandate, build_scope


def test_root_mandate_is_a_single_node_with_no_containment_check() -> None:
    """A mandate with no parent must report as one root node, in_bounds None."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    store = MutableMandateChainStore()
    store.add(mandate)

    chain = build_delegation_chain(mandate, store)

    assert len(chain.nodes) == 1
    assert chain.nodes[0].is_root
    assert chain.nodes[0].in_bounds is None
    assert chain.edges == []
    assert not chain.chain_broken


def test_in_bounds_child_reports_true_with_a_non_violating_edge() -> None:
    """A child whose scope fits inside its parent's must report in_bounds True."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("2000")))
    child = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(max_amount=Decimal("1000")),
        expires_at=parent.expires_at,
    )
    store = MutableMandateChainStore()
    store.add(parent)
    store.add(child)

    chain = build_delegation_chain(child, store)

    assert len(chain.nodes) == 2
    child_node = next(n for n in chain.nodes if n.mandate_id == child.mandate_id)
    assert child_node.in_bounds is True
    assert len(chain.edges) == 1
    assert chain.edges[0].child_mandate_id == child.mandate_id
    assert chain.edges[0].parent_mandate_id == parent.mandate_id
    assert chain.edges[0].violates is False


def test_over_scoped_child_reports_false_with_a_violating_edge() -> None:
    """A child whose ceiling exceeds its parent's must report in_bounds False and a named reason."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("1000")))
    child = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(max_amount=Decimal("5000")),
        expires_at=parent.expires_at,
    )
    store = MutableMandateChainStore()
    store.add(parent)
    store.add(child)

    chain = build_delegation_chain(child, store)

    child_node = next(n for n in chain.nodes if n.mandate_id == child.mandate_id)
    assert child_node.in_bounds is False
    assert "scope_amount_exceeds_parent" in child_node.reasons
    assert chain.edges[0].violates is True


def test_sibling_cap_accounts_for_other_children_of_the_same_parent() -> None:
    """A second sibling exceeding the parent's remaining budget must be flagged, the first left alone."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("1000")))
    sibling_a = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(max_amount=Decimal("700")),
        expires_at=parent.expires_at,
    )
    sibling_b = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(max_amount=Decimal("600")),
        expires_at=parent.expires_at,
    )
    store = MutableMandateChainStore()
    store.add(parent)
    store.add(sibling_a)
    store.add(sibling_b)

    chain_a = build_delegation_chain(sibling_a, store)
    chain_b = build_delegation_chain(sibling_b, store)

    node_a = next(n for n in chain_a.nodes if n.mandate_id == sibling_a.mandate_id)
    node_b = next(n for n in chain_b.nodes if n.mandate_id == sibling_b.mandate_id)
    assert node_a.in_bounds is True
    assert node_b.in_bounds is False
    assert "sibling_cap_exceeds_parent_remaining" in node_b.reasons


def test_unresolvable_parent_reports_honestly_with_no_containment_verdict() -> None:
    """A mandate whose declared parent is unknown to the store must report unresolvable, not a guess."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=build_mandate(private_key).mandate_id)
    store = MutableMandateChainStore()
    store.add(child)

    chain = build_delegation_chain(child, store)

    assert len(chain.nodes) == 1
    assert chain.nodes[0].unresolvable_parent is True
    assert chain.nodes[0].in_bounds is None
    assert chain.chain_broken
    assert chain.chain_broken_reason == "unresolvable_ancestor"


def test_multi_level_chain_reports_each_ancestors_own_verdict() -> None:
    """A three-level chain must report a containment verdict for each non-root link independently."""
    private_key, _ = generate_keypair()
    grandparent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("5000")))
    parent = build_mandate(
        private_key,
        parent_mandate_id=grandparent.mandate_id,
        scope=build_scope(max_amount=Decimal("2000")),
        expires_at=grandparent.expires_at,
    )
    child = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=build_scope(max_amount=Decimal("1000")),
        expires_at=parent.expires_at,
    )
    store = MutableMandateChainStore()
    store.add(grandparent)
    store.add(parent)
    store.add(child)

    chain = build_delegation_chain(child, store)

    assert [n.mandate_id for n in chain.nodes] == [child.mandate_id, parent.mandate_id, grandparent.mandate_id]
    assert chain.nodes[0].in_bounds is True  # child vs parent
    assert chain.nodes[1].in_bounds is True  # parent vs grandparent
    assert chain.nodes[2].is_root
    assert len(chain.edges) == 2
    assert not chain.chain_broken
