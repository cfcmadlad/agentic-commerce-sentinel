"""Tests for `containment.store.build_store_from_signed_mandates`."""

from __future__ import annotations

from containment.store import MutableMandateChainStore, build_store_from_signed_mandates
from mandate.signing import generate_keypair, sign_mandate
from tests.factories import build_mandate


def test_indexes_every_distinct_mandate() -> None:
    """Every mandate with a unique ID must be resolvable afterward."""
    private_key, _ = generate_keypair()
    mandate_a = build_mandate(private_key)
    mandate_b = build_mandate(private_key)
    signed_a = sign_mandate(mandate_a, private_key)
    signed_b = sign_mandate(mandate_b, private_key)

    store = build_store_from_signed_mandates([signed_a, signed_b])

    assert store.get(mandate_a.mandate_id) == mandate_a
    assert store.get(mandate_b.mandate_id) == mandate_b


def test_repeated_identical_mandate_resolves_normally() -> None:
    """The same mandate presented across multiple sessions is not a conflict."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)

    store = build_store_from_signed_mandates([signed, signed, signed])

    assert store.get(mandate.mandate_id) == mandate


def test_conflicting_content_for_the_same_id_is_excluded_not_arbitrarily_resolved() -> None:
    """Two different mandates sharing an ID must both become unresolvable, not one silently win.

    This is the honest response to an upstream ID collision (or any other
    source of two conflicting records for one ID): resolving to either
    version arbitrarily would let a containment decision depend on
    iteration order rather than trustworthy data.
    """
    private_key, _ = generate_keypair()
    shared_id = build_mandate(private_key).mandate_id
    version_one = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-one")
    version_two = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-two")
    signed_one = sign_mandate(version_one, private_key)
    signed_two = sign_mandate(version_two, private_key)

    store = build_store_from_signed_mandates([signed_one, signed_two])

    assert store.get(shared_id) is None


def test_mutable_store_resolves_added_mandates() -> None:
    """A mandate added incrementally must be resolvable afterward."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    store = MutableMandateChainStore()
    store.add(mandate)
    assert store.get(mandate.mandate_id) == mandate


def test_mutable_store_repeated_identical_add_is_not_a_conflict() -> None:
    """Adding the same mandate content twice (e.g. re-presented in a later session) is fine."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    store = MutableMandateChainStore()
    store.add(mandate)
    store.add(mandate)
    assert store.get(mandate.mandate_id) == mandate


def test_mutable_store_excludes_conflicting_content_for_the_same_id() -> None:
    """Two different mandates sharing an ID must both become unresolvable, matching the bulk builder's rule."""
    private_key, _ = generate_keypair()
    shared_id = build_mandate(private_key).mandate_id
    version_one = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-one")
    version_two = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-two")
    store = MutableMandateChainStore()
    store.add(version_one)
    store.add(version_two)
    assert store.get(shared_id) is None


def test_mutable_store_stays_excluded_after_a_conflict_even_if_the_original_is_re_added() -> None:
    """Once an ID is flagged conflicting, it stays unresolvable rather than flip-flopping."""
    private_key, _ = generate_keypair()
    shared_id = build_mandate(private_key).mandate_id
    version_one = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-one")
    version_two = build_mandate(private_key, mandate_id=shared_id, agent_id="agent-two")
    store = MutableMandateChainStore()
    store.add(version_one)
    store.add(version_two)
    store.add(version_one)
    assert store.get(shared_id) is None


def test_mutable_store_all_mandates_lists_everything_recorded() -> None:
    """all_mandates must return every distinct mandate added, for sibling/descendant scans."""
    private_key, _ = generate_keypair()
    mandate_a = build_mandate(private_key)
    mandate_b = build_mandate(private_key)
    store = MutableMandateChainStore()
    store.add(mandate_a)
    store.add(mandate_b)
    assert set(store.all_mandates()) == {mandate_a, mandate_b}
