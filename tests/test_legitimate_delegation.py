"""Tests for the legitimate delegation-chain generator.

This is the corpus that makes containment's "zero false positives on
legitimate traffic" claim a real, falsifiable measurement instead of a
structural non-event -- see `generator/attacks/legitimate_delegation.py`'s
own module docstring and `docs/adr/0004-delegation-chain-containment.md`'s
addendum. The property that matters most is the one in
`test_zero_false_positives_against_the_real_containment_gate`: every
session this generator produces, decided against the real, stateful
`ContainmentGate` in isolation, comes back in bounds.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

import pytest

from generator.attacks.common import build_world
from generator.attacks.legitimate_delegation import (
    VARIANT_NARROWER_NO_ALLOWLIST,
    VARIANT_NARROWER_WITH_ALLOWLIST,
    VARIANT_SIBLING_FANOUT,
    generate_legitimate_delegation_sessions,
)
from generator.legitimate import generate_legitimate_sessions
from mandate.signing import signature_is_valid
from mandate.verification import verify_mandate

LEGIT_N_SESSIONS = 1000
LEGIT_SEED = 4242
N_DELEGATIONS = 300
DELEGATION_SEED = 2026

_LEGIT = generate_legitimate_sessions(LEGIT_N_SESSIONS, seed=LEGIT_SEED)
_WORLD = build_world(_LEGIT)
_BATCH = generate_legitimate_delegation_sessions(_WORLD, N_DELEGATIONS, seed=DELEGATION_SEED)


def test_produces_at_least_the_requested_count() -> None:
    """Sibling-fanout groups can push the realized count above the target."""
    assert len(_BATCH) >= N_DELEGATIONS


def test_every_session_is_labeled_legitimate() -> None:
    """Not an attack -- `is_attack=False`, `AttackClass.LEGITIMATE`."""
    for item in _BATCH:
        assert item.labeled.is_attack is False


def test_reproducible_for_the_same_seed() -> None:
    """The same (world, n, seed) triple must produce byte-identical output."""
    second = generate_legitimate_delegation_sessions(_WORLD, N_DELEGATIONS, seed=DELEGATION_SEED)
    assert [item.signed_mandate.mandate.mandate_id for item in _BATCH] == [
        item.signed_mandate.mandate.mandate_id for item in second
    ]


def test_every_child_mandate_is_genuinely_signed() -> None:
    """Not a structural shortcut -- a real Ed25519 signature over the real mandate bytes."""
    for item in _BATCH:
        signed = item.signed_mandate
        public_key = _LEGIT.registry.get(signed.mandate.agent_id, signed.mandate.signer_key_id)
        assert public_key is not None
        assert signature_is_valid(signed, public_key)


def test_every_child_verifies_against_the_real_registry() -> None:
    """Layer 1 itself must accept every mandate this generator produces."""
    registry = _LEGIT.registry
    ledger = _LEGIT.ledger
    for item in _BATCH:
        signed = item.signed_mandate
        result = verify_mandate(signed, registry, ledger, now=signed.mandate.issued_at)
        assert result.valid, result.reasons


def test_every_child_is_a_genuine_scope_subset_of_its_parent() -> None:
    """Every dimension `containment/engine.py::_check_scope_subset` checks must narrow, never widen."""
    by_id = _LEGIT.signed_mandates
    for item in _BATCH:
        child = item.signed_mandate.mandate
        assert child.parent_mandate_id is not None
        parent = by_id[child.parent_mandate_id]
        assert child.scope.max_amount <= parent.mandate.scope.max_amount
        assert child.scope.currency == parent.mandate.scope.currency
        assert child.scope.allowed_merchant_categories <= parent.mandate.scope.allowed_merchant_categories
        assert child.scope.allowed_item_categories <= parent.mandate.scope.allowed_item_categories
        assert parent.mandate.scope.valid_from <= child.scope.valid_from
        assert child.scope.valid_until <= parent.mandate.scope.valid_until
        assert child.scope.max_transaction_count <= parent.mandate.scope.max_transaction_count
        assert child.expires_at <= parent.mandate.expires_at


def test_narrower_with_allowlist_children_keep_a_real_explicit_allowlist() -> None:
    """This variant is only meaningful if the parent's allowlist is non-trivial."""
    with_allowlist = [item for item in _BATCH if item.variant == VARIANT_NARROWER_WITH_ALLOWLIST]
    assert with_allowlist
    for item in with_allowlist:
        assert item.signed_mandate.mandate.scope.allowed_merchant_ids is not None


def test_narrower_no_allowlist_children_have_no_allowlist_on_either_side() -> None:
    """The exact case a naive containment check might mistake for widening."""
    no_allowlist = [item for item in _BATCH if item.variant == VARIANT_NARROWER_NO_ALLOWLIST]
    assert no_allowlist
    by_id = _LEGIT.signed_mandates
    for item in no_allowlist:
        assert item.signed_mandate.mandate.scope.allowed_merchant_ids is None
        parent_id = item.signed_mandate.mandate.parent_mandate_id
        assert parent_id is not None
        parent = by_id[parent_id]
        assert parent.mandate.scope.allowed_merchant_ids is None


def test_sibling_fanout_group_stays_comfortably_under_the_parent_cap() -> None:
    """Unlike the attack variant of the same shape, this group must never approach the cap."""
    siblings = [item for item in _BATCH if item.variant == VARIANT_SIBLING_FANOUT]
    assert siblings
    by_parent: dict[UUID, list[Decimal]] = {}
    by_id = _LEGIT.signed_mandates
    for item in siblings:
        parent_id = item.signed_mandate.mandate.parent_mandate_id
        assert parent_id is not None
        by_parent.setdefault(parent_id, []).append(item.signed_mandate.mandate.scope.max_amount)
    for parent_id, amounts in by_parent.items():
        parent = by_id[parent_id]
        assert sum(amounts) <= parent.mandate.scope.max_amount


def test_zero_false_positives_against_the_real_containment_gate() -> None:
    """The headline claim: every session here, decided in isolation, is genuinely in bounds.

    "In isolation" matters: this corpus is scored on its own, not mixed with
    the mandate-chaining attack corpus, which independently draws from the
    same eligible-parent pool and can (via its own, already-disclosed
    `fanout_structuring` gap -- an accepted "first sibling" consuming real
    parent budget) cause a later legitimate sibling sharing that same parent
    to be correctly rejected too. That is a real, disclosed side effect of
    an already-known gap, not a containment bug -- see docs/adr/0004's
    addendum -- and is exactly why this test measures the legitimate
    generator's own self-consistency in isolation, where the claim is
    unconditional.
    """
    from containment.gate import ContainmentGate
    from containment.store import build_store_from_signed_mandates

    all_signed = list(_LEGIT.signed_mandates.values()) + [item.signed_mandate for item in _BATCH]
    store = build_store_from_signed_mandates(all_signed)
    gate = ContainmentGate(store)

    false_positives = []
    for item in sorted(_BATCH, key=lambda item: item.labeled.trace.started_at):
        result = gate.decide(item.signed_mandate.mandate)
        if not result.in_bounds:
            false_positives.append((item.variant, result.reasons))

    assert false_positives == []


def test_rejects_nonpositive_n_sessions() -> None:
    """A caller asking for zero or fewer sessions gets a clear error, not an empty result."""
    with pytest.raises(ValueError, match="positive"):
        generate_legitimate_delegation_sessions(_WORLD, 0, seed=DELEGATION_SEED)
