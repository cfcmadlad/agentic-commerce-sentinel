"""Tests for `counterfactual.deterministic`: Layers 1, 2, and 2.5's minimal-edit explanations.

Every feasible case asserts `solver_verified` is True (the module's own
internal Z3 cross-check passed) in addition to checking the suggested
values -- if a future edit to `formal/model.py` or this module ever drifted
out of sync, `AssertionError` would fire before a test even reached its own
assertions, which every test here exercises implicitly.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

from containment.chain import AncestorChainResolution
from counterfactual.deterministic import (
    FieldEdit,
    containment_counterfactual,
    scope_counterfactual,
    verification_counterfactual,
)
from mandate.schema import Mandate, SignedMandate
from mandate.signing import generate_keypair, sign_mandate
from mandate.verification import AgentKeyRegistry, KeyRevocationReason, MandateLedger
from tests.factories import REFERENCE_NOW, build_mandate, build_scope, build_session_trace

_ZERO = Decimal("0")


def _registry_and_signed(**mandate_overrides: object) -> tuple[AgentKeyRegistry, MandateLedger, SignedMandate]:
    """Builds a registered, signed mandate plus a fresh registry and ledger.

    Args:
        **mandate_overrides: Overrides passed through to `build_mandate`.

    Returns:
        (registry, ledger, signed_mandate).
    """
    private_key, public_key = generate_keypair()
    mandate = build_mandate(private_key, **mandate_overrides)  # type: ignore[arg-type]
    signed = sign_mandate(mandate, private_key)
    registry = AgentKeyRegistry()
    registry.register(mandate.agent_id, mandate.signer_key_id, public_key)
    return registry, MandateLedger(), signed


# --- Layer 1: verification -------------------------------------------------


def test_verification_already_valid_returns_none() -> None:
    """A mandate that already verifies has nothing to explain."""
    registry, ledger, signed = _registry_and_signed()
    result = verification_counterfactual(signed, registry, ledger, now=REFERENCE_NOW)
    assert result is None


def test_verification_unregistered_key_flips_to_registered() -> None:
    """An unknown signer's counterfactual is a boolean flip on key registration."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)
    result = verification_counterfactual(signed, AgentKeyRegistry(), MandateLedger(), now=REFERENCE_NOW)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    assert any(edit.field == "has_registered_key" and edit.suggested_value == "true" for edit in result.edits)


def test_verification_revoked_key_is_infeasible() -> None:
    """A revoked signing key has no field-level fix: no mandate edit un-revokes a key."""
    registry, ledger, signed = _registry_and_signed()
    registry.revoke(
        signed.mandate.agent_id,
        signed.mandate.signer_key_id,
        reason=KeyRevocationReason.COMPROMISED,
        revoked_by="security-team",
        at=REFERENCE_NOW,
    )
    result = verification_counterfactual(signed, registry, ledger, now=REFERENCE_NOW)
    assert result is not None
    assert not result.feasible
    assert result.edits == ()
    assert not result.solver_verified


def test_verification_revocation_check_uses_its_own_instant_not_now() -> None:
    """A caller-supplied `now` for the mandate's own time window must not also decide revocation."""
    registry, ledger, signed = _registry_and_signed()
    revoked_at = REFERENCE_NOW + timedelta(minutes=1)
    registry.revoke(
        signed.mandate.agent_id,
        signed.mandate.signer_key_id,
        reason=KeyRevocationReason.COMPROMISED,
        revoked_by="security-team",
        at=revoked_at,
    )
    # now is before the revocation and would otherwise report "already valid"; a real decision
    # instant after the revocation must still catch it via the separate revocation_checked_at.
    result = verification_counterfactual(
        signed, registry, ledger, now=REFERENCE_NOW, revocation_checked_at=revoked_at + timedelta(minutes=1)
    )
    assert result is not None
    assert not result.feasible


def test_verification_expired_mandate_suggests_later_expiry() -> None:
    """An expired mandate's counterfactual pushes expires_at to at least `now`."""
    later_now = REFERENCE_NOW + timedelta(days=30)
    registry, ledger, signed = _registry_and_signed()
    result = verification_counterfactual(signed, registry, ledger, now=later_now)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    expiry_edits = [e for e in result.edits if e.field == "expires_at"]
    assert len(expiry_edits) == 1
    assert expiry_edits[0].suggested_value == later_now.isoformat()


def test_verification_budget_exhausted_suggests_higher_count() -> None:
    """A spent mandate's counterfactual raises max_transaction_count past usage."""
    registry, _, signed = _registry_and_signed(scope=build_scope(max_transaction_count=1))
    ledger = MandateLedger()
    ledger.record_usage(signed.mandate.mandate_id)
    result = verification_counterfactual(signed, registry, ledger, now=REFERENCE_NOW)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    budget_edits = [e for e in result.edits if e.field == "scope.max_transaction_count"]
    assert budget_edits == [
        FieldEdit("scope.max_transaction_count", "1", "2")
    ]


def test_verification_multiple_failures_edits_each_independently() -> None:
    """A mandate both expired and budget-exhausted gets one edit per failure."""
    later_now = REFERENCE_NOW + timedelta(days=30)
    registry, _, signed = _registry_and_signed(scope=build_scope(max_transaction_count=1))
    ledger = MandateLedger()
    ledger.record_usage(signed.mandate.mandate_id)
    result = verification_counterfactual(signed, registry, ledger, now=later_now)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    fields = {e.field for e in result.edits}
    assert fields == {"expires_at", "scope.valid_until", "scope.max_transaction_count"}


# --- Layer 2: scope ----------------------------------------------------------


def test_scope_in_scope_returns_none() -> None:
    """An in-scope session has nothing to explain."""
    trace = build_session_trace()
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, mandate_id=trace.mandate_id, agent_id=trace.agent_id, user_id=trace.user_id)
    signed = sign_mandate(mandate, private_key)
    assert scope_counterfactual(trace, signed) is None


def test_scope_no_mandate_presented_is_infeasible() -> None:
    """A session with no mandate at all has no scope to compare against."""
    trace = build_session_trace(mandate_id=None)
    result = scope_counterfactual(trace, None)
    assert result is not None
    assert not result.feasible
    assert result.edits == ()
    assert not result.solver_verified


def test_scope_amount_over_ceiling_suggests_the_ceiling() -> None:
    """An over-ceiling transaction's counterfactual amount is the mandate's own ceiling."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=build_scope(max_amount=Decimal("2000.00")))
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        amount=Decimal("8000.00"),
    )
    result = scope_counterfactual(trace, signed)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    amount_edits = [e for e in result.edits if e.field == "trace.amount"]
    assert amount_edits == [FieldEdit("trace.amount", "8000.00", "2000.00")]


def test_scope_merchant_category_not_allowed_suggests_allowed_set() -> None:
    """A disallowed category's counterfactual names the mandate's own allowed set."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(
        private_key, scope=build_scope(allowed_merchant_categories=frozenset({"grocery"}))
    )
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        merchant_category="electronics",
        item_category="packaged_food",
    )
    result = scope_counterfactual(trace, signed)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    category_edits = [e for e in result.edits if e.field == "trace.merchant_category"]
    assert len(category_edits) == 1
    assert "grocery" in category_edits[0].suggested_value


def test_scope_outside_time_window_before_suggests_valid_from() -> None:
    """A too-early session's counterfactual timestamp is the window's own start."""
    scope = build_scope(valid_from=REFERENCE_NOW, valid_until=REFERENCE_NOW + timedelta(days=6))
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=scope)
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        started_at=REFERENCE_NOW - timedelta(days=1),
        completed_at=REFERENCE_NOW - timedelta(days=1),
    )
    result = scope_counterfactual(trace, signed)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    time_edits = [e for e in result.edits if e.field == "trace.started_at"]
    assert time_edits[0].suggested_value == scope.valid_from.isoformat()


def test_scope_merchant_not_allowed_with_restriction_suggests_allowlist() -> None:
    """A merchant outside an explicit allowlist gets that allowlist as the suggestion."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=frozenset({"bigbasket"})))
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        merchant_id="blinkit",
    )
    result = scope_counterfactual(trace, signed)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    merchant_edits = [e for e in result.edits if e.field == "trace.merchant_id"]
    assert "bigbasket" in merchant_edits[0].suggested_value


# --- Layer 2.5: containment (library-level) ---------------------------------


def _resolved(parent: Mandate) -> AncestorChainResolution:
    """Wraps a resolved parent mandate as an intact chain resolution.

    Args:
        parent: The immediate parent mandate.

    Returns:
        A non-broken resolution.
    """
    return AncestorChainResolution(
        immediate_parent=parent, ancestors=(parent,), cycle_detected=False, depth_exceeded=False, unresolvable=False
    )


def _broken_chain() -> AncestorChainResolution:
    """Builds a chain resolution broken by a detected cycle.

    Returns:
        A broken resolution.
    """
    return AncestorChainResolution(
        immediate_parent=None, ancestors=(), cycle_detected=True, depth_exceeded=False, unresolvable=False
    )


def test_containment_in_bounds_returns_none() -> None:
    """A child identical to its parent's scope has nothing to explain."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=parent.scope, expires_at=parent.expires_at
    )
    assert containment_counterfactual(child, _resolved(parent), _ZERO) is None


def test_containment_broken_chain_is_infeasible() -> None:
    """A cyclic chain has no field-level fix."""
    private_key, _ = generate_keypair()
    child = build_mandate(private_key, parent_mandate_id=uuid4())
    result = containment_counterfactual(child, _broken_chain(), _ZERO)
    assert result is not None
    assert not result.feasible
    assert result.edits == ()
    assert not result.solver_verified
    assert "cycle_detected" in result.explanation


def test_containment_amount_exceeds_parent_suggests_parent_ceiling() -> None:
    """A child ceiling above its parent's gets the parent's own ceiling as the suggestion."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("2000.00")))
    child_scope = build_scope(max_amount=Decimal("5000.00"))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope, expires_at=parent.expires_at
    )
    result = containment_counterfactual(child, _resolved(parent), _ZERO)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    amount_edits = [e for e in result.edits if e.field == "scope.max_amount"]
    assert amount_edits == [FieldEdit("scope.max_amount", "5000.00", "2000.00")]


def test_containment_sibling_cap_accounts_for_committed_total() -> None:
    """A child that fits the parent's own ceiling but not its remaining budget is bounded by the remainder."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(max_amount=Decimal("2000.00")))
    child_scope = build_scope(max_amount=Decimal("1500.00"))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope, expires_at=parent.expires_at
    )
    result = containment_counterfactual(child, _resolved(parent), Decimal("1000.00"))
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    amount_edits = [e for e in result.edits if e.field == "scope.max_amount"]
    assert amount_edits == [FieldEdit("scope.max_amount", "1500.00", "1000.00")]


def test_containment_category_no_overlap_is_infeasible() -> None:
    """A child category set disjoint from the parent's has no trim to suggest."""
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key, scope=build_scope(allowed_merchant_categories=frozenset({"grocery"})))
    child_scope = build_scope(
        allowed_merchant_categories=frozenset({"electronics"}),
        allowed_item_categories=frozenset({"laptop"}),
    )
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope, expires_at=parent.expires_at
    )
    result = containment_counterfactual(child, _resolved(parent), _ZERO)
    assert result is not None
    assert not result.feasible
    assert result.edits == ()
    assert not result.solver_verified


def test_containment_category_partial_overlap_trims_to_intersection() -> None:
    """A child category set that partially overlaps its parent's is trimmed, not replaced."""
    private_key, _ = generate_keypair()
    parent = build_mandate(
        private_key, scope=build_scope(allowed_merchant_categories=frozenset({"grocery", "fashion_apparel"}))
    )
    child_scope = build_scope(allowed_merchant_categories=frozenset({"grocery", "electronics"}))
    child = build_mandate(
        private_key, parent_mandate_id=parent.mandate_id, scope=child_scope, expires_at=parent.expires_at
    )
    result = containment_counterfactual(child, _resolved(parent), _ZERO)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    category_edits = [e for e in result.edits if e.field == "scope.allowed_merchant_categories"]
    assert len(category_edits) == 1
    assert "grocery" in category_edits[0].suggested_value
    assert "electronics" not in category_edits[0].suggested_value


def test_containment_expiry_exceeds_parent_suggests_parent_expiry() -> None:
    """A child expiring after its parent gets the parent's own expiry as the suggestion.

    Only the child's own `expires_at` is pushed out here -- its scope stays
    identical to the parent's, so `SCOPE_WINDOW_NOT_SUBSET` does not also
    fire and this test isolates `EXPIRY_EXCEEDS_PARENT` alone.
    """
    private_key, _ = generate_keypair()
    parent = build_mandate(private_key)
    child = build_mandate(
        private_key,
        parent_mandate_id=parent.mandate_id,
        scope=parent.scope,
        expires_at=parent.expires_at + timedelta(days=10),
    )
    result = containment_counterfactual(child, _resolved(parent), _ZERO)
    assert result is not None
    assert result.feasible
    assert result.solver_verified
    expiry_edits = [e for e in result.edits if e.field == "expires_at"]
    assert expiry_edits[0].suggested_value == parent.expires_at.isoformat()
