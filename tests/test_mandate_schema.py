"""Tests for `mandate.schema`: the invariants a mandate must satisfy to exist."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from mandate.signing import generate_keypair
from tests.factories import REFERENCE_NOW, build_mandate, build_scope


class TestMandateScope:
    """Validation rules for `MandateScope`."""

    def test_valid_scope_constructs(self) -> None:
        """A scope built with the factory defaults should construct without error."""
        scope = build_scope()
        assert scope.max_amount == Decimal("2000.00")

    def test_rejects_inverted_time_window(self) -> None:
        """valid_until before valid_from must fail loudly, not silently invert."""
        with pytest.raises(ValidationError, match="valid_until precedes valid_from"):
            build_scope(
                valid_from=REFERENCE_NOW,
                valid_until=REFERENCE_NOW - timedelta(days=1),
            )

    def test_rejects_empty_merchant_categories(self) -> None:
        """An unrestricted mandate (no category) is not a scoped mandate."""
        with pytest.raises(ValidationError, match="allowed_merchant_categories"):
            build_scope(allowed_merchant_categories=frozenset())

    def test_rejects_empty_item_categories(self) -> None:
        """Same rule for item categories."""
        with pytest.raises(ValidationError, match="allowed_item_categories"):
            build_scope(allowed_item_categories=frozenset())

    def test_rejects_non_positive_amount(self) -> None:
        """A zero or negative ceiling authorizes nothing meaningful; reject it."""
        with pytest.raises(ValidationError):
            build_scope(max_amount=Decimal("0"))

    def test_rejects_zero_transaction_count(self) -> None:
        """A mandate that authorizes zero transactions should not be constructible."""
        with pytest.raises(ValidationError):
            build_scope(max_transaction_count=0)


class TestMandate:
    """Validation rules for `Mandate`."""

    def test_valid_mandate_constructs(self) -> None:
        """A mandate built with factory defaults should construct without error."""
        private_key, _ = generate_keypair()
        mandate = build_mandate(private_key)
        assert mandate.parent_mandate_id is None

    def test_rejects_expiry_before_issuance(self) -> None:
        """expires_at at or before issued_at must fail loudly."""
        private_key, _ = generate_keypair()
        with pytest.raises(ValidationError, match="expires_at must be strictly after"):
            build_mandate(
                private_key,
                issued_at=REFERENCE_NOW,
                expires_at=REFERENCE_NOW - timedelta(minutes=1),
            )

    def test_rejects_scope_window_exceeding_mandate_expiry(self) -> None:
        """A transaction window that outlives the mandate's own TTL is invalid."""
        private_key, _ = generate_keypair()
        scope = build_scope(valid_until=REFERENCE_NOW + timedelta(days=30))
        with pytest.raises(ValidationError, match="cannot exceed"):
            build_mandate(
                private_key,
                scope=scope,
                expires_at=REFERENCE_NOW + timedelta(days=7),
            )

    def test_rejects_short_nonce(self) -> None:
        """Nonces below the minimum length are rejected to keep replay-resistance meaningful."""
        private_key, _ = generate_keypair()
        with pytest.raises(ValidationError):
            build_mandate(private_key, nonce="short")

    def test_parent_mandate_id_round_trips(self) -> None:
        """A chained mandate should carry its parent's ID through unchanged."""
        private_key, _ = generate_keypair()
        parent_id = build_mandate(private_key).mandate_id
        child = build_mandate(private_key, parent_mandate_id=parent_id)
        assert child.parent_mandate_id == parent_id

    def test_mandate_is_frozen(self) -> None:
        """Mutating a constructed mandate must fail: it would invalidate the signature silently."""
        private_key, _ = generate_keypair()
        mandate = build_mandate(private_key)
        with pytest.raises(ValidationError):
            mandate.agent_id = "someone-else"