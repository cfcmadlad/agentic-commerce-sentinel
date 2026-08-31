"""Tests for `agent.tools`: the three real tools and their guardrails.

`checkout` is exercised against a real, fully fitted `service.state.AppState`
(module-scoped, built once -- fitting the pipeline is the expensive part,
same reasoning `tests/test_service.py`'s own session-scoped `client` fixture
already documents) so these tests assert on real `service.main.decide` and
real `containment` verdicts, never a mocked decision.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.catalog import CATALOG, CatalogItem, find_item
from agent.tools import (
    STANDARD_EVENT_GAPS,
    ShopperToolContext,
    ToolValidationError,
    checkout,
    propose_purchase,
    search_catalog,
)
from mandate.schema import Mandate, MandateScope, SignedMandate
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes, sign_mandate
from service.state import AppState, build_app_state

ANCHOR = datetime(2026, 5, 1, 9, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def state(tmp_path_factory: pytest.TempPathFactory) -> AppState:
    """A real, fully fitted `AppState`, built once for this module's tests."""
    tmp_dir = tmp_path_factory.mktemp("agent-tools-state")
    return build_app_state(audit_log_path=tmp_dir / "audit.jsonl", escalation_log_path=tmp_dir / "escalations.jsonl")


def _stable_uuid(label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"test-agent-tools:{label}")


def _register_and_sign(
    state: AppState,
    label: str,
    *,
    max_amount: Decimal,
    merchant_categories: frozenset[str],
    item_categories: frozenset[str],
    parent_mandate_id: UUID | None = None,
) -> tuple[str, SignedMandate, Ed25519PrivateKey]:
    """Builds a fresh, registered, signed mandate for one test.

    Returns:
        `(agent_id, signed_mandate, private_key)`.
    """
    seed_bytes = hashlib.sha256(f"test-agent-tools-{label}".encode("utf-8")).digest()
    private_key, public_key = keypair_from_seed_bytes(seed_bytes)
    agent_id = f"shopper-agent-test-{label}"
    key_id = key_id_for_public_key(public_key)
    state.registry.register(agent_id, key_id, public_key)

    mandate = Mandate(
        mandate_id=_stable_uuid(f"mandate:{label}"),
        agent_id=agent_id,
        user_id=f"user-{label}",
        parent_mandate_id=parent_mandate_id,
        issued_at=ANCHOR - timedelta(hours=2),
        expires_at=ANCHOR + timedelta(hours=7),
        nonce=_stable_uuid(f"nonce:{label}").hex,
        scope=MandateScope(
            max_amount=max_amount,
            currency="INR",
            allowed_merchant_categories=merchant_categories,
            allowed_item_categories=item_categories,
            valid_from=ANCHOR - timedelta(hours=2),
            valid_until=ANCHOR + timedelta(hours=6),
            max_transaction_count=10,
        ),
        signer_key_id=key_id,
    )
    return agent_id, sign_mandate(mandate, private_key), private_key


def _ctx(
    state: AppState, agent_id: str, signed_mandate: SignedMandate, catalog: tuple[CatalogItem, ...]
) -> ShopperToolContext:
    return ShopperToolContext(
        agent_id=agent_id,
        user_id=signed_mandate.mandate.user_id,
        signed_mandate=signed_mandate,
        app_state=state,
        session_started_at=ANCHOR,
        event_gaps=STANDARD_EVENT_GAPS,
        include_browse=True,
        catalog=catalog,
    )


def test_propose_purchase_rejects_unknown_item(state: AppState) -> None:
    """An item ID with no catalog entry is rejected, not silently treated as zero-cost."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "unknown-item",
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    ctx = _ctx(state, agent_id, signed, CATALOG)
    with pytest.raises(ToolValidationError, match="unknown catalog item"):
        propose_purchase(ctx, "does-not-exist", 1)


def test_propose_purchase_rejects_item_outside_scenario_catalog(state: AppState) -> None:
    """An item that exists globally but is not in this scenario's catalog subset is rejected."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "outside-subset",
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    narrow_catalog = tuple(item for item in CATALOG if item.item_id == "earbuds-wireless-01")
    ctx = _ctx(state, agent_id, signed, narrow_catalog)
    with pytest.raises(ToolValidationError, match="unknown catalog item"):
        propose_purchase(ctx, "laptop-pro-01", 1)


@pytest.mark.parametrize("quantity", [0, -1, 21, 1000])
def test_propose_purchase_rejects_out_of_range_quantity(state: AppState, quantity: int) -> None:
    """A non-positive or excessive quantity is rejected."""
    agent_id, signed, _ = _register_and_sign(
        state,
        f"bad-qty-{quantity}",
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    ctx = _ctx(state, agent_id, signed, CATALOG)
    with pytest.raises(ToolValidationError, match="quantity"):
        propose_purchase(ctx, "earbuds-wireless-01", quantity)


def test_propose_purchase_computes_total_amount_from_catalog_price(state: AppState) -> None:
    """`total_amount` is always `catalog price * quantity` -- never trusted from any external input."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "amount-calc",
        max_amount=Decimal("10000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    ctx = _ctx(state, agent_id, signed, CATALOG)
    item = find_item("earbuds-wireless-01")
    assert item is not None
    proposal = propose_purchase(ctx, "earbuds-wireless-01", 3)
    assert proposal.total_amount == item.price * 3


def test_search_catalog_only_returns_scenario_subset(state: AppState) -> None:
    """`search_catalog` never surfaces an item outside `ctx.catalog`, even if the query matches it globally."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "search-subset",
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    narrow_catalog = tuple(item for item in CATALOG if item.item_id == "earbuds-wireless-01")
    ctx = _ctx(state, agent_id, signed, narrow_catalog)
    results = search_catalog(ctx, "")
    assert results == narrow_catalog
    assert search_catalog(ctx, "laptop") == ()


def test_checkout_allows_in_scope_purchase(state: AppState) -> None:
    """A checkout that fits the mandate's scope is really allowed by `decide()`."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "checkout-allowed",
        max_amount=Decimal("5000"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    ctx = _ctx(state, agent_id, signed, CATALOG)
    verdict = checkout(ctx, "earbuds-wireless-01", 1)
    assert verdict.blocked is False
    assert verdict.source == "allowed"
    assert verdict.containment_in_bounds is None  # root mandate: nothing to check containment against


def test_checkout_blocks_over_ceiling_purchase(state: AppState) -> None:
    """A checkout over the mandate's ceiling is really blocked by Layer 2, deterministically."""
    agent_id, signed, _ = _register_and_sign(
        state,
        "checkout-blocked",
        max_amount=Decimal("2500"),
        merchant_categories=frozenset({"electronics"}),
        item_categories=frozenset({"gadgets"}),
    )
    ctx = _ctx(state, agent_id, signed, CATALOG)
    verdict = checkout(ctx, "laptop-pro-01", 1)
    assert verdict.blocked is True
    assert verdict.source == "rules"
    assert verdict.escalation_opened is False


def test_checkout_child_mandate_containment_violation_opens_escalation(state: AppState) -> None:
    """A budget-inflated child mandate is allowed by decide() but caught by real containment, opening an escalation."""
    parent_agent, signed_parent, parent_private_key = _register_and_sign(
        state,
        "containment-parent",
        max_amount=Decimal("1000"),
        merchant_categories=frozenset({"grocery"}),
        item_categories=frozenset({"packaged_food"}),
    )
    # Establish the parent in the mandate store first, the same way a real
    # prior use would -- checkout() below resolves the child's ancestor
    # chain against whatever the store already knows.
    parent_ctx = _ctx(state, parent_agent, signed_parent, CATALOG)
    parent_verdict = checkout(parent_ctx, "rice-sack-5kg-01", 1)
    assert parent_verdict.blocked is False

    child_mandate = Mandate(
        mandate_id=_stable_uuid("mandate:containment-child"),
        agent_id=parent_agent,
        user_id=signed_parent.mandate.user_id,
        parent_mandate_id=signed_parent.mandate.mandate_id,
        issued_at=ANCHOR - timedelta(hours=1),
        expires_at=ANCHOR + timedelta(hours=7),
        nonce=_stable_uuid("nonce:containment-child").hex,
        scope=MandateScope(
            max_amount=Decimal("5000"),  # exceeds the parent's 1000 -- budget_escalation
            currency="INR",
            allowed_merchant_categories=frozenset({"grocery"}),
            allowed_item_categories=frozenset({"packaged_food"}),
            valid_from=ANCHOR - timedelta(hours=1),
            valid_until=ANCHOR + timedelta(hours=6),
            max_transaction_count=10,
        ),
        signer_key_id=signed_parent.mandate.signer_key_id,
    )
    signed_child = sign_mandate(child_mandate, parent_private_key)

    child_ctx = _ctx(state, parent_agent, signed_child, CATALOG)
    verdict = checkout(child_ctx, "rice-sack-5kg-01", 1)

    assert verdict.blocked is False  # Layers 1-3 allow it: fits the child's own ceiling
    assert verdict.containment_in_bounds is False  # real Layer 2.5 catches it
    assert "scope_amount_exceeds_parent" in verdict.containment_reasons
    assert verdict.escalation_opened is True
    assert verdict.escalation_id is not None

    escalation = state.escalation_queue.get(verdict.escalation_id)
    assert escalation is not None
    assert escalation.agent_id == parent_agent
