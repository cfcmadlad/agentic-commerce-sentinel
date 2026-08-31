"""The fake merchant catalog the shopper agent searches and buys from.

Fixed and hardcoded rather than generated through the repo's seeded-RNG
helper (`generator.rng.rng_uuid`/`rng_nonce`) -- a deliberate judgment call,
not an oversight. A handful of named SKUs is small enough that hardcoding is
strictly more auditable than a generator a reader would have to run to see
what exists: every item a scenario in `agent.scenarios` can select is visible
in one place, at a fixed price, with no seed/parameter combination to
reproduce first. Reusing the seeded-RNG pattern would only pay for itself at
a catalog size this project has no reason to reach.

Prices and categories are chosen deliberately to span Layer 2's scope rules
(some items are inside a typical demo mandate's ceiling and allowlist, some
are not) and to give `agent.scenarios` concrete, named items to steer the
agent toward for each required demo outcome -- see that module for which
item backs which scenario.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class CatalogItem:
    """One fixed SKU in the fake merchant catalog.

    Attributes:
        item_id: Stable, human-readable identifier.
        name: Display name, searchable by `search_catalog`.
        merchant_id: The specific merchant this item is sold by.
        merchant_category: The merchant's category code.
        item_category: The item's own category code.
        price: Unit price, in `CATALOG_CURRENCY`.
    """

    item_id: str
    name: str
    merchant_id: str
    merchant_category: str
    item_category: str
    price: Decimal


CATALOG_CURRENCY = "INR"

CATALOG: tuple[CatalogItem, ...] = (
    CatalogItem(
        item_id="earbuds-wireless-01",
        name="wireless earbuds",
        merchant_id="gearhub-01",
        merchant_category="electronics",
        item_category="gadgets",
        price=Decimal("1499.00"),
    ),
    CatalogItem(
        item_id="speaker-bluetooth-01",
        name="bluetooth speaker",
        merchant_id="gearhub-01",
        merchant_category="electronics",
        item_category="gadgets",
        price=Decimal("2199.00"),
    ),
    CatalogItem(
        item_id="laptop-pro-01",
        name="15-inch laptop",
        merchant_id="gearhub-01",
        merchant_category="electronics",
        item_category="gadgets",
        price=Decimal("42000.00"),
    ),
    CatalogItem(
        item_id="sneakers-running-01",
        name="running sneakers",
        merchant_id="trendline-09",
        merchant_category="fashion",
        item_category="apparel",
        price=Decimal("950.00"),
    ),
    CatalogItem(
        item_id="jacket-denim-01",
        name="denim jacket",
        merchant_id="trendline-09",
        merchant_category="fashion",
        item_category="apparel",
        price=Decimal("1850.00"),
    ),
    CatalogItem(
        item_id="rice-sack-5kg-01",
        name="5kg rice sack",
        merchant_id="freshmart-01",
        merchant_category="grocery",
        item_category="packaged_food",
        price=Decimal("650.00"),
    ),
    CatalogItem(
        item_id="protein-bar-pack-01",
        name="protein bar pack (12-count)",
        merchant_id="freshmart-01",
        merchant_category="grocery",
        item_category="packaged_food",
        price=Decimal("480.00"),
    ),
    CatalogItem(
        item_id="yoga-mat-01",
        name="yoga mat",
        merchant_id="wellspace-02",
        merchant_category="fitness",
        item_category="equipment",
        price=Decimal("1200.00"),
    ),
)


def find_item(item_id: str) -> CatalogItem | None:
    """Looks up one catalog item by its ID.

    Args:
        item_id: The item ID to resolve.

    Returns:
        The matching item, or None if no such item exists.
    """
    for item in CATALOG:
        if item.item_id == item_id:
            return item
    return None


def search_items(query: str) -> tuple[CatalogItem, ...]:
    """Searches the catalog by a case-insensitive substring match on name or category.

    Args:
        query: Free-text search query. Empty or whitespace-only returns the
            full catalog, matching a shopper browsing without a specific
            item in mind.

    Returns:
        Every matching item, in catalog order.
    """
    normalized = query.strip().lower()
    if not normalized:
        return CATALOG
    return tuple(
        item
        for item in CATALOG
        if normalized in item.name.lower()
        or normalized in item.item_category.lower()
        or normalized in item.merchant_category.lower()
    )
