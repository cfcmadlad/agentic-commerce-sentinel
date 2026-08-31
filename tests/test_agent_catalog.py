"""Tests for the fixed fake merchant catalog."""

from __future__ import annotations

from agent.catalog import CATALOG, find_item, search_items


def test_catalog_is_deterministic_and_non_empty() -> None:
    """The catalog is a fixed module-level constant -- same content every call."""
    assert len(CATALOG) > 0
    assert CATALOG == tuple(CATALOG)


def test_catalog_item_ids_are_unique() -> None:
    """Every item ID appears exactly once, so `find_item` is unambiguous."""
    ids = [item.item_id for item in CATALOG]
    assert len(ids) == len(set(ids))


def test_find_item_returns_none_for_unknown_id() -> None:
    """An unknown item ID resolves to None, not an exception."""
    assert find_item("does-not-exist") is None


def test_find_item_returns_the_matching_item() -> None:
    """A known item ID resolves to the exact catalog entry."""
    item = find_item("earbuds-wireless-01")
    assert item is not None
    assert item.name == "wireless earbuds"


def test_search_items_empty_query_returns_full_catalog() -> None:
    """An empty or whitespace-only query returns every item."""
    assert search_items("") == CATALOG
    assert search_items("   ") == CATALOG


def test_search_items_matches_name_case_insensitively() -> None:
    """A substring match on name is case-insensitive."""
    results = search_items("EARBUDS")
    assert any(item.item_id == "earbuds-wireless-01" for item in results)


def test_search_items_matches_category() -> None:
    """A query matching an item or merchant category returns that item."""
    results = search_items("apparel")
    assert all(item.item_category == "apparel" for item in results)
    assert len(results) > 0


def test_search_items_no_match_returns_empty() -> None:
    """A query matching nothing returns an empty tuple, not an error."""
    assert search_items("nonexistent-item-xyz") == ()
