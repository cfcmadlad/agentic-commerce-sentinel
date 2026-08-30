"""Tests for `policy.linter`: unreachable, contradictory, and unfireable rule detection."""

from __future__ import annotations

from policy.linter import CATEGORY_CONTRADICTORY, CATEGORY_UNFIREABLE, CATEGORY_UNREACHABLE, lint_policy
from policy.loader import load_default_policy, load_policy_text


def test_default_policy_lints_clean() -> None:
    """The shipped default policy must have no lint issues at all."""
    assert lint_policy(load_default_policy()) == ()


def test_contradictory_rules_sharing_a_reason_are_flagged() -> None:
    """Two rules firing the same named reason must both be flagged contradictory."""
    text = """
policy_version: "1.0.0"
rules:
  - name: rule_one
    reason: amount_over_ceiling
    check: compare
    left: trace.amount
    right: mandate.scope.max_amount
  - name: rule_two
    reason: amount_over_ceiling
    check: equals
    left: trace.currency
    right: mandate.scope.currency
"""
    issues = lint_policy(load_policy_text(text))
    categories = {issue.category for issue in issues}
    names = {issue.rule_name for issue in issues}
    assert CATEGORY_CONTRADICTORY in categories
    assert names == {"rule_one", "rule_two"}


def test_unfireable_self_comparison_is_flagged() -> None:
    """A rule comparing a field to itself can never violate, and must be flagged."""
    text = """
policy_version: "1.0.0"
rules:
  - name: pointless_rule
    reason: amount_over_ceiling
    check: equals
    left: trace.amount
    right: trace.amount
"""
    issues = lint_policy(load_policy_text(text))
    assert any(issue.category == CATEGORY_UNFIREABLE and issue.rule_name == "pointless_rule" for issue in issues)


def test_unfireable_in_range_with_identical_bounds_is_flagged() -> None:
    """An in_range rule whose low and high are the same field is a single point, not a range."""
    text = """
policy_version: "1.0.0"
rules:
  - name: degenerate_range
    reason: outside_time_window
    check: in_range
    value: trace.started_at
    low: mandate.scope.valid_from
    high: mandate.scope.valid_from
"""
    issues = lint_policy(load_policy_text(text))
    assert any(issue.category == CATEGORY_UNFIREABLE and issue.rule_name == "degenerate_range" for issue in issues)


def test_unreachable_non_orderable_compare_is_flagged() -> None:
    """A 'compare' rule against a set-typed field can never evaluate correctly, and must be flagged unreachable."""
    text = """
policy_version: "1.0.0"
rules:
  - name: nonsensical_compare
    reason: merchant_category_not_allowed
    check: compare
    left: mandate.scope.allowed_merchant_categories
    right: mandate.scope.allowed_item_categories
"""
    issues = lint_policy(load_policy_text(text))
    assert any(issue.category == CATEGORY_UNREACHABLE and issue.rule_name == "nonsensical_compare" for issue in issues)
