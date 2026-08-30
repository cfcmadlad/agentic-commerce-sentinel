"""Tests for `policy.loader`: strict YAML validation with precise errors."""

from __future__ import annotations

import pytest

from policy.loader import PolicyLoadError, load_default_policy, load_policy_text

_VALID_YAML = """
policy_version: "1.0.0"
rules:
  - name: amount_over_ceiling
    reason: amount_over_ceiling
    check: compare
    left: trace.amount
    right: mandate.scope.max_amount
"""


def test_default_policy_loads_and_has_nine_rules() -> None:
    """The shipped default policy must load cleanly and match Layer 2's real rule count."""
    document = load_default_policy()
    assert document.policy_version == "1.0.0"
    assert len(document.rules) == 9


def test_valid_yaml_loads() -> None:
    """A minimal, well-formed document must load without error."""
    document = load_policy_text(_VALID_YAML)
    assert document.policy_version == "1.0.0"
    assert len(document.rules) == 1


def test_malformed_yaml_raises_a_precise_error() -> None:
    """Genuinely broken YAML syntax must fail with a clear error, not an opaque traceback."""
    with pytest.raises(PolicyLoadError, match="invalid YAML"):
        load_policy_text("rules: [this is not: valid: yaml:")


def test_non_mapping_top_level_raises() -> None:
    """A YAML document that isn't a mapping at the top level must be rejected clearly."""
    with pytest.raises(PolicyLoadError, match="mapping"):
        load_policy_text("- just\n- a\n- list\n")


def test_unknown_field_path_is_rejected() -> None:
    """A rule referencing a field path outside the known allowlist must fail to load."""
    text = _VALID_YAML.replace("trace.amount", "trace.nonexistent_field")
    with pytest.raises(PolicyLoadError, match="unknown field path"):
        load_policy_text(text)


def test_wrong_fields_for_check_kind_is_rejected() -> None:
    """A 'membership' rule missing its required 'value' field must fail with a named, precise error."""
    text = """
policy_version: "1.0.0"
rules:
  - name: broken_rule
    reason: merchant_category_not_allowed
    check: membership
    field_set: mandate.scope.allowed_merchant_categories
"""
    with pytest.raises(PolicyLoadError, match="requires 'value'"):
        load_policy_text(text)


def test_irrelevant_field_for_check_kind_is_rejected() -> None:
    """An 'equals' rule carrying a 'field_set' it does not use must fail with a named, precise error."""
    text = """
policy_version: "1.0.0"
rules:
  - name: broken_rule
    reason: currency_mismatch
    check: equals
    left: trace.currency
    right: mandate.scope.currency
    field_set: mandate.scope.allowed_merchant_categories
"""
    with pytest.raises(PolicyLoadError, match="does not use 'field_set'"):
        load_policy_text(text)


def test_invalid_semver_is_rejected() -> None:
    """A policy_version that isn't MAJOR.MINOR.PATCH must fail to load."""
    text = _VALID_YAML.replace('"1.0.0"', '"v1"')
    with pytest.raises(PolicyLoadError, match="MAJOR.MINOR.PATCH"):
        load_policy_text(text)


def test_duplicate_rule_names_are_rejected() -> None:
    """Two rules sharing a name must fail to load, not silently shadow one another."""
    text = _VALID_YAML + """
  - name: amount_over_ceiling
    reason: currency_mismatch
    check: equals
    left: trace.currency
    right: mandate.scope.currency
"""
    with pytest.raises(PolicyLoadError, match="duplicate rule name"):
        load_policy_text(text)


def test_unrecognized_top_level_key_is_rejected() -> None:
    """An unexpected top-level key (a typo) must fail to load, not be silently ignored."""
    text = _VALID_YAML + "\nunexpected_key: true\n"
    with pytest.raises(PolicyLoadError):
        load_policy_text(text)
