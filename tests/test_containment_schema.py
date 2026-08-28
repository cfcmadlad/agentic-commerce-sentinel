"""Tests for the containment schema's fail-closed schema-drift guard."""

from __future__ import annotations

import pytest

import containment.schema as containment_schema
from containment.schema import ContainmentSchemaDriftError, assert_known_scope_fields


def test_current_schema_passes() -> None:
    """`MandateScope`'s real fields must match containment's known set today."""
    assert_known_scope_fields()  # must not raise


def test_missing_known_field_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checked field vanishing from the schema must fail closed, not pass silently."""
    monkeypatch.setattr(
        containment_schema,
        "_KNOWN_SCOPE_FIELDS",
        frozenset(containment_schema._KNOWN_SCOPE_FIELDS | {"a_field_that_does_not_exist"}),
    )
    with pytest.raises(ContainmentSchemaDriftError, match="missing"):
        assert_known_scope_fields()


def test_unrecognized_field_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A new schema field with no containment rule must fail closed, not pass silently."""
    known_minus_one = frozenset(list(containment_schema._KNOWN_SCOPE_FIELDS)[:-1])
    monkeypatch.setattr(containment_schema, "_KNOWN_SCOPE_FIELDS", known_minus_one)
    with pytest.raises(ContainmentSchemaDriftError, match="unrecognized"):
        assert_known_scope_fields()
