"""Tests for `formal.properties`: the property set itself is well-formed."""

from __future__ import annotations

import z3  # type: ignore[import-untyped]

from formal.properties import all_properties


def test_exactly_eight_properties() -> None:
    """The milestone's brief asked for 5-8 properties; this project ships all 8 planned."""
    assert len(all_properties()) == 8


def test_property_names_are_unique() -> None:
    """Two properties sharing a name would make the report ambiguous."""
    names = [prop.name for prop in all_properties()]
    assert len(names) == len(set(names))


def test_every_property_has_a_nonempty_description_and_layer() -> None:
    """A property with no stated layer or description would be unreportable."""
    for prop in all_properties():
        assert prop.description.strip()
        assert prop.layer.strip()


def test_every_property_formula_is_a_boolean_expression() -> None:
    """Every formula must actually be a Z3 boolean expression, not a stray Python value."""
    for prop in all_properties():
        assert z3.is_bool(prop.formula)


def test_every_layer_from_the_milestone_is_represented() -> None:
    """Layers 1, 2, and 2.5 must each have at least one property, plus the combination logic."""
    layers = [prop.layer for prop in all_properties()]
    assert any("Layer 1" in layer for layer in layers)
    assert any("Layer 2 (" in layer for layer in layers)
    assert any("Layer 2.5" in layer for layer in layers)
    assert any("Combination" in layer for layer in layers)
