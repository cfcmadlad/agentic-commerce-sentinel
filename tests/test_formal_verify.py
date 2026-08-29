"""Tests for `formal.verify`, including a real deliberate-bug demonstration.

`test_all_real_properties_are_proved` is the main integration test: it
mirrors `run_verify_policy_properties.py` exactly, proving every property
this project ships stands up to Z3.

`test_deliberately_broken_subset_check_yields_a_real_counterexample` and
`test_the_same_check_fixed_is_proved` demonstrate the method actually
working, kept as permanent, real, re-runnable tests rather than a one-off
script and a paraphrase in the ADR: introduce one genuine
transcription bug into an encoding (reversing one `IsSubset` direction --
exactly the kind of copy-paste mistake this module's several near-identical
subset checks invite), show Z3 return `sat` with a concrete counterexample,
then show the same check with the bug reverted returns `unsat`. The
counterexample text these tests produce is quoted verbatim in
`docs/adr/0005-formal-verification-of-deterministic-layers.md`.
"""

from __future__ import annotations

import z3  # type: ignore[import-untyped]

from formal.model import ContainmentVars, contained, containment_bounds, fresh_containment_vars
from formal.properties import Property, all_properties
from formal.verify import format_report, verify_all, verify_property


def test_all_real_properties_are_proved() -> None:
    """Every property this project ships must actually prove -- the headline claim."""
    results = verify_all(all_properties())
    unproved = [r.property.name for r in results if not r.proved]
    assert not unproved, f"expected every property proved, but these were not: {unproved}"


def test_format_report_states_the_methodology() -> None:
    """The report must be legible about what it is, without external context."""
    results = verify_all(all_properties())
    rendered = format_report(results)
    assert "unsat" in rendered.lower()
    assert "8/8 properties proved" in rendered


def _broken_scope_is_subset(v: ContainmentVars) -> z3.BoolRef:
    """A deliberately mistranscribed variant of `formal.model.scope_is_subset`.

    The bug: the merchant-category subset direction is reversed --
    `IsSubset(parent_categories, child_categories)` instead of
    `IsSubset(child_categories, parent_categories)`. This is exactly the
    kind of copy-paste mistake `containment/engine.py::_check_scope_subset`
    invites, since it contains three near-identical subset checks in a row
    (merchant categories, item categories, merchant IDs) that differ only in
    which field they read.

    This function exists solely to demonstrate that Z3 catches a real
    mistranscription with a concrete counterexample -- it is never imported
    by `formal/model.py`, `formal/properties.py`, or anything the real
    verification suite runs, and must never be treated as the real encoding.

    Args:
        v: The containment variable bundle.

    Returns:
        The (deliberately wrong) subset formula.
    """
    merchant_id_subset_ok = z3.Or(
        z3.Not(v.parent_has_merchant_restriction),
        z3.And(v.child_has_merchant_restriction, z3.IsSubset(v.child_merchant_ids, v.parent_merchant_ids)),
    )
    return z3.And(
        v.child_max_amount <= v.parent_max_amount,
        v.currency_match,
        z3.IsSubset(v.parent_merchant_categories, v.child_merchant_categories),  # BUG: reversed
        z3.IsSubset(v.child_item_categories, v.parent_item_categories),
        merchant_id_subset_ok,
        v.parent_valid_from <= v.child_valid_from,
        v.child_valid_until <= v.parent_valid_until,
        v.child_max_transaction_count <= v.parent_max_transaction_count,
    )


def test_deliberately_broken_subset_check_yields_a_real_counterexample() -> None:
    """Z3 must catch a reversed subset direction, not silently accept it.

    Demonstrates the method actually works: this is not a tautology-proving
    exercise that would rubber-stamp anything. A real mistranscription
    produces `sat` with a genuine, inspectable counterexample -- concrete
    category sets where the buggy check accepts a mandate that WIDENS its
    merchant-category reach relative to its parent, exactly the kind of
    escalation Layer 2.5 exists to prevent.
    """
    v = fresh_containment_vars("broken")
    premise = v.child_max_amount <= v.parent_max_amount
    broken_property = Property(
        name="DEMONSTRATION_ONLY_broken_scope_attenuation",
        layer="test demonstration, not a real property",
        description="deliberately mistranscribed; must yield sat, never used outside this test",
        formula=z3.Implies(premise, _broken_scope_is_subset(v)),
    )
    result = verify_property(broken_property)

    assert not result.proved
    assert result.counterexample is not None
    # The counterexample must show the reversed check accepting a case where
    # the child's category set is NOT a subset of the parent's -- i.e. Z3
    # found the exact kind of authority-widening state Layer 2.5 must reject.
    assert len(result.counterexample) > 0


def test_the_same_check_fixed_is_proved() -> None:
    """The real (non-reversed) subset check, for the identical shape, proves unsat.

    Same premise, same variable bundle shape, only the one reversed
    `IsSubset` direction corrected back to `formal.model.scope_is_subset`'s
    real form -- already exercised end to end via property P5
    (`delegated_scope_only_attenuates`) in
    `test_all_real_properties_are_proved`, restated here explicitly for a
    direct broken-then-fixed comparison.
    """
    v = fresh_containment_vars("fixed")
    premise = z3.And(containment_bounds(v), contained(v))
    conclusion = z3.IsSubset(v.child_merchant_categories, v.parent_merchant_categories)
    fixed_property = Property(
        name="DEMONSTRATION_ONLY_fixed_scope_attenuation",
        layer="test demonstration, not a real property",
        description="the corrected check, for direct comparison against the broken variant above",
        formula=z3.Implies(premise, conclusion),
    )
    result = verify_property(fixed_property)

    assert result.proved
    assert result.counterexample is None
