"""Checks each safety property with Z3 and reports proved/violated.

A property is proved by asserting its *negation* and checking that the
resulting formula is unsatisfiable: if no input anywhere in the bounded
encoded space makes the negation true, the property holds for every input in
that space, not merely the ones sampled by a test suite. If the negation
*is* satisfiable, Z3 returns a concrete counterexample -- an actual
assignment to every symbolic variable that violates the property -- which
this module extracts and reports rather than discarding.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import z3  # type: ignore[import-untyped]

from formal.properties import Property, all_properties

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PropertyResult:
    """The outcome of checking one property.

    Attributes:
        property: The property that was checked.
        proved: True iff Z3 proved the property holds for every input in
            the bounded encoded space (its negation was unsatisfiable).
        counterexample: When `proved` is False, a concrete assignment (Z3
            variable name to its value, as text) that violates the
            property. None when `proved` is True.
    """

    property: Property
    proved: bool
    counterexample: dict[str, str] | None


def verify_property(prop: Property) -> PropertyResult:
    """Checks one property by asserting its negation and requiring unsat.

    Args:
        prop: The property to check.

    Returns:
        The result, with a concrete counterexample attached if the property
        does not hold.

    Raises:
        RuntimeError: If Z3 returns `unknown` rather than a decisive
            `sat`/`unsat` result. This encoding uses only linear integer
            arithmetic and finite-set theory over bounded domains, both
            decidable, so `unknown` here indicates something is wrong with
            the encoding itself and must not be silently treated as either
            a proof or a violation.
    """
    solver = z3.Solver()
    solver.add(z3.Not(prop.formula))
    outcome = solver.check()

    if outcome == z3.unsat:
        logger.info("property %s: proved", prop.name)
        return PropertyResult(property=prop, proved=True, counterexample=None)

    if outcome == z3.sat:
        model = solver.model()
        counterexample = {str(decl.name()): str(model[decl]) for decl in model.decls()}
        logger.warning("property %s: violated, counterexample: %s", prop.name, counterexample)
        return PropertyResult(property=prop, proved=False, counterexample=counterexample)

    raise RuntimeError(
        f"Z3 returned unknown for property {prop.name!r}: {solver.reason_unknown()}; "
        f"this encoding is fully decidable, so this indicates a problem with the encoding itself"
    )


def verify_all(properties: tuple[Property, ...] | None = None) -> tuple[PropertyResult, ...]:
    """Checks every property, or a given subset.

    Args:
        properties: The properties to check. Defaults to
            `formal.properties.all_properties()`.

    Returns:
        One result per property, in the same order given.
    """
    props = properties if properties is not None else all_properties()
    return tuple(verify_property(prop) for prop in props)


def format_report(results: tuple[PropertyResult, ...]) -> str:
    """Renders verification results as plain text.

    Args:
        results: The results to render.

    Returns:
        A human-readable multi-line summary, including any counterexample.
    """
    lines = [
        "Formal verification of Layers 1, 2, and 2.5's deterministic decision logic",
        "(Z3 SMT solver; each property checked by asserting its negation and requiring unsat)",
        "",
    ]
    for result in results:
        status = "PROVED (unsat)" if result.proved else "VIOLATED (sat -- counterexample found)"
        lines.append(f"[{status}] {result.property.name}")
        lines.append(f"    layer: {result.property.layer}")
        lines.append(f"    {result.property.description}")
        if not result.proved and result.counterexample:
            lines.append("    counterexample:")
            for var_name, value in sorted(result.counterexample.items()):
                lines.append(f"      {var_name} = {value}")
        lines.append("")

    n_proved = sum(1 for result in results if result.proved)
    lines.append(f"{n_proved}/{len(results)} properties proved.")
    return "\n".join(lines)
