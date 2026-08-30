"""Lints an already-loaded policy document for unreachable, contradictory, or unfireable rules.

Three named categories, each precisely defined for this project's minimal,
non-Turing-complete policy format (`policy/schema.py`'s own module
docstring explains why the format is this narrow):

- **Unreachable**: a `"compare"` or `"in_range"` rule whose field(s) do not
  resolve to an orderable type (a set or a UUID cannot be compared with
  `<=`). Evaluating such a rule would raise at runtime, so in practice it
  could never fire correctly -- the field-path-existence half of
  "unreachable" is already caught earlier, at load time, by
  `policy.schema.PolicyRule`'s own `extra="forbid"` and known-path
  validation, which is why this linter's own unreachable check is about
  type compatibility, not path existence.
- **Contradictory**: two or more rules sharing the same `reason` -- a
  fired reason should map to exactly one deterministic check, not several
  that could disagree about the same named violation.
- **Unfireable**: a `"compare"` or `"in_range"` rule whose two (or three)
  sides are the identical field path -- a field can never violate a
  comparison against itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from policy.schema import PolicyDocument, PolicyRule

_FIELD_KIND: dict[str, str] = {
    "trace.mandate_id": "uuid",
    "mandate.mandate_id": "uuid",
    "trace.agent_id": "str",
    "mandate.agent_id": "str",
    "trace.user_id": "str",
    "mandate.user_id": "str",
    "trace.amount": "number",
    "mandate.scope.max_amount": "number",
    "trace.currency": "str",
    "mandate.scope.currency": "str",
    "trace.merchant_category": "str",
    "mandate.scope.allowed_merchant_categories": "set",
    "trace.item_category": "str",
    "mandate.scope.allowed_item_categories": "set",
    "trace.merchant_id": "str",
    "mandate.scope.allowed_merchant_ids": "set",
    "trace.started_at": "datetime",
    "mandate.scope.valid_from": "datetime",
    "mandate.scope.valid_until": "datetime",
}
_ORDERABLE_KINDS = frozenset({"number", "datetime"})

CATEGORY_UNREACHABLE = "unreachable"
CATEGORY_CONTRADICTORY = "contradictory"
CATEGORY_UNFIREABLE = "unfireable"


@dataclass(frozen=True)
class LintIssue:
    """One problem the linter found.

    Attributes:
        rule_name: The offending rule's name.
        category: One of `CATEGORY_UNREACHABLE`, `CATEGORY_CONTRADICTORY`,
            or `CATEGORY_UNFIREABLE`.
        message: A human-readable explanation.
    """

    rule_name: str
    category: str
    message: str


def _check_orderable(rule: PolicyRule, path: str | None, issues: list[LintIssue]) -> None:
    """Flags a comparison field that does not resolve to an orderable type.

    Args:
        rule: The rule the field belongs to.
        path: The field path to check, or None (skipped if so).
        issues: Accumulator to append a found issue to.
    """
    if path is None:
        return
    kind = _FIELD_KIND[path]
    if kind not in _ORDERABLE_KINDS:
        issues.append(
            LintIssue(
                rule.name,
                CATEGORY_UNREACHABLE,
                f"{rule.check} requires an orderable field, but {path!r} is a {kind!r} -- "
                f"this rule would raise, not evaluate, and so could never actually fire",
            )
        )


def lint_policy(document: PolicyDocument) -> tuple[LintIssue, ...]:
    """Lints a policy document for unreachable, contradictory, or unfireable rules.

    Args:
        document: The document to lint.

    Returns:
        Every issue found, in no particular guaranteed order.
    """
    issues: list[LintIssue] = []

    by_reason: dict[str, list[str]] = {}
    for rule in document.rules:
        by_reason.setdefault(rule.reason, []).append(rule.name)
    for reason, names in by_reason.items():
        if len(names) > 1:
            for name in names:
                others = [n for n in names if n != name]
                issues.append(
                    LintIssue(name, CATEGORY_CONTRADICTORY, f"reason {reason!r} is also fired by {others}")
                )

    for rule in document.rules:
        if rule.check in ("equals", "compare") and rule.left == rule.right:
            issues.append(
                LintIssue(rule.name, CATEGORY_UNFIREABLE, f"{rule.check} compares {rule.left!r} to itself")
            )
        if rule.check == "in_range" and rule.low == rule.high:
            issues.append(
                LintIssue(
                    rule.name, CATEGORY_UNFIREABLE, "low and high are the same field; the range is a single point"
                )
            )
        if rule.check == "compare":
            _check_orderable(rule, rule.left, issues)
        if rule.check == "in_range":
            _check_orderable(rule, rule.value, issues)

    return tuple(issues)
