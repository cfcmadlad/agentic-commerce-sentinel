"""Compiles a validated `PolicyDocument` into a read-only evaluator.

`resolve_path` only ever performs attribute lookups along a path already
validated against `policy.schema.KNOWN_FIELD_PATHS` -- there is no way to
reach this code with an arbitrary, policy-document-supplied attribute
name, and nothing here ever assigns to, mutates, or calls a method on
anything it resolves. This is what makes "no policy construct may express
a mutating or offensive action" true of the compiled form, not just the
document schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.schema import SessionTrace
from mandate.schema import SignedMandate
from policy.schema import PolicyDocument, PolicyRule


@dataclass(frozen=True)
class _Context:
    """The two objects every rule's field paths resolve against."""

    trace: SessionTrace
    signed: SignedMandate


def resolve_path(path: str, ctx: _Context) -> Any:  # noqa: ANN401 - a field-path resolver is inherently dynamic
    """Resolves one known dotted field path against a session's trace and mandate.

    Args:
        path: A dotted path already validated against
            `policy.schema.KNOWN_FIELD_PATHS` (e.g. `"mandate.scope
            .max_amount"`).
        ctx: The trace and signed mandate to resolve against.

    Returns:
        The resolved value.
    """
    parts = path.split(".")
    root: Any = ctx.trace if parts[0] == "trace" else ctx.signed.mandate
    value = root
    for part in parts[1:]:
        value = getattr(value, part)
    return value


def _rule_violates(rule: PolicyRule, ctx: _Context) -> bool:
    """Evaluates whether one rule's comparison fails for this context.

    Args:
        rule: The rule to evaluate.
        ctx: The trace and signed mandate to evaluate it against.

    Returns:
        True if the rule's comparison does not hold (a violation).

    Raises:
        AssertionError: If `rule.check` is not one of the schema's four
            known kinds -- unreachable given `PolicyRule`'s own validation,
            kept as a fail-loud guard against a future schema change adding
            a check kind this function was never updated for.
    """
    if rule.check == "equals":
        assert rule.left is not None and rule.right is not None
        return bool(resolve_path(rule.left, ctx) != resolve_path(rule.right, ctx))
    if rule.check == "compare":
        assert rule.left is not None and rule.right is not None
        return bool(resolve_path(rule.left, ctx) > resolve_path(rule.right, ctx))
    if rule.check == "membership":
        assert rule.value is not None and rule.field_set is not None
        field_set = resolve_path(rule.field_set, ctx)
        if field_set is None:
            return False  # None means "no restriction" -- see PolicyRule's own docstring
        return bool(resolve_path(rule.value, ctx) not in field_set)
    if rule.check == "in_range":
        assert rule.value is not None and rule.low is not None and rule.high is not None
        value = resolve_path(rule.value, ctx)
        low = resolve_path(rule.low, ctx)
        high = resolve_path(rule.high, ctx)
        return not (low <= value <= high)
    raise AssertionError(f"unreachable: unknown check kind {rule.check!r}")


@dataclass(frozen=True)
class CompiledPolicy:
    """A policy document, ready to evaluate real sessions against.

    Attributes:
        document: The validated document this was compiled from.
    """

    document: PolicyDocument

    @property
    def version(self) -> str:
        """The compiled policy's own semantic version.

        Returns:
            `document.policy_version`.
        """
        return self.document.policy_version

    def evaluate(self, trace: SessionTrace, signed: SignedMandate) -> tuple[str, ...]:
        """Evaluates every rule, in document order, against one session.

        Args:
            trace: The session under evaluation.
            signed: The mandate presented in that session. Must not be
                None -- a session presenting no mandate at all is a
                precondition this policy does not model (see
                `policy/default_policy.yaml`'s own module-level comment);
                callers check for that case before reaching here.

        Returns:
            The `reason` of every rule that violated, in document order --
            reproducing `detect.scope.enforce_scope`'s own `reasons` tuple
            when evaluated against the default policy (see
            `tests/test_policy_behavioral_identity.py`).
        """
        ctx = _Context(trace=trace, signed=signed)
        return tuple(rule.reason for rule in self.document.rules if _rule_violates(rule, ctx))


def compile_policy(document: PolicyDocument) -> CompiledPolicy:
    """Compiles a validated policy document into an evaluator.

    Args:
        document: The document to compile.

    Returns:
        The compiled policy.
    """
    return CompiledPolicy(document=document)
