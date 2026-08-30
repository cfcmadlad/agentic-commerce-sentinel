"""Declarative policy-document schema: Layer 2's rule set as versioned, structured data.

YAML chosen over a custom expression grammar -- the brief's own instruction
was to propose which and why. Every one of Layer 2's real rules
(`detect/scope.py`) is a single declarative comparison: one field against
another field, or one field against a set. None of them compose booleans,
do arithmetic, or need control flow. YAML already represents "a list of
typed, named records" directly, and needs no interpreter beyond schema
validation; a custom expression grammar would need its own parser,
evaluator, and sandboxing to guarantee it could only ever express a
read-only comparison -- exactly what "no policy construct may express a
mutating or offensive action" requires, and what this schema makes true by
construction instead of by runtime enforcement: `PolicyRule` has no field
capable of naming an action, only a comparison between two already-known
field values.

Scope boundary, stated up front: this package proves a declarative policy
document can faithfully reproduce Layer 2's real decisions (see
`tests/test_policy_behavioral_identity.py`, checked against the full
generated corpus) and ships real linting and semantic versioning. It is not
wired into `/sessions/decide` as the live authoritative source -- the same
boundary already drawn for Layer 2.5's containment engine
(`docs/adr/0008`'s scope note): replacing what actually governs a live
decision is a separate, larger choice this milestone does not make
reactively. See `docs/adr/0013-policy-as-code.md`.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# The only field paths a rule may reference -- a closed allowlist, not an
# arbitrary attribute walk. `policy/compiler.py::resolve_path` refuses
# anything not in this set, and `policy/linter.py` flags a rule
# referencing an unknown path as unreachable (it could never evaluate
# against real data). Mirrors exactly the fields `detect/scope.py`'s real
# checks read from `SessionTrace` and `SignedMandate` -- nothing more.
KNOWN_FIELD_PATHS: frozenset[str] = frozenset(
    {
        "trace.mandate_id",
        "trace.agent_id",
        "trace.user_id",
        "trace.amount",
        "trace.currency",
        "trace.merchant_category",
        "trace.item_category",
        "trace.merchant_id",
        "trace.started_at",
        "mandate.mandate_id",
        "mandate.agent_id",
        "mandate.user_id",
        "mandate.scope.max_amount",
        "mandate.scope.currency",
        "mandate.scope.allowed_merchant_categories",
        "mandate.scope.allowed_item_categories",
        "mandate.scope.allowed_merchant_ids",
        "mandate.scope.valid_from",
        "mandate.scope.valid_until",
    }
)

_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

CheckKind = Literal["equals", "compare", "membership", "in_range"]


class PolicyRule(BaseModel):
    """One declarative rule: a single comparison, and the reason it names on violation.

    Exactly which of `left`/`right`/`value`/`field_set`/`low`/`high` are
    required depends on `check` -- validated in `_check_shape_matches_kind`
    below, so a malformed rule fails to load with a precise, named error
    rather than a confusing downstream `KeyError`.

    Attributes:
        name: A short, stable, unique identifier for this rule.
        reason: The `detect.scope.ScopeViolationReason` value this rule
            corresponds to when it fires.
        check: Which comparison this rule performs:
            - `"equals"`: `left == right` must hold; violates otherwise.
            - `"compare"`: `left <= right` must hold; violates otherwise.
            - `"membership"`: `value` must be a member of `field_set`;
              violates otherwise. `field_set` resolving to `None` means
              "no restriction" (matching `mandate.schema.MandateScope
              .allowed_merchant_ids`'s own documented meaning of `None`)
              and is always satisfied, never a violation.
            - `"in_range"`: `low <= value <= high` must hold; violates
              otherwise.
        left: Dotted field path, for `"equals"`/`"compare"`.
        right: Dotted field path, for `"equals"`/`"compare"`.
        value: Dotted field path, for `"membership"`/`"in_range"`.
        field_set: Dotted field path resolving to a set (or None), for
            `"membership"`.
        low: Dotted field path, for `"in_range"`.
        high: Dotted field path, for `"in_range"`.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    reason: str
    check: CheckKind
    left: str | None = None
    right: str | None = None
    value: str | None = None
    field_set: str | None = None
    low: str | None = None
    high: str | None = None

    @model_validator(mode="after")
    def _check_shape_matches_kind(self) -> PolicyRule:
        """Validates that exactly the fields `check` needs are present.

        Returns:
            The validated rule, unchanged.

        Raises:
            ValueError: If a required field for this rule's `check` kind is
                missing, or an irrelevant field is set.
        """
        required: dict[str, tuple[str, ...]] = {
            "equals": ("left", "right"),
            "compare": ("left", "right"),
            "membership": ("value", "field_set"),
            "in_range": ("value", "low", "high"),
        }
        all_fields = {"left", "right", "value", "field_set", "low", "high"}
        needed = set(required[self.check])
        for field_name in needed:
            if getattr(self, field_name) is None:
                raise ValueError(f"rule {self.name!r}: check {self.check!r} requires {field_name!r}")
        for field_name in all_fields - needed:
            if getattr(self, field_name) is not None:
                raise ValueError(f"rule {self.name!r}: check {self.check!r} does not use {field_name!r}")
        return self

    @field_validator("left", "right", "value", "field_set", "low", "high")
    @classmethod
    def _check_known_field_path(cls, path: str | None) -> str | None:
        """Validates that any given field path is on the known allowlist.

        Args:
            path: The field path to validate, or None.

        Returns:
            The path, unchanged.

        Raises:
            ValueError: If `path` is not None and not a known field path.
        """
        if path is not None and path not in KNOWN_FIELD_PATHS:
            raise ValueError(f"unknown field path {path!r}; must be one of {sorted(KNOWN_FIELD_PATHS)}")
        return path


class PolicyDocument(BaseModel):
    """A complete, versioned policy document.

    Attributes:
        policy_version: Semantic version (`MAJOR.MINOR.PATCH`) of this
            document.
        rules: Every rule, in evaluation order. Order matters for matching
            `detect.scope.enforce_scope`'s own reason ordering exactly.
    """

    model_config = ConfigDict(extra="forbid")

    policy_version: str
    rules: tuple[PolicyRule, ...]

    @field_validator("policy_version")
    @classmethod
    def _check_semver(cls, version: str) -> str:
        """Validates that `policy_version` is a bare `MAJOR.MINOR.PATCH` string.

        Args:
            version: The version string to validate.

        Returns:
            The version, unchanged.

        Raises:
            ValueError: If `version` is not of the form `MAJOR.MINOR.PATCH`.
        """
        if not _SEMVER_PATTERN.match(version):
            raise ValueError(f"policy_version {version!r} must be MAJOR.MINOR.PATCH (e.g. '1.0.0')")
        return version

    @model_validator(mode="after")
    def _check_unique_rule_names(self) -> PolicyDocument:
        """Validates that no two rules share a name.

        Returns:
            The validated document, unchanged.

        Raises:
            ValueError: If any rule name is repeated.
        """
        names = [r.name for r in self.rules]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            raise ValueError(f"duplicate rule name(s): {sorted(duplicates)}")
        return self
