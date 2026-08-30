"""Z3-verified minimal-edit counterfactuals for Layers 1, 2, and 2.5.

For a denied verdict, this module identifies exactly the fields whose own
check failed (Layer 1's six conjuncts, Layer 2's ten, Layer 2.5's nine are
each independent -- no two named failure reasons share a field, per the
functions they mirror: `mandate.verification.verify_mandate`,
`detect.scope.enforce_scope`, `containment.engine.enforce_containment`), and
computes each failing field's own boundary value directly -- the ceiling,
window edge, or budget the mandate would need, or the trimmed set that fits
inside a parent's grant. Because the checks are independent conjuncts, editing
exactly the currently-failing fields to their own boundary is provably the
minimal edit: no smaller edit can work (every failing clause must change by
definition), and no field outside the failing set needs to move (every
clause it belongs to already holds).

The boundary values themselves are ordinary arithmetic -- a ceiling is just
the mandate's own ceiling, a window edge is just the mandate's own window.
What makes this "derived from the solver, not hand-written" in the sense
Milestone R's brief asks for: the resulting edited assignment is checked
for satisfiability against the exact same `mandate_verified`/`in_scope`/
`contained` Z3 predicates `formal/model.py` built for Milestone P's
exhaustive proofs, not a second, independently-written copy of "is this
valid". If a future change to `formal/model.py` (or a mistake in this
module's own field-to-clause mapping) ever produces an edit the real
predicate does not accept, `_verify` returns False and the public function
raises `AssertionError` rather than silently reporting a wrong answer --
the solver is the correctness oracle, even though it is not doing a search.

Scope boundary, stated explicitly: Layer 2.5 (containment) is not wired into
the live API service (`service/main.py` calls only Layers 1, 2, and 3 --
see its own module docstring), so `containment_counterfactual` is a
library-level capability, exercised by its own tests and available to any
caller with a resolved delegation chain (for example a future audit tool
over `eval/containment_evaluation.py`'s corpus), not surfaced through
`/sessions/decide`. A chain-topology violation (a cycle, an unresolvable
ancestor, or exceeding the depth bound) has no field-level fix at all --
`containment_counterfactual` reports that honestly rather than inventing
one.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

import z3  # type: ignore[import-untyped]

from common.schema import SessionTrace
from containment.chain import AncestorChainResolution
from containment.engine import enforce_containment
from containment.schema import ContainmentViolationReason
from detect.scope import ScopeViolationReason, enforce_scope
from formal.model import (
    ITEM_CATEGORIES,
    MERCHANT_CATEGORIES,
    MERCHANT_IDS,
    ItemCategory,
    MerchantCategory,
    MerchantId,
    contained,
    fresh_containment_vars,
    fresh_scope_vars,
    fresh_verification_vars,
    in_scope,
    mandate_verified,
)
from mandate.schema import Mandate, SignedMandate
from mandate.signing import signature_is_valid
from mandate.verification import AgentKeyRegistry, MandateLedger

logger = logging.getLogger(__name__)

# Amounts throughout this project are Decimal rupees; formal/model.py's Z3
# encoding uses integer paise (see its own module docstring). Converted only
# at the boundary of this module, never carried as a float anywhere.
_PAISE_PER_RUPEE = 100


@dataclass(frozen=True)
class FieldEdit:
    """One field this counterfactual changes, real value to suggested value.

    Attributes:
        field: Dotted path identifying the field (e.g. `"trace.amount"`,
            `"scope.max_amount"`), for display and for the audit record.
        real_value: The field's actual value in the denied session, as text.
        suggested_value: The value that would need to hold instead, as text.
    """

    field: str
    real_value: str
    suggested_value: str


@dataclass(frozen=True)
class Counterfactual:
    """One layer's counterfactual explanation for a denied verdict.

    Attributes:
        layer: Which layer this explains (`"layer1_verification"`,
            `"layer2_scope"`, or `"layer2_5_containment"`).
        feasible: True if a field-level edit was found. False for a
            structural violation with no field-level fix (no mandate
            presented at all; a broken delegation-chain topology; a
            category-subset violation with no overlap to trim to).
        edits: The fields to change and their suggested values. Empty when
            `feasible` is False.
        explanation: A plain-language sentence stating the edit, or (when
            infeasible) why none exists.
        solver_verified: True if the suggested edit was checked
            satisfiable against `formal.model`'s real decision predicate.
            False only for the infeasible cases above, which have no
            edited assignment to check.
    """

    layer: str
    feasible: bool
    edits: tuple[FieldEdit, ...]
    explanation: str
    solver_verified: bool


def _dt_to_seconds(value: datetime) -> int:
    """Converts a timestamp to integer seconds, the unit `formal.model` compares in.

    Args:
        value: The timestamp to convert.

    Returns:
        Whole seconds since the Unix epoch. Sub-second precision is not
        meaningful here -- every real timestamp this project generates or
        accepts is compared at second granularity by the layers this module
        explains.
    """
    return int(value.timestamp())


def _amount_to_paise(value: Decimal) -> int:
    """Converts a Decimal rupee amount to the integer paise `formal.model` uses.

    Args:
        value: The amount to convert.

    Returns:
        The amount in paise.
    """
    return int(value * _PAISE_PER_RUPEE)


def _bool_fix(var: z3.BoolRef, value: bool) -> z3.BoolRef:
    """Builds the constraint pinning a Z3 boolean to a concrete value.

    Args:
        var: The boolean variable to pin.
        value: The value to pin it to.

    Returns:
        `var` itself if `value` is True, `Not(var)` otherwise.
    """
    return var if value else z3.Not(var)


def _enum_map(constants: tuple[z3.ExprRef, ...], values: Sequence[str]) -> dict[str, z3.ExprRef]:
    """Assigns each distinct real string a slot in an abstract Z3 enum domain.

    `formal/model.py`'s category/merchant-ID domains are abstract and
    catalog-agnostic (see its own module docstring): what matters to the
    decision logic is set membership and subset relationships, never which
    element it received. This builds a fresh, call-local bijection from the
    real strings actually involved in one concrete session -- never a fixed
    global catalog table, so this module stays decoupled from
    `generator/config.py`'s specific category names.

    Args:
        constants: The abstract domain's enum constants (e.g.
            `formal.model.MERCHANT_CATEGORIES`).
        values: The real strings to map, in any order; duplicates collapse.

    Returns:
        Each distinct value mapped to one constant.

    Raises:
        ValueError: If more distinct values are given than the domain has
            room for.
    """
    unique = list(dict.fromkeys(values))
    if len(unique) > len(constants):
        raise ValueError(
            f"cannot represent {len(unique)} distinct values in this "
            f"{len(constants)}-element abstract domain: {unique}"
        )
    return {value: constants[i] for i, value in enumerate(unique)}


def _z3_set(sort: z3.SortRef, elements: Iterable[z3.ExprRef]) -> z3.ExprRef:
    """Builds a concrete Z3 set literal from enum constants.

    Args:
        sort: The element sort (e.g. `formal.model.MerchantCategory`).
        elements: The constants to include.

    Returns:
        The set containing exactly those elements.
    """
    result = z3.EmptySet(sort)
    for element in elements:
        result = z3.SetAdd(result, element)
    return result


def _verify(constraints: list[z3.BoolRef], predicate: z3.BoolRef) -> bool:
    """Checks a fully concrete assignment against a real decision predicate.

    Every variable the predicate reads is pinned by `constraints`, so this
    is not a search -- it is Z3 confirming (or refuting) a single already-
    computed answer, used here as an independent correctness oracle over
    the exact encoding Milestone P proved properties about.

    Args:
        constraints: Equality/fix constraints pinning every variable.
        predicate: The decision predicate to check (`mandate_verified`,
            `in_scope`, or `contained`).

    Returns:
        True if the pinned assignment satisfies the predicate.
    """
    solver = z3.Solver()
    solver.add(*constraints)
    solver.add(predicate)
    return bool(solver.check() == z3.sat)


def verification_counterfactual(
    signed: SignedMandate,
    registry: AgentKeyRegistry,
    ledger: MandateLedger,
    now: datetime,
    *,
    revocation_checked_at: datetime | None = None,
) -> Counterfactual | None:
    """Explains a denied Layer 1 verdict as the minimal mandate edit that would allow it.

    Recomputes all six of `mandate.verification.verify_mandate`'s time/budget/
    signature conjuncts directly from concrete inputs, rather than trusting
    its `reasons` tuple -- that tuple short-circuits on a signature failure
    and does not report whether the time window or budget also failed, but
    this function's "what would need to change" answer needs the full
    picture regardless of which check the real function stopped at.

    Key revocation is checked separately, first, and is not one of those
    six: it is a security kill switch on the key itself, not a property of
    the mandate's own fields, so no field-level edit can undo it -- see the
    `feasible=False` case below.

    Args:
        signed: The mandate and its claimed signature.
        registry: Registry of public keys trusted to sign for each agent.
        ledger: Usage ledger to check remaining transaction budget against.
        now: The verification instant for the mandate's own time-window
            checks (`valid_from`, `expires_at`, `valid_until`).
        revocation_checked_at: The instant to check key revocation against.
            Defaults to `now` if omitted. Kept separate for the same reason
            `mandate.verification.verify_mandate` keeps it separate: it
            must match the real decision's revocation check, not a value
            that happens to be convenient for the mandate's own time-window
            math.

    Returns:
        None if the mandate already verifies (nothing to explain). A
        `feasible=False` counterfactual if the key was revoked -- no
        mandate edit fixes that. Otherwise a feasible counterfactual, since
        every one of the remaining six conjuncts is either a free boolean
        or a value with a well-defined boundary.

    Raises:
        AssertionError: If the computed edit does not satisfy
            `formal.model.mandate_verified` -- see the module docstring.
    """
    if revocation_checked_at is None:
        revocation_checked_at = now
    mandate = signed.mandate
    if registry.is_revoked(mandate.agent_id, mandate.signer_key_id, revocation_checked_at):
        logger.info(
            "verification_counterfactual: mandate %s blocked by key revocation, no feasible edit",
            mandate.mandate_id,
        )
        return Counterfactual(
            layer="layer1_verification",
            feasible=False,
            edits=(),
            explanation=(
                "No counterfactual is available: the signing key was revoked, which is a "
                "security kill switch on the key itself, not a property of this mandate's "
                "fields. Only rotating or re-registering a trusted key for this agent "
                "restores decisions signed by it."
            ),
            solver_verified=False,
        )
    public_key = registry.get(mandate.agent_id, mandate.signer_key_id)
    has_registered_key = public_key is not None
    signature_valid = has_registered_key and signature_is_valid(signed, public_key)  # type: ignore[arg-type]
    usage_count = ledger.usage_count(mandate.mandate_id)

    already_valid_from = now >= mandate.scope.valid_from
    not_expired = now <= mandate.expires_at
    within_window = now <= mandate.scope.valid_until
    budget_ok = usage_count < mandate.scope.max_transaction_count

    if has_registered_key and signature_valid and already_valid_from and not_expired and within_window and budget_ok:
        return None

    post_has_registered_key = has_registered_key
    post_signature_valid = signature_valid
    post_valid_from = mandate.scope.valid_from
    post_expires_at = mandate.expires_at
    post_valid_until = mandate.scope.valid_until
    post_max_transaction_count = mandate.scope.max_transaction_count
    edits: list[FieldEdit] = []
    clauses: list[str] = []

    if not has_registered_key:
        post_has_registered_key = True
        edits.append(FieldEdit("has_registered_key", "false", "true"))
        clauses.append("the presenting agent's signing key were registered")
    if not signature_valid:
        post_signature_valid = True
        edits.append(FieldEdit("signature_valid", "false", "true"))
        clauses.append("the mandate's signature verified")
    if not already_valid_from:
        post_valid_from = now
        edits.append(FieldEdit("scope.valid_from", mandate.scope.valid_from.isoformat(), now.isoformat()))
        clauses.append(f"the mandate's valid_from were at or before {now.isoformat()}")
    if not not_expired:
        post_expires_at = now
        edits.append(FieldEdit("expires_at", mandate.expires_at.isoformat(), now.isoformat()))
        clauses.append(f"the mandate's expires_at were at or after {now.isoformat()}")
    if not within_window:
        post_valid_until = now
        edits.append(FieldEdit("scope.valid_until", mandate.scope.valid_until.isoformat(), now.isoformat()))
        clauses.append(f"the mandate's valid_until were at or after {now.isoformat()}")
    if not budget_ok:
        post_max_transaction_count = usage_count + 1
        edits.append(
            FieldEdit(
                "scope.max_transaction_count",
                str(mandate.scope.max_transaction_count),
                str(post_max_transaction_count),
            )
        )
        clauses.append(f"the mandate authorized at least {post_max_transaction_count} transactions")

    v = fresh_verification_vars("cf_verification")
    fixed = [
        _bool_fix(v.has_registered_key, post_has_registered_key),
        _bool_fix(v.signature_valid, post_signature_valid),
        v.now == z3.IntVal(_dt_to_seconds(now)),
        v.valid_from == z3.IntVal(_dt_to_seconds(post_valid_from)),
        v.valid_until == z3.IntVal(_dt_to_seconds(post_valid_until)),
        v.expires_at == z3.IntVal(_dt_to_seconds(post_expires_at)),
        v.usage_count == z3.IntVal(usage_count),
        v.max_transaction_count == z3.IntVal(post_max_transaction_count),
    ]
    if not _verify(fixed, mandate_verified(v)):
        raise AssertionError(
            "verification_counterfactual computed an edit that formal.model.mandate_verified "
            "does not accept; this indicates the two have drifted out of sync"
        )

    explanation = "This verdict flips to ALLOW if " + "; and ".join(clauses) + "."
    logger.info("verification_counterfactual: mandate %s, %d field(s) edited", mandate.mandate_id, len(edits))
    return Counterfactual(
        layer="layer1_verification", feasible=True, edits=tuple(edits), explanation=explanation, solver_verified=True
    )


def scope_counterfactual(trace: SessionTrace, signed: SignedMandate | None) -> Counterfactual | None:
    """Explains a denied Layer 2 verdict as the minimal transaction edit that would allow it.

    Args:
        trace: The session under evaluation.
        signed: The mandate presented in that session, or None.

    Returns:
        None if the session is already in scope. A `feasible=False`
        counterfactual if no mandate was presented at all -- there is no
        scope to compare the transaction against. Otherwise a feasible,
        solver-verified counterfactual.

    Raises:
        AssertionError: If the computed edit does not satisfy
            `formal.model.in_scope` -- see the module docstring.
    """
    result = enforce_scope(trace, signed)
    if result.in_scope:
        return None
    if signed is None:
        return Counterfactual(
            layer="layer2_scope",
            feasible=False,
            edits=(),
            explanation=(
                "No counterfactual is available: no mandate was presented for this session, "
                "so there is no scope to compare the transaction against."
            ),
            solver_verified=False,
        )

    mandate = signed.mandate
    scope = mandate.scope
    edits: list[FieldEdit] = []
    clauses: list[str] = []

    post_mandate_id_match = trace.mandate_id == mandate.mandate_id
    post_agent_id_match = trace.agent_id == mandate.agent_id
    post_user_id_match = trace.user_id == mandate.user_id
    post_amount = trace.amount
    post_currency_match = trace.currency == scope.currency
    post_merchant_category = trace.merchant_category
    post_item_category = trace.item_category
    post_merchant_id = trace.merchant_id
    post_session_time = trace.started_at

    if ScopeViolationReason.MANDATE_ID_MISMATCH in result.reasons:
        post_mandate_id_match = True
        edits.append(FieldEdit("trace.mandate_id", str(trace.mandate_id), str(mandate.mandate_id)))
        clauses.append("the session presented this exact mandate")
    if ScopeViolationReason.AGENT_BINDING_MISMATCH in result.reasons:
        post_agent_id_match = True
        edits.append(FieldEdit("trace.agent_id", trace.agent_id, mandate.agent_id))
        clauses.append(f"the session's agent_id were {mandate.agent_id!r}")
    if ScopeViolationReason.USER_BINDING_MISMATCH in result.reasons:
        post_user_id_match = True
        edits.append(FieldEdit("trace.user_id", trace.user_id, mandate.user_id))
        clauses.append(f"the session's user_id were {mandate.user_id!r}")
    if ScopeViolationReason.AMOUNT_OVER_CEILING in result.reasons:
        post_amount = scope.max_amount
        edits.append(FieldEdit("trace.amount", str(trace.amount), str(scope.max_amount)))
        clauses.append(f"the amount were at most {scope.max_amount} {scope.currency}")
    if ScopeViolationReason.CURRENCY_MISMATCH in result.reasons:
        post_currency_match = True
        edits.append(FieldEdit("trace.currency", trace.currency, scope.currency))
        clauses.append(f"the currency were {scope.currency}")
    if ScopeViolationReason.MERCHANT_CATEGORY_NOT_ALLOWED in result.reasons:
        allowed = sorted(scope.allowed_merchant_categories)
        post_merchant_category = allowed[0]
        edits.append(FieldEdit("trace.merchant_category", trace.merchant_category, f"one of {allowed}"))
        clauses.append(f"the merchant category were one of {allowed}")
    if ScopeViolationReason.ITEM_CATEGORY_NOT_ALLOWED in result.reasons:
        allowed_items = sorted(scope.allowed_item_categories)
        post_item_category = allowed_items[0]
        edits.append(FieldEdit("trace.item_category", trace.item_category, f"one of {allowed_items}"))
        clauses.append(f"the item category were one of {allowed_items}")
    if ScopeViolationReason.MERCHANT_NOT_ALLOWED in result.reasons:
        assert scope.allowed_merchant_ids is not None, "MERCHANT_NOT_ALLOWED cannot fire with no restriction"
        allowed_merchants = sorted(scope.allowed_merchant_ids)
        post_merchant_id = allowed_merchants[0]
        edits.append(FieldEdit("trace.merchant_id", trace.merchant_id, f"one of {allowed_merchants}"))
        clauses.append(f"the merchant were one of {allowed_merchants}")
    if ScopeViolationReason.OUTSIDE_TIME_WINDOW in result.reasons:
        post_session_time = scope.valid_from if trace.started_at < scope.valid_from else scope.valid_until
        edits.append(FieldEdit("trace.started_at", trace.started_at.isoformat(), post_session_time.isoformat()))
        clauses.append(
            f"the session occurred within the mandate's authorized window "
            f"({scope.valid_from.isoformat()} to {scope.valid_until.isoformat()})"
        )

    category_map = _enum_map(
        MERCHANT_CATEGORIES,
        sorted({trace.merchant_category, post_merchant_category, *scope.allowed_merchant_categories}),
    )
    item_map = _enum_map(
        ITEM_CATEGORIES, sorted({trace.item_category, post_item_category, *scope.allowed_item_categories})
    )
    has_merchant_restriction = scope.allowed_merchant_ids is not None
    merchant_map = _enum_map(
        MERCHANT_IDS,
        sorted({trace.merchant_id, post_merchant_id, *(scope.allowed_merchant_ids or frozenset())}),
    )

    v = fresh_scope_vars("cf_scope")
    fixed = [
        _bool_fix(v.mandate_id_match, post_mandate_id_match),
        _bool_fix(v.agent_id_match, post_agent_id_match),
        _bool_fix(v.user_id_match, post_user_id_match),
        v.amount == z3.IntVal(_amount_to_paise(post_amount)),
        v.max_amount == z3.IntVal(_amount_to_paise(scope.max_amount)),
        _bool_fix(v.currency_match, post_currency_match),
        v.merchant_category == category_map[post_merchant_category],
        v.allowed_merchant_categories
        == _z3_set(MerchantCategory, (category_map[c] for c in scope.allowed_merchant_categories)),
        v.item_category == item_map[post_item_category],
        v.allowed_item_categories == _z3_set(ItemCategory, (item_map[c] for c in scope.allowed_item_categories)),
        _bool_fix(v.has_merchant_restriction, has_merchant_restriction),
        v.merchant_id == merchant_map[post_merchant_id],
        v.allowed_merchant_ids
        == _z3_set(MerchantId, (merchant_map[m] for m in (scope.allowed_merchant_ids or frozenset()))),
        v.session_time == z3.IntVal(_dt_to_seconds(post_session_time)),
        v.valid_from == z3.IntVal(_dt_to_seconds(scope.valid_from)),
        v.valid_until == z3.IntVal(_dt_to_seconds(scope.valid_until)),
    ]
    if not _verify(fixed, in_scope(v)):
        raise AssertionError(
            "scope_counterfactual computed an edit that formal.model.in_scope does not accept; "
            "this indicates the two have drifted out of sync"
        )

    explanation = "This verdict flips to ALLOW if " + "; and ".join(clauses) + "."
    logger.info("scope_counterfactual: session %s, %d field(s) edited", trace.session_id, len(edits))
    return Counterfactual(
        layer="layer2_scope", feasible=True, edits=tuple(edits), explanation=explanation, solver_verified=True
    )


def containment_counterfactual(
    mandate: Mandate, chain: AncestorChainResolution, committed_sibling_total: Decimal
) -> Counterfactual | None:
    """Explains a denied Layer 2.5 verdict as the minimal child-mandate edit that would allow it.

    Library-level only -- see the module docstring's scope-boundary
    paragraph on why this is not wired into `/sessions/decide`.

    Args:
        mandate: The delegated mandate under evaluation.
        chain: Its resolved ancestor chain.
        committed_sibling_total: Sum already committed by other children of
            the same parent.

    Returns:
        None if containment already accepts the mandate. A
        `feasible=False` counterfactual if the chain's own topology is
        broken (a cycle, an unresolvable ancestor, or the depth bound
        exceeded), or if a category-subset violation has no non-empty
        overlap with the parent's grant to trim to. Otherwise a feasible,
        solver-verified counterfactual.

    Raises:
        AssertionError: If the computed edit does not satisfy
            `formal.model.contained`, or if containment was violated but no
            field-level edit was derived from its reasons -- see the module
            docstring.
    """
    result = enforce_containment(mandate, chain, committed_sibling_total)
    if result.in_bounds:
        return None
    if chain.broken:
        topology_reasons = [r.value for r in result.reasons]
        return Counterfactual(
            layer="layer2_5_containment",
            feasible=False,
            edits=(),
            explanation=(
                "No field-level counterfactual is available: the delegation chain's own "
                f"topology is broken ({', '.join(topology_reasons)}), independent of any "
                "mandate field's value."
            ),
            solver_verified=False,
        )

    parent = chain.immediate_parent
    assert parent is not None  # guaranteed by enforce_containment when chain.broken is False

    child_scope = mandate.scope
    parent_scope = parent.scope
    edits: list[FieldEdit] = []
    clauses: list[str] = []

    post_currency_match = child_scope.currency == parent_scope.currency
    post_merchant_categories = child_scope.allowed_merchant_categories
    post_item_categories = child_scope.allowed_item_categories
    post_has_merchant_restriction = child_scope.allowed_merchant_ids is not None
    post_merchant_ids = child_scope.allowed_merchant_ids
    post_valid_from = child_scope.valid_from
    post_valid_until = child_scope.valid_until
    post_max_transaction_count = child_scope.max_transaction_count
    post_expires_at = mandate.expires_at

    if ContainmentViolationReason.SCOPE_CURRENCY_MISMATCH in result.reasons:
        post_currency_match = True
        edits.append(FieldEdit("scope.currency", child_scope.currency, parent_scope.currency))
        clauses.append(f"the child's currency were {parent_scope.currency}")

    if ContainmentViolationReason.SCOPE_MERCHANT_CATEGORY_NOT_SUBSET in result.reasons:
        trimmed = child_scope.allowed_merchant_categories & parent_scope.allowed_merchant_categories
        if not trimmed:
            return _no_overlap_counterfactual(
                "merchant categories", sorted(parent_scope.allowed_merchant_categories)
            )
        post_merchant_categories = trimmed
        edits.append(
            FieldEdit(
                "scope.allowed_merchant_categories",
                str(sorted(child_scope.allowed_merchant_categories)),
                str(sorted(trimmed)),
            )
        )
        clauses.append(f"the child's allowed merchant categories were trimmed to {sorted(trimmed)}")

    if ContainmentViolationReason.SCOPE_ITEM_CATEGORY_NOT_SUBSET in result.reasons:
        trimmed_items = child_scope.allowed_item_categories & parent_scope.allowed_item_categories
        if not trimmed_items:
            return _no_overlap_counterfactual("item categories", sorted(parent_scope.allowed_item_categories))
        post_item_categories = trimmed_items
        edits.append(
            FieldEdit(
                "scope.allowed_item_categories",
                str(sorted(child_scope.allowed_item_categories)),
                str(sorted(trimmed_items)),
            )
        )
        clauses.append(f"the child's allowed item categories were trimmed to {sorted(trimmed_items)}")

    if ContainmentViolationReason.SCOPE_MERCHANT_ID_NOT_SUBSET in result.reasons:
        if parent_scope.allowed_merchant_ids is None:
            raise AssertionError("unreachable: SCOPE_MERCHANT_ID_NOT_SUBSET fired with an unrestricted parent")
        if child_scope.allowed_merchant_ids is None:
            post_merchant_ids = parent_scope.allowed_merchant_ids
            post_has_merchant_restriction = True
            edits.append(
                FieldEdit(
                    "scope.allowed_merchant_ids", "unrestricted", str(sorted(parent_scope.allowed_merchant_ids))
                )
            )
            clauses.append(
                "the child declared its own merchant allowlist, a subset of the parent's "
                f"({sorted(parent_scope.allowed_merchant_ids)})"
            )
        else:
            trimmed_merchants = child_scope.allowed_merchant_ids & parent_scope.allowed_merchant_ids
            if not trimmed_merchants:
                return _no_overlap_counterfactual("merchants", sorted(parent_scope.allowed_merchant_ids))
            post_merchant_ids = trimmed_merchants
            edits.append(
                FieldEdit(
                    "scope.allowed_merchant_ids",
                    str(sorted(child_scope.allowed_merchant_ids)),
                    str(sorted(trimmed_merchants)),
                )
            )
            clauses.append(f"the child's allowed merchants were trimmed to {sorted(trimmed_merchants)}")

    if ContainmentViolationReason.SCOPE_WINDOW_NOT_SUBSET in result.reasons:
        if child_scope.valid_from < parent_scope.valid_from:
            post_valid_from = parent_scope.valid_from
            edits.append(
                FieldEdit("scope.valid_from", child_scope.valid_from.isoformat(), parent_scope.valid_from.isoformat())
            )
        if child_scope.valid_until > parent_scope.valid_until:
            post_valid_until = parent_scope.valid_until
            edits.append(
                FieldEdit(
                    "scope.valid_until", child_scope.valid_until.isoformat(), parent_scope.valid_until.isoformat()
                )
            )
        clauses.append(
            "the child's authorized window fit within the parent's "
            f"({parent_scope.valid_from.isoformat()} to {parent_scope.valid_until.isoformat()})"
        )

    if ContainmentViolationReason.SCOPE_TRANSACTION_COUNT_EXCEEDS_PARENT in result.reasons:
        post_max_transaction_count = parent_scope.max_transaction_count
        edits.append(
            FieldEdit(
                "scope.max_transaction_count",
                str(child_scope.max_transaction_count),
                str(parent_scope.max_transaction_count),
            )
        )
        clauses.append(f"the child's max_transaction_count were at most {parent_scope.max_transaction_count}")

    if ContainmentViolationReason.EXPIRY_EXCEEDS_PARENT in result.reasons:
        post_expires_at = parent.expires_at
        edits.append(FieldEdit("expires_at", mandate.expires_at.isoformat(), parent.expires_at.isoformat()))
        clauses.append(f"the child's expires_at were at or before the parent's ({parent.expires_at.isoformat()})")

    amount_bounds: list[Decimal] = []
    if ContainmentViolationReason.SCOPE_AMOUNT_EXCEEDS_PARENT in result.reasons:
        amount_bounds.append(parent_scope.max_amount)
    if ContainmentViolationReason.SIBLING_CAP_EXCEEDS_PARENT_REMAINING in result.reasons:
        amount_bounds.append(parent_scope.max_amount - committed_sibling_total)
    post_max_amount = child_scope.max_amount
    if amount_bounds:
        post_max_amount = min(amount_bounds)
        edits.append(FieldEdit("scope.max_amount", str(child_scope.max_amount), str(post_max_amount)))
        if len(amount_bounds) == 2:
            clauses.append(
                f"the child's max_amount were at most {post_max_amount} {parent_scope.currency} (bounded by "
                "both the parent's own ceiling and its remaining budget after sibling mandates)"
            )
        else:
            clauses.append(f"the child's max_amount were at most {post_max_amount} {parent_scope.currency}")

    if not edits:
        raise AssertionError("containment violated but no field-level edit was derived from its reasons")

    category_map = _enum_map(
        MERCHANT_CATEGORIES,
        sorted(
            {
                *child_scope.allowed_merchant_categories,
                *post_merchant_categories,
                *parent_scope.allowed_merchant_categories,
            }
        ),
    )
    item_map = _enum_map(
        ITEM_CATEGORIES,
        sorted({*child_scope.allowed_item_categories, *post_item_categories, *parent_scope.allowed_item_categories}),
    )
    merchant_map = _enum_map(
        MERCHANT_IDS,
        sorted(
            {
                *(child_scope.allowed_merchant_ids or frozenset()),
                *(post_merchant_ids or frozenset()),
                *(parent_scope.allowed_merchant_ids or frozenset()),
            }
        ),
    )

    v = fresh_containment_vars("cf_containment")
    fixed = [
        v.child_max_amount == z3.IntVal(_amount_to_paise(post_max_amount)),
        v.parent_max_amount == z3.IntVal(_amount_to_paise(parent_scope.max_amount)),
        _bool_fix(v.currency_match, post_currency_match),
        v.child_merchant_categories
        == _z3_set(MerchantCategory, (category_map[c] for c in post_merchant_categories)),
        v.parent_merchant_categories
        == _z3_set(MerchantCategory, (category_map[c] for c in parent_scope.allowed_merchant_categories)),
        v.child_item_categories == _z3_set(ItemCategory, (item_map[c] for c in post_item_categories)),
        v.parent_item_categories
        == _z3_set(ItemCategory, (item_map[c] for c in parent_scope.allowed_item_categories)),
        _bool_fix(v.parent_has_merchant_restriction, parent_scope.allowed_merchant_ids is not None),
        _bool_fix(v.child_has_merchant_restriction, post_has_merchant_restriction),
        v.child_merchant_ids
        == _z3_set(MerchantId, (merchant_map[m] for m in (post_merchant_ids or frozenset()))),
        v.parent_merchant_ids
        == _z3_set(MerchantId, (merchant_map[m] for m in (parent_scope.allowed_merchant_ids or frozenset()))),
        v.child_valid_from == z3.IntVal(_dt_to_seconds(post_valid_from)),
        v.child_valid_until == z3.IntVal(_dt_to_seconds(post_valid_until)),
        v.parent_valid_from == z3.IntVal(_dt_to_seconds(parent_scope.valid_from)),
        v.parent_valid_until == z3.IntVal(_dt_to_seconds(parent_scope.valid_until)),
        v.child_max_transaction_count == z3.IntVal(post_max_transaction_count),
        v.parent_max_transaction_count == z3.IntVal(parent_scope.max_transaction_count),
        v.child_expires_at == z3.IntVal(_dt_to_seconds(post_expires_at)),
        v.parent_expires_at == z3.IntVal(_dt_to_seconds(parent.expires_at)),
        v.committed_sibling_total == z3.IntVal(_amount_to_paise(committed_sibling_total)),
        v.depth == z3.IntVal(len(chain.ancestors)),
        _bool_fix(v.cycle_detected, chain.cycle_detected),
        _bool_fix(v.unresolvable, chain.unresolvable),
    ]
    if not _verify(fixed, contained(v)):
        raise AssertionError(
            "containment_counterfactual computed an edit that formal.model.contained does not "
            "accept; this indicates the two have drifted out of sync"
        )

    explanation = "This verdict flips to in-bounds if " + "; and ".join(clauses) + "."
    logger.info("containment_counterfactual: mandate %s, %d field(s) edited", mandate.mandate_id, len(edits))
    return Counterfactual(
        layer="layer2_5_containment", feasible=True, edits=tuple(edits), explanation=explanation, solver_verified=True
    )


def _no_overlap_counterfactual(dimension: str, parent_allowed: list[str]) -> Counterfactual:
    """Builds the honest infeasible result for a category-subset trim with no overlap.

    Args:
        dimension: Human name of the set dimension with no overlap (e.g.
            `"merchant categories"`).
        parent_allowed: The parent's allowed set, for the explanation.

    Returns:
        A `feasible=False` counterfactual stating why no minimal trim exists.
    """
    return Counterfactual(
        layer="layer2_5_containment",
        feasible=False,
        edits=(),
        explanation=(
            f"No minimal-edit counterfactual exists: the child's requested {dimension} share no "
            f"overlap at all with the parent's allowed set ({parent_allowed}); the child would "
            "need an entirely different grant, not a trimmed one."
        ),
        solver_verified=False,
    )
