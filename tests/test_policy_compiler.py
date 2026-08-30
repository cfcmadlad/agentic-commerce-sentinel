"""Targeted tests for `policy.compiler`, narrower than the full corpus identity check."""

from __future__ import annotations

from decimal import Decimal

from mandate.signing import generate_keypair, sign_mandate
from policy.compiler import compile_policy
from policy.loader import load_default_policy
from tests.factories import build_mandate, build_scope, build_session_trace

_COMPILED = compile_policy(load_default_policy())


def test_version_matches_the_loaded_document() -> None:
    """CompiledPolicy.version must reflect the document's own policy_version."""
    assert _COMPILED.version == "1.0.0"


def test_compliant_session_fires_no_rules() -> None:
    """A session fully within its mandate's scope must produce an empty reasons tuple."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key)
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(mandate_id=mandate.mandate_id, agent_id=mandate.agent_id, user_id=mandate.user_id)
    assert _COMPILED.evaluate(trace, signed) == ()


def test_unrestricted_merchant_ids_never_fires_merchant_not_allowed() -> None:
    """allowed_merchant_ids=None must mean unrestricted, matching enforce_scope's own documented meaning."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=None))
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        merchant_id="any-merchant-at-all",
    )
    assert "merchant_not_allowed" not in _COMPILED.evaluate(trace, signed)


def test_restricted_merchant_ids_fires_when_merchant_not_in_the_list() -> None:
    """An explicit merchant allowlist must be enforced when present."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=build_scope(allowed_merchant_ids=frozenset({"bigbasket"})))
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id, agent_id=mandate.agent_id, user_id=mandate.user_id, merchant_id="blinkit"
    )
    assert "merchant_not_allowed" in _COMPILED.evaluate(trace, signed)


def test_multiple_violations_are_all_reported_in_document_order() -> None:
    """Several simultaneous violations must all be reported, in the rules' declared order."""
    private_key, _ = generate_keypair()
    mandate = build_mandate(private_key, scope=build_scope(max_amount=Decimal("100"), currency="INR"))
    signed = sign_mandate(mandate, private_key)
    trace = build_session_trace(
        mandate_id=mandate.mandate_id,
        agent_id=mandate.agent_id,
        user_id=mandate.user_id,
        amount=Decimal("5000.00"),
        currency="USD",
    )
    reasons = _COMPILED.evaluate(trace, signed)
    assert reasons == ("amount_over_ceiling", "currency_mismatch")
