"""Tests for `generator.legitimate`: reproducibility and scope consistency."""

from __future__ import annotations

import pytest

from common.schema import AttackClass
from generator.legitimate import generate_legitimate_sessions
from mandate.verification import MandateLedger, verify_mandate

N_SESSIONS = 150
SEED = 42


def test_generates_requested_count() -> None:
    """The generator must produce exactly the requested number of sessions."""
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    assert len(out.labeled_sessions) == N_SESSIONS


def test_rejects_non_positive_session_count() -> None:
    """A zero or negative session count is a caller error, not zero output."""
    with pytest.raises(ValueError, match="must be positive"):
        generate_legitimate_sessions(0, seed=SEED)


def test_same_seed_is_byte_identical() -> None:
    """Two runs with the same (n_sessions, seed) must produce identical traces.

    This is the reproducibility guarantee Section 5 requires of the
    committed generator: the same seed must always produce the same data,
    including UUIDs and key material, not just the same distributional
    shape.
    """
    out_a = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    out_b = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    assert [s.trace.model_dump() for s in out_a.labeled_sessions] == [
        s.trace.model_dump() for s in out_b.labeled_sessions
    ]


def test_same_seed_reproduces_mandate_signatures() -> None:
    """Signatures, not just trace content, must be reproducible across runs."""
    out_a = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    out_b = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    for mandate_id, signed_a in out_a.signed_mandates.items():
        assert out_b.signed_mandates[mandate_id].signature == signed_a.signature


def test_different_seed_produces_different_output() -> None:
    """A different seed must not coincidentally reproduce the same first session."""
    out_a = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    out_b = generate_legitimate_sessions(N_SESSIONS, seed=SEED + 1)
    assert (
        out_a.labeled_sessions[0].trace.model_dump()
        != out_b.labeled_sessions[0].trace.model_dump()
    )


def test_every_session_stays_inside_its_mandate_scope() -> None:
    """Every generated session's amount, merchant, category, and timing must be in-scope.

    This is the core correctness property of a *legitimate* generator: if
    this test can fail, the generator is silently producing scope
    violations mislabeled as legitimate, which would corrupt every metric
    downstream.
    """
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    for labeled in out.labeled_sessions:
        trace = labeled.trace
        assert trace.mandate_id is not None, "legitimate sessions always present a mandate"
        scope = out.signed_mandates[trace.mandate_id].mandate.scope

        assert trace.amount <= scope.max_amount
        assert trace.merchant_category in scope.allowed_merchant_categories
        assert trace.item_category in scope.allowed_item_categories
        if scope.allowed_merchant_ids is not None:
            assert trace.merchant_id in scope.allowed_merchant_ids
        assert scope.valid_from <= trace.started_at <= scope.valid_until


def test_every_session_mandate_verifies_at_its_own_session_time() -> None:
    """Replaying sessions through a ledger in order, every mandate must verify valid.

    Verifies the generator's output is consumable by Layer 1 as-is: no
    fixture massaging required for a downstream rules baseline (Day 3) to
    treat every one of these sessions as legitimate.
    """
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    ledger = MandateLedger()
    for labeled in out.labeled_sessions:
        assert labeled.trace.mandate_id is not None, "legitimate sessions always present a mandate"
        signed = out.signed_mandates[labeled.trace.mandate_id]
        result = verify_mandate(signed, out.registry, ledger, now=labeled.trace.started_at)
        assert result.valid, f"session {labeled.trace.session_id} failed: {result.reasons}"
        ledger.record_usage(signed.mandate.mandate_id)


def test_some_mandates_are_reused_across_sessions() -> None:
    """The recurring-mandate path must actually trigger at the configured probability.

    A generator that never reuses mandates would make the mandate-replay
    attack generator (Day 2) unable to find a legitimately-issued,
    partially-spent mandate to imitate.
    """
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    assert len(out.signed_mandates) < len(out.labeled_sessions)


def test_all_labels_are_legitimate() -> None:
    """This generator must only ever emit the LEGITIMATE label."""
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    assert all(s.attack_class == AttackClass.LEGITIMATE for s in out.labeled_sessions)
    assert all(not s.is_attack for s in out.labeled_sessions)


def test_sessions_sorted_by_start_time() -> None:
    """Output must be chronologically sorted for downstream sequence processing."""
    out = generate_legitimate_sessions(N_SESSIONS, seed=SEED)
    timestamps = [s.trace.started_at for s in out.labeled_sessions]
    assert timestamps == sorted(timestamps)