"""Tests for `detect.ensemble`: combining the rules verdict with the Layer 3 score."""

from __future__ import annotations

from uuid import uuid4

import pytest

from detect.baseline import BaselineDecision
from detect.ensemble import SOURCE_ALLOWED, SOURCE_BEHAVIORAL, SOURCE_RULES, ensemble_decide
from detect.scope import ScopeViolationReason
from mandate.verification import VerificationFailureReason


def _blocked_decision() -> BaselineDecision:
    """Builds a decision the rules already blocked.

    Returns:
        A blocked `BaselineDecision`.
    """
    return BaselineDecision(
        session_id=uuid4(),
        blocked=True,
        verification_reasons=(VerificationFailureReason.EXPIRED,),
        scope_reasons=(),
    )


def _allowed_decision() -> BaselineDecision:
    """Builds a decision the rules allowed through.

    Returns:
        An allowed `BaselineDecision`.
    """
    return BaselineDecision(session_id=uuid4(), blocked=False, verification_reasons=(), scope_reasons=())


def test_rules_block_wins_regardless_of_score() -> None:
    """A rules block must stand even if a behavioral score is also provided."""
    decision = ensemble_decide(_blocked_decision(), behavioral_score=0.01, threshold=0.9)
    assert decision.blocked
    assert decision.source == SOURCE_RULES


def test_rules_block_wins_with_no_score_at_all() -> None:
    """A rules block must not require a behavioral score to stand."""
    decision = ensemble_decide(_blocked_decision(), behavioral_score=None, threshold=0.5)
    assert decision.blocked
    assert decision.source == SOURCE_RULES


def test_score_above_threshold_blocks_a_rules_allowed_session() -> None:
    """The behavioral layer can add a block the rules did not find."""
    decision = ensemble_decide(_allowed_decision(), behavioral_score=0.8, threshold=0.5)
    assert decision.blocked
    assert decision.source == SOURCE_BEHAVIORAL


def test_score_below_threshold_allows_the_session() -> None:
    """A low behavioral score must not override a rules allow into a block."""
    decision = ensemble_decide(_allowed_decision(), behavioral_score=0.2, threshold=0.5)
    assert not decision.blocked
    assert decision.source == SOURCE_ALLOWED


def test_score_exactly_at_threshold_blocks() -> None:
    """The threshold comparison is inclusive."""
    decision = ensemble_decide(_allowed_decision(), behavioral_score=0.5, threshold=0.5)
    assert decision.blocked


def test_missing_score_on_a_rules_allowed_session_is_rejected() -> None:
    """Every rules-allowed session must be scored; a missing score is a caller bug."""
    with pytest.raises(ValueError, match="no behavioral score"):
        ensemble_decide(_allowed_decision(), behavioral_score=None, threshold=0.5)


def test_blocked_decision_preserves_fired_rules() -> None:
    """The rules that fired must survive into the ensemble decision for audit."""
    blocked = BaselineDecision(
        session_id=uuid4(),
        blocked=True,
        verification_reasons=(),
        scope_reasons=(ScopeViolationReason.AMOUNT_OVER_CEILING,),
    )
    decision = ensemble_decide(blocked, behavioral_score=None, threshold=0.5)
    assert decision.rules_fired == ("layer2:amount_over_ceiling",)