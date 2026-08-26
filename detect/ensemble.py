"""Combines the Layer 1/2 verdict with the Layer 3 score into one decision.

The rule this module enforces is narrow on purpose: if Layers 1 or 2 already
blocked a session, Layer 3 cannot unblock it. Layer 3 only ever adds
coverage on sessions the deterministic layers already allowed. This keeps
the deterministic layers' guarantees intact regardless of what the model
does — a bug or drift in Layer 3 can, at worst, fail to catch something new;
it can never override a Layer 1 signature failure or a Layer 2 scope breach.

The combination itself is deterministic given the score and threshold. The
score comes from `detect/behavioral.py`; the threshold comes from a
`CalibrationResult` chosen in `detect/calibration.py`. This module performs
no learning and no narration — an LLM reasoning layer elsewhere in this
project may explain an `EnsembleDecision` after the fact, but never produces
one.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from detect.baseline import BaselineDecision

SOURCE_RULES = "rules"
SOURCE_BEHAVIORAL = "behavioral"
SOURCE_ALLOWED = "allowed"


@dataclass(frozen=True)
class EnsembleDecision:
    """The final verdict for one session, with its source and evidence.

    Attributes:
        session_id: The session decided on.
        blocked: The final block/allow verdict.
        source: Which layer produced the block — `SOURCE_RULES` if Layer 1
            or 2 fired, `SOURCE_BEHAVIORAL` if only the Layer 3 score crossed
            the threshold, or `SOURCE_ALLOWED` if nothing fired.
        behavioral_score: The Layer 3 score, if it was computed. None when
            the rules already blocked the session and Layer 3 was not
            consulted for the verdict.
        rules_fired: Every Layer 1/2 rule that fired, from the underlying
            `BaselineDecision`.
    """

    session_id: UUID
    blocked: bool
    source: str
    behavioral_score: float | None
    rules_fired: tuple[str, ...]


def ensemble_decide(
    baseline_decision: BaselineDecision,
    behavioral_score: float | None,
    threshold: float,
) -> EnsembleDecision:
    """Combines a rules verdict with a Layer 3 score into a final decision.

    Args:
        baseline_decision: The Layer 1/2 verdict for this session.
        behavioral_score: The Layer 3 score for this session, or None if it
            was not computed (for example because the session was already
            blocked by the rules and scoring it would be wasted work).
        threshold: The calibrated cutoff at or above which the behavioral
            score alone blocks a session.

    Returns:
        The combined decision.

    Raises:
        ValueError: If the rules allowed the session but no behavioral score
            was provided. A session the deterministic layers passed through
            must be scored; silently treating a missing score as "allow"
            would make the ensemble's coverage depend on an unlogged
            upstream failure rather than a deliberate decision.
    """
    if baseline_decision.blocked:
        return EnsembleDecision(
            session_id=baseline_decision.session_id,
            blocked=True,
            source=SOURCE_RULES,
            behavioral_score=behavioral_score,
            rules_fired=baseline_decision.fired_rules,
        )

    if behavioral_score is None:
        raise ValueError(
            f"session {baseline_decision.session_id} was allowed by the rules but has no "
            f"behavioral score; every rules-allowed session must be scored"
        )

    blocked = behavioral_score >= threshold
    return EnsembleDecision(
        session_id=baseline_decision.session_id,
        blocked=blocked,
        source=SOURCE_BEHAVIORAL if blocked else SOURCE_ALLOWED,
        behavioral_score=behavioral_score,
        rules_fired=(),
    )