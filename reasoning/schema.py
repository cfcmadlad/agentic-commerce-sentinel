"""Types for Layer 4: narration input, narration output, and the audit record.

Kept separate from the narration and audit-log logic (`narrate.py`,
`audit_log.py`) so the type contracts -- what the narration layer is given,
what it produces, and what gets persisted -- are visible in one place. This
mirrors the split this project already uses between `mandate/schema.py`
(pure data) and `mandate/verification.py` (logic that acts on that data).

`NarrationInput` and `Narration` are both frozen dataclasses, and neither
holds a live reference to a `detect.baseline.BaselineDecision` or
`detect.ensemble.EnsembleDecision` instance -- every field is a value copied
out of those types at construction time (see
`reasoning.narrate.build_narration_input`). This is what makes it structural,
not conventional, that the narration layer cannot write back into a verdict:
there is no field on either type whose mutation, or whose value, could
change what Layers 1-3 already decided, and no function anywhere in
`reasoning/` accepts a `Narration` and returns or updates a decision type.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(frozen=True)
class NarrationInput:
    """Everything the narration layer is given about one already-decided session.

    Attributes:
        session_id: The session this narration is about.
        mandate_id: The mandate presented in the session, if any.
        merchant_id: Merchant identifier from the session trace. Nominally
            free text -- see the module docstring of `reasoning.narrate` for
            why this field is treated as untrusted data, never instructions.
        merchant_category: Merchant category from the session trace. Same
            free-text caveat as `merchant_id`.
        item_category: Item category from the session trace. Same free-text
            caveat as `merchant_id`.
        amount: Transaction amount.
        currency: ISO 4217 currency code.
        blocked: The final verdict, copied from `EnsembleDecision.blocked`.
        source: Which layer produced the verdict (`detect.ensemble.SOURCE_*`).
        rules_fired: Every Layer 1/2 rule name that fired, copied from
            `EnsembleDecision.rules_fired`. Empty when no rule fired.
        behavioral_score: The Layer 3 score, if one was computed for this
            session. None when the rules already blocked the session before
            Layer 3 was consulted.
        threshold: The calibrated operating threshold in effect when this
            session was scored, if a score was computed. None otherwise.
        top_features: Signed per-session SHAP attribution (feature name,
            contribution), largest absolute contribution first, from
            `detect.attribution.explain_row`. Empty when no attribution is
            available for this session -- for example, a session the rules
            already blocked, or a corpus attribution was never computed
            for (see `reasoning.narrate`'s reuse note for the held-out
            corpus).
    """

    session_id: UUID
    mandate_id: UUID | None
    merchant_id: str
    merchant_category: str
    item_category: str
    amount: Decimal
    currency: str
    blocked: bool
    source: str
    rules_fired: tuple[str, ...]
    behavioral_score: float | None
    threshold: float | None
    top_features: tuple[tuple[str, float], ...]


@dataclass(frozen=True)
class Narration:
    """The narration layer's complete output for one session.

    Deliberately has no field typed as `EnsembleDecision`, `BaselineDecision`,
    or any other type from `detect/` -- there is no compatible field for
    such a value to occupy, so narration output cannot be threaded back into
    those modules even by a future caller's mistake. `verdict_summary` is a
    plain string derived once, in `reasoning.narrate.narrate`, directly from
    the immutable `NarrationInput` it was given -- never parsed or inferred
    from the LLM's own response text, so a prompt-injected response cannot
    change what this object reports as the verdict.

    Attributes:
        session_id: The session this narration is about.
        verdict_summary: Plain-text verdict, e.g. "blocked (rules)" or
            "allowed" -- derived from `NarrationInput`, not from `narrative`.
        narrative: The LLM-authored plain-language explanation.
        rule_citations: Rule names the narrative was instructed to cite,
            copied from the `NarrationInput` it was built from.
        feature_citations: Feature names the narrative was instructed to
            cite, copied from the `NarrationInput` it was built from.
        model: Identifier of the model that generated `narrative`.
        generated_at: UTC time this narration was produced. Not
            reproducible run-to-run by nature -- see `reasoning.narrate`'s
            module docstring.
    """

    session_id: UUID
    verdict_summary: str
    narrative: str
    rule_citations: tuple[str, ...]
    feature_citations: tuple[str, ...]
    model: str
    generated_at: datetime


@dataclass(frozen=True)
class AuditRecord:
    """One append-only audit-log entry: everything about one decision, at rest.

    Attributes:
        record_id: Unique identifier for this audit entry, distinct from
            `session_id` so two audit entries could in principle exist for
            one session (e.g. a re-narration) without colliding.
        session_id: The session this record documents.
        mandate_id: The mandate presented in the session, if any.
        blocked: The final verdict.
        source: Which layer produced the verdict (`detect.ensemble.SOURCE_*`).
        rules_fired: Every Layer 1/2 rule name that fired.
        behavioral_score: The Layer 3 score, if computed.
        top_features: Signed per-session SHAP attribution, as in
            `NarrationInput.top_features`.
        narrative: The plain-language explanation produced for this record.
        narrated_by_model: Identifier of the model that produced `narrative`.
        created_at: UTC time this record was appended to the audit log.
    """

    record_id: UUID
    session_id: UUID
    mandate_id: UUID | None
    blocked: bool
    source: str
    rules_fired: tuple[str, ...]
    behavioral_score: float | None
    top_features: tuple[tuple[str, float], ...]
    narrative: str
    narrated_by_model: str
    created_at: datetime
