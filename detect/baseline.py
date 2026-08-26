"""The rules-only baseline: Layer 1 plus Layer 2, no machine learning.

This is the number every later model has to beat — if the behavioral model
doesn't improve on it with statistical significance, the model gets dropped
and that gets reported.

Two properties keep this a fair comparator rather than a strawman:

- Stateful the way Layer 1 requires: mandate budgets are consumed as
  sessions are scored, in chronological order, so a replayed mandate reads
  as spent.
- Budget is consumed only on sessions the baseline *allows*. A blocked
  transaction never reaches authorization, so it never spends the mandate —
  otherwise a flood of rejected sessions could exhaust a legitimate user's
  budget.

Emits a hard verdict, not a score. Threshold sweeps belong to the scored
ensemble; a rules engine has one operating point by construction.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from common.schema import SessionTrace
from detect.resolution import MandateResolver
from detect.scope import ScopeViolationReason, enforce_scope
from mandate.verification import (
    AgentKeyRegistry,
    MandateLedger,
    VerificationFailureReason,
    verify_mandate,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BaselineDecision:
    """The rules-only verdict for one session, with its justification.

    Attributes:
        session_id: The session decided on.
        blocked: True if any Layer 1 or Layer 2 rule fired.
        verification_reasons: Layer 1 failures, empty if Layer 1 passed.
        scope_reasons: Layer 2 failures, empty if Layer 2 passed.
    """

    session_id: UUID
    blocked: bool
    verification_reasons: tuple[VerificationFailureReason, ...]
    scope_reasons: tuple[ScopeViolationReason, ...]

    @property
    def fired_rules(self) -> tuple[str, ...]:
        """Names every rule that fired, across both layers.

        Returns:
            Rule names prefixed by layer, for audit display and the gate
            report's per-rule breakdown.
        """
        return tuple(
            [f"layer1:{r.value}" for r in self.verification_reasons]
            + [f"layer2:{r.value}" for r in self.scope_reasons]
        )


class RulesOnlyBaseline:
    """Scores sessions using only the deterministic Layer 1 and Layer 2 rules.

    Stateful across a run because Layer 1's budget check is. Construct one
    per evaluation run — reusing an instance across two runs carries ledger
    state between them.
    """

    def __init__(self, registry: AgentKeyRegistry, resolver: MandateResolver) -> None:
        """Initializes the baseline with its injected dependencies.

        Args:
            registry: Registry of public keys trusted to sign for each agent.
            resolver: Resolves the mandate document each session presented.
        """
        self._registry = registry
        self._resolver = resolver
        self._ledger = MandateLedger()

    @property
    def ledger(self) -> MandateLedger:
        """Exposes the ledger accumulated so far.

        Returns:
            The live ledger, for inspection in tests and audit tooling.
        """
        return self._ledger

    def decide(self, trace: SessionTrace) -> BaselineDecision:
        """Produces a verdict for a single session and advances ledger state.

        Args:
            trace: The session to decide on. Must be passed in chronological
                order — out-of-order calls evaluate the budget rule against
                a ledger from the future.

        Returns:
            The decision, including every rule that fired.
        """
        signed = self._resolver.resolve(trace.session_id)

        if signed is None:
            scope_result = enforce_scope(trace, None)
            return BaselineDecision(
                session_id=trace.session_id,
                blocked=True,
                verification_reasons=(),
                scope_reasons=scope_result.reasons,
            )

        verification = verify_mandate(signed, self._registry, self._ledger, now=trace.started_at)
        scope_result = enforce_scope(trace, signed)
        blocked = not verification.valid or not scope_result.in_scope

        if not blocked:
            self._ledger.record_usage(signed.mandate.mandate_id)

        return BaselineDecision(
            session_id=trace.session_id,
            blocked=blocked,
            verification_reasons=verification.reasons,
            scope_reasons=scope_result.reasons,
        )

    def decide_all(self, traces: Iterable[SessionTrace]) -> tuple[BaselineDecision, ...]:
        """Decides a chronologically ordered stream of sessions.

        Args:
            traces: Sessions in ascending `started_at` order.

        Returns:
            One decision per session, in input order.

        Raises:
            ValueError: If the sessions are not in ascending start-time
                order — an unsorted stream would silently produce plausible
                but wrong budget-rule results.
        """
        decisions: list[BaselineDecision] = []
        previous_start = None
        for trace in traces:
            if previous_start is not None and trace.started_at < previous_start:
                raise ValueError(
                    f"session {trace.session_id} starts before the previous session; "
                    f"the baseline requires chronologically ordered input"
                )
            previous_start = trace.started_at
            decisions.append(self.decide(trace))
        logger.info("baseline decided %d sessions", len(decisions))
        return tuple(decisions)