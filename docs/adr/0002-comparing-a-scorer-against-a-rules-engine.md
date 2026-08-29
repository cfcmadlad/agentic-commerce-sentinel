# ADR 0002: Comparing a scored detector against a rules engine

## Status
Accepted

## Context
The evaluation has to answer one question: does Layer 3 earn its place on top
of the deterministic rules layers. Two of the metrics the project committed to
turn out to be awkward against this particular comparator, and both awkwardnesses
are structural rather than incidental, so they need a recorded decision rather
than a choice made silently inside a formatting function.

**The baseline does not produce a ranking.** AUC-ROC, AUC-PR and DeLong's test
are all defined over an ordering of the scored population. `RulesOnlyBaseline`
emits a hard block/allow verdict; there is no ordering within the blocked group
or within the allowed group, because a rules engine has exactly one operating
point by construction. `eval/ensemble_evaluation.py` sidesteps the issue
entirely: it computes no AUC at all and compares the two systems only as
hard classifiers, so no convention for scoring the baseline as a ranking
existed to inherit here.

**The baseline's precision is 1.0, and is 1.0 by construction.** The legitimate
generator places every legitimate session inside its own mandate's scope, so no
Layer 1 or Layer 2 rule can fire on one. This is a correctness property of the
generator and the scope engine agreeing, and it is reported as such in the
README rather than as an achievement. But it means the project's own standing
gate -- "beat the rules-only baseline on precision at fixed recall, with
significance, or drop Layer 3" -- is unsatisfiable as literally written. A
comparator at perfect precision cannot be beaten on precision at any recall by
any detector whatsoever. It can only be tied.

## Decision

**Score the baseline as binary, and say what that costs.** The baseline is
scored 1.0 when it blocks and 0.0 when it allows. This is the honest
representation of what it emits and the whole of the information it provides.
The midrank Mann-Whitney kernel used in `eval/metrics.py` and `eval/delong.py`
handles the resulting ties by construction -- a tied pair contributes 0.5 -- so
DeLong is well defined here rather than undefined, which is worth stating
plainly because the opposite is a common assumption. What is true is that the
baseline's AUC collapses to balanced accuracy, `(sensitivity + specificity) / 2`,
and carries no ranking information. `DeLongResult.baseline_is_degenerate` and
`ScoreSummary.is_binary_score` carry that fact onto the result object so a
report cannot print the AUC without the caveat, and
`tests/test_metrics.py::test_binary_score_auc_equals_balanced_accuracy` pins the
equivalence rather than leaving it as prose.

Two rejected alternatives. A pseudo-continuous score built from the count or
severity of rules fired would buy a little ordering among blocked sessions, at
the cost of asserting an ordering the baseline does not actually claim -- "three
rules fired is more suspicious than one" is an invention, not a property of the
system. Omitting DeLong entirely would dodge a committed deliverable. Reporting
it with its limitation attached is more useful than either.

**Report the gate both ways, and decide on the reading that is not
foreclosed.** `GateAssessment` carries the literal comparison
(`precision_gate_passed`, plus `baseline_precision_is_saturated` diagnosing why
it reads False) and the complementary one
(`recall_gain_at_baseline_precision`: how much recall Layer 3 adds without
giving up any of the baseline's precision). The verdict,
`layer3_earns_its_place`, rests on the second together with the paired McNemar
test, because that is the comparison the gate was actually trying to make. Both
readings are computed and printed on every run; neither is selected after seeing
the numbers.

The paired McNemar test at the operating point remains the primary significance
test, since it is the correct test for two hard classifiers evaluated on the
same sessions. DeLong is reported as a secondary, low-resolution check.

## Consequences

- `precision_gate_passed` will read False on every run against this corpus. That
  is expected and diagnosed, not a failing result, and anyone reading the report
  sees the reason on the adjacent line.
- If the baseline ever stops being precision-saturated -- a scope-engine bug, or
  a future generator that produces genuinely ambiguous legitimate traffic -- the
  literal reading becomes informative again and the gate reports it without
  needing a change.
- A Layer 3 that reproduced the rules-only outcome exactly would leave McNemar
  with no discordant pairs and DeLong with no variance. Both are undefined
  there, and rather than propagating an exception, `_assess_gate` reports the
  degenerate case as the decisive gate failure it is: a layer that changes no
  decision adds nothing. `GateAssessment.is_degenerate` records it.
- The DeLong number is weaker evidence than the McNemar number here, and the
  report says so in the output rather than only in this document.
- None of this changes what would be reported if Layer 3 genuinely failed. The
  gate's failure paths are exercised directly in `tests/test_full_evaluation.py`,
  including the case where Layer 3 adds recall but not significantly, and the
  case where it adds none at all.
