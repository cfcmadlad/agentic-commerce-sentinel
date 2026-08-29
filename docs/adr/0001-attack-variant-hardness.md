# ADR 0001: Impersonation attack-variant hardness

## Status
Accepted

## Context
The behavioral-only impersonation variant and rapid-reuse replay are the two
attack types no deterministic rule can see -- Layer 3 exists specifically to
catch them. The generator's pacing bounds for the scripted client
(`MAX_SCRIPTED_EVENT_GAP_SECONDS`) and its browse-skip probability
(`SKIP_BROWSE_PROBABILITY`) directly control how separable that traffic is
from legitimate sessions.

At the original bounds (1-6s gap, 0.6 skip probability), a single-feature
threshold on event timing alone achieved a meaningfully high AUC-PR on the
rules-invisible residual. A model trained on that data could appear to beat
the rules baseline while mostly reconstructing one threshold rule -- a result
that would not survive a panel asking "what is the model actually learning."

## Decision
Widen `MAX_SCRIPTED_EVENT_GAP_SECONDS` from 6 to 20 and lower
`SKIP_BROWSE_PROBABILITY` from 0.6 to 0.35, so scripted-client pacing overlaps
further into the legitimate 2-45s jitter range and browse-skipping is a
minority rather than majority pattern within the class.

## Consequences
- The behavioral model has a harder, more defensible separation task; a
  reported win is less likely to be a restated single-rule threshold.
- Recall on this variant may come in lower than it would have under the
  easier setting. That is treated as an honest result, not a regression to
  fix by reverting this decision.
- If the behavioral model cannot beat the rules-only baseline with
  statistical significance under this setting, per project policy that is
  reported plainly and the model is dropped, not re-tuned against the
  held-out class or walked back to the easier bounds to manufacture a win.
- The ensemble evaluation's own diagnostics confirmed that even under this harder
  setting, the model's separation of `behavioral_only` is not attributable to
  a single feature: clock-time, amount, and session-composition features
  score at base-rate AUC-PR in isolation, and pacing alone (without
  reuse-timing features) only reaches AUC-PR 0.31 on the isolated two-class
  problem. The reported result comes from combining pacing, browse-skip, and
  reuse-timing signal jointly, trained across all three attack classes.