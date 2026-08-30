"""Human-in-the-loop escalation queue and per-agent circuit breaker.

A session Layer 3 flags for hold (`detect.ensemble.SOURCE_BEHAVIORAL` --
neither deterministic layer blocked it, but the behavioral score crossed
the calibrated threshold) is not itself an enforcement action anywhere in
this project; every other layer's own documentation and this project's
frontend both already state the same thing: "a detector and verifier, not
an autonomous enforcement system." This package is what makes that
statement structural rather than aspirational for the one case where a
human actually needs to look at something -- an `Escalation` is opened,
tracked through `open -> reviewed -> resolved`, and every transition is
recorded with the acting party, in a hash-chained log of its own
(`escalation/log.py`, built on the shared primitives in
`common/hash_chain.py`).

The circuit breaker is a separate, deterministic escalation: if an agent
accumulates enough escalated verdicts within a rolling window, it is
suspended outright -- and stays suspended until a human explicitly resets
it, never automatically and never by the triggering escalations aging out
of the window. This is the one place in this package that gates something
real (`service/main.py::decide` hard-blocks any session from a suspended
agent before running the ordinary layers at all), and it is worth stating
plainly what it is not: not a fraud model, not a learned threshold, not
tunable by anything other than its two named constants -- a suspended
agent is exactly as auditable and as reversible-by-a-human as everything
else this project ships.
"""

from __future__ import annotations
