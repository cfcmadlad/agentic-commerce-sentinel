"""Layer 2.5: deterministic delegation-chain containment.

A new, separately-labelled layer sitting between Layer 2 (scope enforcement,
`detect/scope.py`) and Layer 3 (behavioral anomaly detection, `detect/
behavioral.py`) in the pipeline. Layers 1-3 each reason about one mandate, or
one session against one mandate, in isolation; none of them compare a
mandate's authority to the authority of the mandate it was delegated from.
This package closes exactly that gap, and only that gap: it receives a
mandate plus its resolved ancestor chain and returns a machine-readable
verdict on whether the delegation itself stayed inside what the parent
actually granted.

Deterministic rules only -- no machine learning, no features borrowed from
Layer 3. Not a patch to Milestone C's disclosed held-out-class result: every
rule this package enforces was fixed by its design brief before it was ever
run against the frozen held-out corpus, and nothing in `detect/`, `features/`,
or the generator's tuning was touched to build it. See
`docs/adr/0004-delegation-chain-containment.md` for the design, the
once-only evaluation protocol, and which chaining variants still evade it.
"""

from __future__ import annotations
