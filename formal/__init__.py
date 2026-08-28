"""Formal verification of the deterministic decision layers (1, 2, 2.5).

This package proves properties about the same decision logic `detect/scope.py`,
`mandate/verification.py`, `containment/engine.py`, and `detect/ensemble.py`
already implement -- exhaustively, over a bounded but otherwise unconstrained
state space, rather than sampled at specific test-suite inputs. A pytest suite
answers "does this pass for the cases we thought to write"; an SMT solver
answers "is there ANY input, anywhere in the encoded space, where this
property fails" -- and if the answer is unsat, none exists, full stop.

Deliberately out of scope, and never encoded here: Layer 3 (the learned
behavioral model). Its decision boundary is not expressible in closed-form
SMT constraints, and encoding an approximation of it would prove something
about the approximation, not the model. Every property in this package
either concerns Layers 1, 2, and 2.5 alone, or treats Layer 3's contribution
as a free, entirely unconstrained boolean input -- a property that holds
regardless of what that variable is holds regardless of what the real model
would ever output for it.

Also out of scope, by design, not oversight: this package never generates
attack payloads, and its outputs (proofs and counterexamples about this
project's own encoded policy logic) are not usable as attack inputs against
anything -- a counterexample here describes a gap in this repository's
formal model, not a technique against a real payment system. See
`docs/adr/0005-formal-verification-of-deterministic-layers.md` for the full
design, the property list, and the explicit boundary between what is proved
and what is not.
"""

from __future__ import annotations
