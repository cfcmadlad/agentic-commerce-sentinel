"""Minimal-edit counterfactual explanations for an already-decided verdict.

Answers a different question than the reasoning layer's narration
(`reasoning/narrate.py`) or the SHAP attribution it cites
(`detect/attribution.py`): not "why was this blocked" but "what is the
smallest change that would have allowed it". Both are explanations of a
verdict that has already been decided elsewhere; nothing in this package
sets or adjusts one.

Two structurally different methods, split across two modules, because the
two kinds of layer this package explains admit fundamentally different
guarantees:

- `counterfactual.deterministic` covers Layers 1, 2, and 2.5. Every
  suggested edit is verified against the exact Z3 encoding
  `formal/model.py` built for Milestone P's exhaustive proofs -- the same
  `mandate_verified`/`in_scope`/`contained` predicates, not a second,
  potentially drifting reimplementation of "is this mandate valid". If the
  deterministic rules ever change, a counterfactual that no longer matches
  them fails loudly (an `AssertionError`) rather than silently reporting a
  stale edit.
- `counterfactual.behavioral` covers Layer 3, the learned model. There is
  no closed-form encoding to consult -- see `formal/__init__.py`'s own
  scope note on why Layer 3 is never Z3-encoded -- so this module searches
  the real fitted model directly (bisection against `predict_proba`,
  prioritized by SHAP attribution). This is a heuristic, not an exhaustive
  search of the model's decision surface, and is documented as such: it can
  report "no counterfactual found" when a smaller one may exist outside the
  features or search bounds it tried, but it never reports an edit that was
  not actually verified against the real model's own output.
"""

from __future__ import annotations
