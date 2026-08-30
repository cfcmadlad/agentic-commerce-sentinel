"""Policy as code: Layer 2's rule set expressed as a versioned, linted YAML document.

`policy/default_policy.yaml` is a declarative re-encoding of `detect/
scope.py::enforce_scope`'s real nine rules -- not a new rule set. Proven
behaviorally identical to the real function over the full generated
corpus (`tests/test_policy_behavioral_identity.py`), not merely asserted.

Deliberately not wired into `/sessions/decide` as the live authoritative
source for Layer 2 -- the same scope boundary already drawn for Layer
2.5's containment engine (`docs/adr/0008`'s scope note): replacing what
actually governs a live decision is a separate, larger choice this
milestone does not make reactively. See `docs/adr/0013-policy-as-code.md`.
"""

from __future__ import annotations
