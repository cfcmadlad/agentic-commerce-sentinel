"""The governed live shopper agent: a real, tool-calling LLM agent the Sentinel governs.

Every other "agent" in this codebase is a synthetic data-generator construct
-- a labeled record produced offline, never a running process that decides
what to do next. This package is the one exception: `agent.shopper` runs a
real Groq tool-calling loop that searches a fake merchant catalog, proposes a
purchase, and attempts checkout. The checkout attempt is the only place this
package touches the real system, and it does so honestly -- `agent.tools
.checkout` calls the real `service.main.decide` function (Layers 1, 2, and 3,
plus the circuit breaker) in-process, then separately computes the real
Layer 2.5 containment verdict via `service.delegation_chain
.build_delegation_chain`, the same function `GET /mandates/{id}/chain`
already exposes -- containment is not wired into `decide` itself (see that
function's own docstring and `docs/adr/0008-counterfactual-explanations
.md`'s scope note), so this is the honest way to show its real verdict
without fabricating anything or changing the live decision path.

Everything this agent writes -- audit entries, escalations, mandate/ledger
state -- goes to a demo-run-isolated instance of `service.state.AppState`,
never the shared default paths a live service or another test run would use.
See `docs/adr/0016-governed-live-agent.md` for the full design rationale and
the isolation and non-offensive boundaries this package enforces
structurally, not just by convention.
"""

from __future__ import annotations
