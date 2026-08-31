# ADR 0016: Governed live shopper agent

## Status

Accepted. Built, tested, and verified against the real fitted pipeline. This
document is a record of a design decision, not a proposal.

## Context

Every "agent" this project has produced so far is a synthetic
data-generator construct -- a labeled record produced offline, never a real,
running process that decides what to do next. For a track judged partly on
whether an agent or LLM was used appropriately, and on graceful handling of
a bad outcome, a pipeline that only scores pre-generated traffic risks
reading as a fraud-detection project rather than an agentic one. The fix
identified was not more detection engineering -- the detection core (Ed25519
verification, deterministic scope enforcement, delegation-chain containment,
the behavioral ensemble, Z3 formal verification, graph-based collusion
detection, a tamper-evident audit chain, reproducibility manifests) was
already judged differentiated. What was missing was a real, tool-calling
agent the Sentinel visibly governs live.

## Design

New top-level package `agent/`, exactly as the sprint brief proposed (no
package-name collision found in Step 0's discovery pass):

- `agent/catalog.py` -- a small, fixed, hardcoded fake merchant catalog (8
  SKUs). Hardcoded rather than generated through the project's seeded-RNG
  helper (`generator/rng.py::rng_uuid`/`rng_nonce`): at this size, hardcoding
  is strictly more auditable than a generator a reader would have to run to
  see what exists, and the brief's own suggested default agreed. Prices and
  categories deliberately span Layer 2's scope rules.
- `agent/llm_client.py` -- a new, genuinely different, tool-calling-capable
  Groq client (`GroqToolCallingClient`), following `reasoning.narrate
  .GroqNarrationClient`'s conventions (caller constructs `groq.Groq()` and
  passes it in; an empty-and-toolcall-free completion is a hard failure) but
  not reusing that class, since `GroqNarrationClient.complete` is plain-text
  completion only and Layer 4 must never be confused, in code or in the
  frontend, with a component that takes actions.
- `agent/tools.py` -- the three tools (`search_catalog`, `propose_purchase`,
  `checkout`) and `ShopperToolContext`, the bound, model-unreachable context
  fixing agent identity, mandate, shared `AppState`, and event-pacing
  template before the agent loop ever starts.
- `agent/shopper.py` -- the tool-calling loop, capped at
  `MAX_TOOL_ITERATIONS = 6`, dispatching only to `agent.tools`'s three
  functions.
- `agent/scenarios.py` -- the four fixed scripted scenarios (prompts and
  bound context fixed ahead of time; verdicts never scripted).
- `run_agent_demo_export.py` -- the CLI export script, matching the
  established `run_*.py` convention.

### The non-offensive boundary, enforced structurally

`checkout` is the only tool with any effect, and the effect is entirely:
call the real `service.main.decide` in-process with a real, already-signed
mandate the scenario harness built (never one the model constructs), then
separately compute the real Layer 2.5 containment verdict. The agent has no
other tool -- no code-exec, no HTTP fetch, no filesystem write outside its
own isolated demo state. `tests/test_agent_structural_isolation.py` asserts
at the AST level, the same discipline `reasoning/narrate.py` already uses
for its own non-mutation guarantee, that `agent.shopper` and
`agent.llm_client` (the two modules a model's own output can influence)
never import `mandate.verification`, `mandate.signing`, `escalation.queue`,
`escalation.circuit_breaker`, `service.main`, `service.state`, or any
`containment.*` module directly -- only `agent.tools` may, and its three
functions are the complete, audited boundary.

Anti-tamper deviation from a literal reading of the brief: the brief's
proposed signature was `checkout(proposal: PurchaseProposal)`. Built instead
as `checkout(item_id, quantity)`, re-deriving the proposal from the catalog
internally, exactly like `propose_purchase` does. A tool-calling model only
ever sees its own prior tool results as text it could, in principle, alter
before echoing back; accepting an opaque, model-echoed proposal object
carrying a price would trust a monetary amount round-tripped through the
model. `checkout` never does -- the model only ever controls which item and
how many.

### Isolation

Every scenario runs against a `service.state.AppState` built with its own
temp-file audit and escalation log paths, matching
`run_delegation_demo_export.py`'s already-established isolation pattern
(the same one Milestone K's own fix addressed after a stray interactive
run's circuit-breaker trip once corrupted an export run via shared default
log files). Every demo agent identity is prefixed `shopper-agent-`, distinct
from `service/state.py`'s own `demo-agent-NN` namespace, so a demo run can
never collide with or be mistaken for the live service's own demo agents.
`tests/test_agent_scenarios_end_to_end.py::test_demo_run_never_touches_the_default_service_log_paths`
is a permanent regression guard, snapshotting the default log paths' state
before and after a full run rather than assuming they start out empty (a
real local machine can legitimately already have a nonempty, gitignored
`service_audit.jsonl` from an earlier manual `uvicorn` run).

### Why tool-calling rather than a fully scripted flow

A scripted flow that always calls the same three tools in the same order
would not actually demonstrate agent judgment -- it would be a puppet show
wearing an agent's clothing. What is scripted here is only the prompt and
the bound context (which mandate, which catalog subset); the model
genuinely chooses what to search for, what to propose, and when to attempt
checkout, and the real Sentinel decides the outcome independently. This is
also why every scenario's expected outcome is *confirmed by the tests
against the real pipeline*, not asserted as a foregone conclusion: if Layer
3's threshold or the containment engine ever changed, the corresponding
scenario test would fail rather than silently keep reporting a stale claim.

### The headline moment: real Layer 2.5, not decide()

`service.main.decide` does not run Layer 2.5 containment -- it never has;
`docs/adr/0008-counterfactual-explanations.md` and `docs/adr/0011
-delegation-graph-and-narration-chat.md` both already disclose this
scope boundary, and `GET /mandates/{id}/chain` is the one place containment
is actually computed, as a separate, explicit read. `checkout` follows that
exact precedent: it calls `decide()` for the real Layers 1-3 plus
circuit-breaker verdict, then separately calls `service.delegation_chain
.build_delegation_chain` for the same mandate. The headline scenario builds
a child mandate whose ceiling (5000) exceeds its parent's (1000) --
`budget_escalation`, one of the three delegation-chaining variants
`docs/adr/0004-delegation-chain-containment.md` already measured at 100%
recall. Nothing was tuned to make this work; it is the same containment
engine and the same variant family already evaluated, run live instead of
offline. Verified against the real fitted pipeline
(`tests/test_agent_scenarios_end_to_end.py::test_outcome_4_headline_containment_catch`):
`decide()` allows the transaction (it fits the child's own ceiling) while
the separate containment check reports `in_bounds=False`.

One small, disclosed extension beyond a pure read: when `checkout` observes
a containment violation, it opens a real escalation via
`state.escalation_queue.open_escalation`, mirroring exactly what `decide()`
already does automatically for a behavioral block. This is the mechanism
behind demo outcome 3 (a scripted-fast pacing pattern reusing
`service/demo_scenarios.py::BEHAVIORAL_ONLY_ID`'s own already-proven
warm-up/final numbers, which Layer 3 flags on its own, opening an
escalation through `decide()`'s existing path with no new code) and outcome
4 (the containment violation, opening an escalation through this package's
own new, mirrored call). Both land in the same real human-review queue.

## Phase 2: making the rigor visible in the UI

Started only once Phase 1 was fully working end to end, per the sprint
brief's own phase ordering. Two additions, both read-only presentations of
already-real, already-committed data -- no new claim, no new computation.

**Step 0 correction.** The brief's own Step 0 findings (and this document's
earlier draft) described the frontend as a sidebar `id`-based *page*
switcher with a `NAV_ITEMS` array. Re-reading the actual current
`frontend/src/components/AppShell.tsx` and `frontend/src/pages/Dashboard.tsx`
(rewritten since that finding, per `PROJECT_PLAN.md`'s Milestone F2 history)
found something more specific: there is no router and no page-switching at
all. Every "page" is a `<section id="...">` composed inline inside one
continuous scroll (`Dashboard.tsx`); `AppShell.tsx`'s array (`SECTIONS`, not
`NAV_ITEMS`) only drives scroll-spy anchor links into that single page. A new
"Operations" view means a new `SECTIONS` entry plus a new inline `<section>`
in `Dashboard.tsx`, not a new routed page -- built that way here.

**`frontend/src/pages/Operations.tsx`**, a new section between Delegation and
Explorer (placement is a judgment call, not dictated by the brief: Operations
conceptually follows "you've just seen delegation-chain containment
explained" and precedes "here are the full evaluation numbers"), with three
panels:

1. The four real `agent_demo.json` scenario transcripts (from
   `run_agent_demo_export.py`), selectable via the same `session-rail` list
   pattern `Delegation.tsx` already established -- real tool-call sequence,
   real verdict badges (the headline scenario shows the `decide()` verdict
   and the separate Layer 2.5 containment verdict side by side, deliberately
   never conflated into one badge, mirroring how `agent.tools.checkout`
   itself keeps them separate). `llm_backend` is always rendered, unhidden:
   this build's committed export used `--fake-llm` (this development
   machine's local proxy cannot reach Groq -- the same
   `CERTIFICATE_VERIFY_FAILED` characteristic already documented for the
   seven pre-existing live-Groq tests), never presented as if it were live.
2. `.ops-terminal`, a live-feeling replay feed. Not live traffic (this
   hosted build has no backend to stream from) -- a genuinely ticking list
   replaying real `collision.json` sessions (already-exported, already used
   elsewhere in this dashboard), sequence-numbered, never a timestamp
   presented as elapsed real time.
3. A Proof Panel citing, never recomputing: the real Z3 8/8 property-by-
   property result (new `--json-out` flag on `run_verify_policy_properties
   .py`, exported to `formal_properties.json`), the real McNemar p-value and
   ensemble AUC-PR bootstrap CI (already in `metrics.json`, reused rather
   than duplicated), a static, ADR/test-file-cited description of the
   Hypothesis property-based invariants (no new export mechanism was built
   for this one, since the brief only asked that the panel *state* what was
   checked, not compute a new number), and the headline reproducibility
   manifest's already-published content hash with a real, working link (the
   real committed file, vendored into `frontend/public/manifests/` so the
   hosted static site has something to actually serve).

**The scoped dark/dense treatment, adapted to the real architecture.** The
brief allowed a denser, darker visual mode for this one operational view,
scoped to "a toggle or a distinct route." Neither exists in the real
architecture (see the Step 0 correction above) -- there is one continuous,
otherwise-light scroll with no per-section theming and no router. A
route-level or global dark toggle would need inventing infrastructure this
app deliberately doesn't have, and a full-section dark background would
visually clash at the scroll boundary with the light sections immediately
above and below it. Adapted, not skipped: the dark, dense treatment is
scoped to one small, self-contained panel (`.ops-terminal`, a fixed near-
black background regardless of viewer theme, like an embedded code block)
rather than the whole section or the app -- everything else on the
Operations section, and the rest of the app, stays the same achromatic
ink-on-paper system unchanged.

**Not built:** the optional live-HTTP mode for `checkout` (Section 4.3's
"additionally support... hitting a configured live API base URL") was
already out of scope for Phase 1 as shipped -- `checkout` calls `decide()`
in-process only. `Operations.tsx` therefore has no live mode either (unlike
`Delegation.tsx`, which has one because the backend chain-lookup endpoint it
calls already exists); it is recorded-only, exactly like every other
Phase-1-driven view's fallback path when no live API is configured.

Verified: `tsc -b --noEmit` and `oxlint` both clean, `npm run build` clean,
and the rendered page inspected directly (DOM/computed content, not just
"it compiled") for both scenarios' verdict badges, the ticking replay feed,
the 8/8 property table, and the manifest link resolving to the real vendored
file -- including at a mobile viewport width, where the sidebar's existing
horizontal-collapse behavior (unmodified) still fits the new nav entry.

## Consequences

- A judge can watch a real LLM decide what to attempt and watch the real
  Sentinel allow, block, or escalate it -- not a scripted verdict -- and can
  now see that same real verdict, plus the project's formal-verification and
  significance results, in the UI rather than only in README prose.
- The non-offensive and isolation boundaries are enforced by AST-level
  tests and a snapshot regression guard, not only by convention.
- `agent.llm_client` duplicates a small amount of structure from
  `reasoning.narrate` (the empty-completion hard-failure guard, the
  caller-constructs-the-client convention) rather than sharing code with it
  -- a deliberate tradeoff: the two modules must stay architecturally
  distinct, and the actual call shape (tool calls vs. plain text) differs
  enough that a shared abstraction would cost more clarity than it saves.
- The Operations view is recorded-only, no live-HTTP mode, since `checkout`
  itself has none -- adding one to either would be a real, separate future
  decision, not a Phase 2 afterthought.
