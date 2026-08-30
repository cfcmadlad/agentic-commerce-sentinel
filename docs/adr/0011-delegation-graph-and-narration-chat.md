# ADR 0011: Delegation graph and narration chat

## Status

Accepted. Built, tested, and verified live against a real running service.

## Context

Layer 2.5 (containment) has been real, tested, and evaluated since Milestone G -- but it has never had a way to look at one specific delegation chain and see what it decided, only aggregate recall numbers over a corpus. This milestone builds that: a live, on-demand endpoint that walks a mandate's ancestor chain and reports each link's own containment verdict, a frontend graph rendering it, and a narration surface beside it -- plus, per the brief, an affordance inviting the user to try to talk the system out of its verdict.

## Design

### `GET /mandates/{id}/chain` is a new read, not a new decision

`service/delegation_chain.py::build_delegation_chain` walks `resolve_ancestor_chain` (already built for Milestone G) and calls the real `enforce_containment` for every link, exactly as `eval/containment_evaluation.py` does offline. It is deliberately **not** folded into `/sessions/decide`'s own verdict -- containment staying out of the live decision path was disclosed once already (`docs/adr/0008`'s scope note) and is not revisited here reactively. This endpoint is a second, independent read over the same mandate store `/sessions/decide` populates as a side effect (`state.mandate_store.add(signed.mandate)`), which is what lets a chain resolve across sessions decided minutes apart.

### A real sequential-order bug, caught by the test that exists to prove sibling accounting works

The first version summed "every *other* mandate sharing this parent" as the committed sibling total, symmetrically, for whichever node was being checked. For a two-sibling group (700 and 600, parent cap 1000), this flags **both** siblings -- each sees the other's amount as already committed. That is wrong: `containment.gate.ContainmentGate`'s real ledger is sequential, and the documented, expected shape of this exact scenario (Milestone G's own `fanout_structuring` finding, restated in `service/delegation_scenarios.py`'s own module docstring) is that the *first* sibling in a fan-out group is indistinguishable from an ordinary well-scoped delegation -- only the second-plus sibling should be flagged.

Caught by `tests/test_delegation_chain.py::test_sibling_cap_accounts_for_other_children_of_the_same_parent`, written to establish exactly this shape, not added after the fact. Fixed: `MutableMandateChainStore.all_mandates()` returns mandates in insertion order (a plain Python dict preserves it), and `build_delegation_chain` now sums only the mandates that arrived *before* the node being checked, mirroring the real ledger's sequential semantics instead of a symmetric current-state read. The one caveat this still carries, stated in the function's own docstring: for a live service, "arrival order" means order of presentation to `/sessions/decide`, not necessarily wall-clock event order if requests arrive out of sequence -- the same disclosed limitation `service/state.py`'s own module docstring already states for causal features.

### Three scenarios chosen to demonstrate the disclosed gap live, not around it

`service/delegation_scenarios.py` builds three fixed, deterministically-derived scenarios (mirroring `service/demo_scenarios.py`'s own established pattern: demo-agent keys, `_stable_uuid`-derived IDs so both a live process and the export script agree byte-for-byte). Two of the three (over-scoped child, sibling fan-out) are deliberately constructed so the child's *own* transaction stays within the *child's own* declared ceiling -- meaning Layers 1-3 allow it, while the chain view's Layer 2.5 check independently flags it. This is not a contrived edge case; it is a live, concrete instance of exactly the architectural gap `docs/adr/0003` and `docs/adr/0004` already disclosed and measured offline, now something a viewer can click through rather than only read a recall number for.

### Recorded mode is genuinely computed, not narrated-then-hardcoded

`run_delegation_demo_export.py` runs each scenario through the real `service.main.decide` handler (same pattern `service/demo_seed.py` established: call the real handler directly, not a second implementation), computes the real chain via `build_delegation_chain`, and -- when `GROQ_API_KEY` is available -- captures a genuine Groq narration for the focus session's own Layer 1-3 verdict. Every one of the three scenarios' recorded narrations in `frontend/public/delegation_demo.json` is real model output from this export run, never hand-written, matching this project's absolute rule for any fixture (`frontend/src/mock/sessions.ts`'s own docstring states it identically).

The export script isolates its audit/escalation logs to a temporary directory (`tempfile.TemporaryDirectory()`) rather than this project's shared `service_audit.jsonl`/`service_escalations.jsonl` defaults -- a real, found-during-this-milestone problem: an interactive manual-testing session against a live `uvicorn` instance had tripped one demo agent's circuit breaker for real, and that suspension, persisted to the shared default log file, silently caused a *later, unrelated* run of the export script to have its decide() calls short-circuited before the mandate ever reached the store (`AssertionError: focus mandate not in the store after deciding`). A one-shot export process should not be able to observe, or be affected by, any other process's history; isolating its logs is the fix, not resetting the breaker by hand each time.

### The "try to convince it" affordance, and an honest correction to its own copy

Per the brief, `Delegation.tsx` includes a free-text box whose content is appended to the focus session's own `merchant_id` field -- the same untrusted, adversarially-tested field `tests/test_prompt_injection_resistance.py` already targets offline -- and re-decides the session live. An early version of the result copy unconditionally claimed "unchanged from before," discovered wrong during manual verification: re-submitting the *same* mandate moments after its first decision is itself a real behavioral signal (rapid reuse), which Layer 3 is specifically built to catch, and can genuinely flip the verdict -- not because of anything the user wrote, but because the act of resubmitting is itself meaningful to the model. The copy now compares the actual before/after verdicts and explains whichever case actually occurred: if unchanged, that the message has no path to move it; if changed, that the change is attributable to a real, named signal (rapid reuse), never to the message's content, and points at the citations as proof.

This also means repeatedly clicking "Send" against the same scenario can, after enough attempts, trip that demo agent's real circuit breaker (Milestone I) -- an authentic property of the live system, not a bug, and left as-is rather than engineered around; a suspended demo agent is exactly as real and exactly as reset-by-a-human-only as any other agent this project's escalation queue tracks.

### Frontend: request bodies always static, verdicts conditionally live

`parent_request`/`child_requests` in the exported fixture are deterministic, pre-signed data -- identical whether or not a live service is configured, so the frontend always reads mandate structure (ceilings, agent IDs, parent links) from the static fixture and builds the graph from that. Only `chain` (the containment verdict) and `focus_decision` (the Layer 1-3 verdict and narration) are conditionally replaced with live-fetched data when `VITE_API_BASE_URL` is configured and reachable -- verified directly, not assumed: with a real `uvicorn` instance running, the graph correctly switched to "Live: fetched from a running service's `/mandates/{id}/chain`" and rendered the same violation the recorded fallback shows, and the convince box correctly gated itself on `live.status === "ready"` rather than merely on the env var being set (an early version showed the input whenever a base URL was configured at all, even if unreachable, since the fetch's own error state wasn't consulted for that specific panel).

## Consequences

**Per this project's standing constraint, `detect/`, `features/`, `mandate/`, `containment/engine.py`, `containment/chain.py`, and the generator were untouched.** New `service/delegation_chain.py` and `service/delegation_scenarios.py`; one additive method (`MutableMandateChainStore`, already added for this endpoint's own storage need) on `containment/store.py`; one new frontend page and its icon; no change to any deterministic layer's own decision logic.

**What this buys.** A concrete, clickable demonstration of a gap this project has disclosed since Milestone C, using a real live endpoint rather than only a corpus-level recall number -- and a genuine, tested confirmation that the reasoning layer's non-mutation guarantee holds under a real adversarial-style live attempt, not merely an offline test.

**What this does not buy.** The chain endpoint only walks ancestors, not full descendant fan-out from an arbitrary node -- the frontend's sibling-fan-out visualization works because the fixture's own `child_requests` list already carries every sibling's mandate content, not because the endpoint itself returns a full subgraph. Sibling-order sensitivity (see above) means this view's containment verdict for a given mandate can, in principle, differ from a stricter historical replay if requests to a live service arrive in a different order than intended -- an honest limitation, not a silent one.
