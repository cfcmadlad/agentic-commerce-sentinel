# ADR 0009: Escalation queue and per-agent circuit breaker

## Status

Accepted. Built, tested, and wired into the live API service.

## Context

Layer 3 flagging a session (`detect.ensemble.SOURCE_BEHAVIORAL`) has never been an enforcement action in this project -- every layer above it, and the frontend itself, already say the same thing: "a detector and verifier, not an autonomous enforcement system." Until this milestone, that statement was true only in the sense that nothing *automatically acted* on a flagged session beyond narrating it. There was no queue, no reviewer workflow, and no way for repeated flags against one agent to lead anywhere. This closes that gap: an `Escalation` is opened automatically, moves through `open -> reviewed -> resolved` only via attributed human action, and a deterministic circuit breaker suspends an agent outright if enough escalations accumulate.

## Design

### A second hash-chained log, generalized rather than duplicated

The brief calls for escalation transitions to go into a hash-chained log, the same tamper-evidence property `reasoning/audit_log.py` (ADR 0007) already built. Rather than copy that ~150-line implementation a second time -- which would leave a real risk of a bug fixed in one copy and not the other -- the hash-chaining mechanics were extracted into `common/hash_chain.py`: a payload-agnostic `HashChainedLog` operating on JSON-safe dicts, plus `verify_hash_chain`. `escalation/log.py` wraps it with `EscalationEvent`-specific (de)serialization, matching `reasoning/audit_log.py`'s own explicit field-by-field mapping convention.

`reasoning/audit_log.py` itself was deliberately **not** migrated onto this new shared layer. It already ships, is tested, and carries a forward-compatibility guarantee fixed once already (ADR 0008's "real forward-compatibility bug" section) -- rewiring already-correct, already-shipped code onto a new abstraction for no functional gain is exactly the kind of risk this project avoids taking reactively. The two logs are separate files (`service_audit.jsonl`, `service_escalations.jsonl`), each with their own hash chain; there is no unification of the escalation trail and the decision trail into one physical file.

### Events, not a mutable record, back the queue

`EscalationEvent` is the append-only unit of truth; `Escalation` is a materialized view rebuilt by folding a chain of events for one `escalation_id` (`escalation/queue.py::_apply`). This mirrors `detect.baseline.RulesOnlyBaseline`'s own stateful-replay pattern rather than storing and mutating an `Escalation` object directly -- the same reasoning: the log is the source of truth, and any in-memory index is rebuildable from it by construction, not by convention. `EscalationQueue.from_path` demonstrates this directly: a fresh queue built from an existing log file replays every event and produces the identical state (including circuit-breaker suspension) a queue that lived through those events live would have.

### The circuit breaker is a pure function of recorded history, not wall-clock time

`CircuitBreaker.record_escalation(agent_id, at)` takes an injected timestamp -- the session's own `started_at`, not `datetime.now()` -- so suspension is exactly as reproducible and testable as every deterministic layer in this project. A rolling window (not `service/middleware.py`'s fixed-window rate limiter) is used because "N escalations within a rolling window" is what the brief actually asks for: a window that always ends at "now," not one that resets on a schedule.

**Suspension is sticky by design.** Once `len(recent) >= threshold` trips it, an agent stays suspended even after the triggering escalations age out of the window -- nothing in `CircuitBreaker` computes suspension fresh on each check; membership in a `_suspended` set is the only thing `is_suspended` reads, and only `reset` (called from a human action at the service boundary) removes it. This is a direct reading of the brief's "reset only via explicit human review action, never automatic or time-based," and it is the one design choice in this milestone that would have been trivially wrong to get by default -- a naive "recompute from history every time" implementation would auto-lift the suspension the moment the window moved past the third escalation.

### A real replay bug, caught by the test written to prove replay actually works

The first version of `EscalationQueue.__post_init__` handled a stored `CIRCUIT_BREAKER_SUSPENDED` event by calling `breaker.record_escalation` again -- treating the suspension record itself as a fourth escalation. This meant replaying a log from disk produced a *different* circuit-breaker state than the live sequence of calls that wrote it: live, two `OPENED` events (with `threshold=2`) trip the breaker directly; replayed, the two `OPENED` events were never fed to the breaker at all, only the one stored `SUSPENDED` event was, which alone can never reach a threshold of two. `test_replaying_from_an_existing_log_rebuilds_the_same_state` caught this immediately -- exactly the test this milestone needed to write regardless, not a special probe added after the fact. Fixed: replay feeds every `OPENED` event to the breaker (mirroring what `open_escalation` does live) and treats a stored `SUSPENDED` event as a no-op record of history already implied by the `OPENED` events around it, never a second trigger.

### Human-in-the-loop is enforced, not merely documented

`review`, `resolve`, and `reset_circuit_breaker` all reject `actor == SYSTEM_ACTOR` with `HumanActionRequiredError` (surfaced as HTTP 422). `resolve` additionally refuses to run against an `OPEN` escalation -- review is a required step, not an optional one a caller can skip by calling resolve directly. Both are the literal enforcement of "human-in-the-loop," not a naming convention a caller could route around.

### Wired into the live service without touching `detect/ensemble.py`

Two integration points in `service/main.py::decide`:

1. **Before anything else runs**, `state.escalation_queue.is_agent_suspended(trace.agent_id)` short-circuits to a hard block -- Layers 1-3 are never evaluated for a suspended agent, since whether this particular session would otherwise have been fine is moot. This uses a new `SOURCE_CIRCUIT_BREAKER = "circuit_breaker"` string constant defined in `service/main.py` itself, not added to `detect/ensemble.py`: both `EnsembleDecision.source` and its wire form are already plain `str` fields, so a new source needs no change to that module at all, keeping the standing "don't touch `detect/` reactively" constraint intact for a genuinely new, service-layer concern.
2. **Immediately after `ensemble_decide` returns**, if `ensemble.source == SOURCE_BEHAVIORAL`, an escalation is opened automatically (`actor=SYSTEM_ACTOR`), at `trace.started_at`.

Read-only endpoints (`GET /escalations`, `GET /escalations/{id}`, `GET /agents/{id}/circuit-breaker`) plus exactly two mutating ones (`POST .../review`, `POST .../resolve`) and one circuit-breaker action (`POST .../circuit-breaker/reset`) -- none of the five touch a mandate, a ledger entry, or a payment; their only effect is on escalation or circuit-breaker state.

## Consequences

**Per this project's standing constraint, `detect/`, `features/`, `mandate/`, and the generator were untouched.** New packages (`common/hash_chain.py`, `escalation/`) plus additive branches in `service/main.py`/`service/state.py`.

**What this buys.** A behaviorally-flagged session now has somewhere to go: a real, auditable, human-gated workflow, and repeated flags against one agent lead to a real consequence (suspension) rather than an accumulating pile of narrated-but-unactioned scores.

**What this does not buy.** The circuit breaker's two constants (`DEFAULT_ESCALATION_THRESHOLD = 3`, `DEFAULT_ROLLING_WINDOW = 24h`) are not fitted to any real fraud-loss data -- there is none for a synthetic-data submission, the same disclosed-assumption pattern `detect/calibration.py`'s cost ratio already uses. The escalation log and the audit log are two separate hash chains, not one unified trail; an operator wanting a single chronological tamper-evident view of "everything that happened to this agent" would need to merge both by timestamp, not read one file.
