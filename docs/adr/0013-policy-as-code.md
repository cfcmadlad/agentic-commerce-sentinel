# ADR 0013: Policy as code

## Status

Accepted. Built and tested; proven behaviorally identical to the real rule set over the full generated corpus.

## Context

Layer 2's nine real rules (`detect/scope.py::enforce_scope`) have always been Python code — correct, tested, and frozen since Milestone B, but not something a non-engineer can read, version, or lint independently of reading the function itself. This milestone builds a declarative, versioned, linted equivalent and proves it reproduces the real rules exactly, without touching the real rules themselves.

## Design

### YAML, not a custom expression grammar — the brief's own "propose which and why"

Every one of Layer 2's real rules is a single declarative comparison: one field against another field, or one field against a set. None compose booleans, do arithmetic, or need control flow. YAML already represents "a list of typed, named records" directly; a custom expression grammar would need its own parser, evaluator, and sandboxing to guarantee it could only ever express a read-only comparison. YAML plus a closed field-path allowlist (`policy.schema.KNOWN_FIELD_PATHS`) makes "no policy construct may express a mutating or offensive action" true **by construction** — `PolicyRule` has no field capable of naming an action, only a comparison between two already-known values — rather than a property something else has to police at runtime.

### Strict schema validation, precise errors, by leaning on pydantic rather than hand-rolling

`PolicyDocument`/`PolicyRule` use `extra="forbid"` (a typo'd key fails to load, not silently ignored) and a `model_validator` that checks exactly the fields a given `check` kind needs are present and nothing else is — each violation names the rule and the specific field, not a generic "invalid document." `policy/loader.py` wraps both YAML parse errors and pydantic validation errors in one `PolicyLoadError`, so a caller has one exception type to catch regardless of which stage failed.

### The linter's three categories, precisely defined for this narrow format

The brief names three categories generically ("unreachable, contradictory, or unfireable"); this project's minimal format makes each concrete and mechanically checkable:

- **Contradictory**: two or more rules firing the same named `reason` — a reason should map to exactly one deterministic check.
- **Unfireable**: a `"compare"`/`"in_range"` rule whose sides are the identical field path — a field can never violate a comparison against itself.
- **Unreachable**: a `"compare"`/`"in_range"` rule against a field that does not resolve to an orderable type (a set or a UUID cannot be compared with `<=`) — evaluating it would raise, not decide, so in practice it could never fire correctly. Field-path *existence* (the more obvious reading of "unreachable") is caught earlier, at load time, by the schema's own known-path validation — by the time a document reaches the linter, an unknown path is already structurally impossible, which is why the linter's own "unreachable" check is about type compatibility, not existence.

### Compiled evaluation is read-only by construction, not by discipline

`policy/compiler.py::resolve_path` only ever performs attribute lookups along a path already validated against the closed allowlist; nothing in the compiled form assigns to, mutates, or calls a method on anything it resolves. This carries the schema's own "no mutating or offensive action" guarantee through to the executable form, not just the document.

### Proof of behavioral identity — the brief's explicit requirement, done for real

`tests/test_policy_behavioral_identity.py` runs the same generator-built corpus `run_gate.py` reports numbers against (5,000 legitimate sessions plus the real attack mix, seed 42) through both the compiled default policy and the real `enforce_scope`, and asserts every session's fired reasons match **exactly** — same reasons, same order — not merely "both agree on blocked/allowed," which would hide a policy that fires the wrong specific rule for the right final verdict. Passed on the first run once the YAML's rule order was written to match `_check_binding` then `_check_transaction_scope`'s own order; no mismatch was found or needed fixing, unlike Milestones K and (see below) this session's other real-bug findings.

### `NO_MANDATE_PRESENTED` is a precondition, not a rule

`enforce_scope`'s early return for `signed is None` has no mandate object to compare fields against at all — there is nothing a declarative comparison rule could express for it. `policy/default_policy.yaml`'s own header comment states this explicitly, and the identity test asserts this case is skipped from the compiled comparison and checked separately (the real function's own reason is still asserted correct).

### Scope boundary, drawn the same way Layer 2.5's was

This milestone proves a declarative policy document *can* faithfully reproduce Layer 2's real decisions and ships real linting and semantic versioning — it does **not** wire the compiled policy into `/sessions/decide` as the live authoritative source. Doing so would mean Layer 2's actual live decisions are governed by a newly-built compiler instead of the already-shipped, already-tested `enforce_scope`, which is exactly the kind of reactive change to the live decision path this project's standing constraint rules out, even though `detect/scope.py` itself would remain textually untouched. The same boundary was already drawn for Layer 2.5's containment engine (`docs/adr/0008`'s scope note) and for Milestone K's delegation-chain read. Consequently, "the active policy version recorded in every audit record" — the brief's own phrase — is a real, tested capability at the library level (`CompiledPolicy.version`) but is not added to `reasoning.schema.AuditRecord`: a field recording a policy version that never actually governs a live decision would be surface area without substance, the same discipline this project applies everywhere else.

## Consequences

**Per this project's standing constraint, `detect/scope.py`, `detect/`, `features/`, and the generator were untouched.** New `policy/` package (`schema.py`, `loader.py`, `compiler.py`, `linter.py`, `default_policy.yaml`) and one new runtime dependency, `pyyaml==6.0.3` (confirmed live via the `--use-feature=truststore` proxy workaround already established this session).

**What this buys.** A real, versioned, linted, human-readable artifact that a non-engineer reviewer could plausibly audit line by line, proven — not merely claimed — to decide identically to the real rules across the full corpus.

**What this does not buy.** No live enforcement path yet; a future decision to actually govern `/sessions/decide` from a compiled policy is a separate, larger milestone this one deliberately does not make. The policy format also only covers Layer 2's rule shape (independent field comparisons) — it has no representation for Layer 1's short-circuit signature check or Layer 2.5's cross-mandate sibling ledger, and does not attempt one.
