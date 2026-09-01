# ADR 0007: Tamper-evident audit log

## Status

Accepted. Built, tested, and verified against a real synthetic tamper.

## Context

`reasoning/audit_log.py`'s `AuditLog` was already append-only *by interface*
— no `update`, `delete`, `clear`, or `truncate` method exists anywhere on
the class, and every `append` call opens the file, writes one line, and
closes it, so nothing in the class itself can seek backward and overwrite a
previous line. That is a real guarantee about what the code *offers*, but it
says nothing about a line that gets edited a different way — directly, with
a text editor or any other tool that has write access to the file. Nothing
in the pre-existing design would have caught that, or said which entry it
happened to.

This closes that specific gap: not preventing an out-of-band edit (a bare
JSONL file on local disk cannot do that, and the module's own docstring
already discloses no file locking and a single-process assumption as an
accepted tradeoff), but making one *detectable*, and pinpointing exactly
where.

## Design

### Hash chain

Each on-disk entry now carries three things: the `AuditRecord` itself,
`prev_hash` (the previous entry's own `record_hash`, or `GENESIS_HASH` for
the first entry in a log), and `record_hash` (the SHA-256 of the canonical
serialization of `{"prev_hash": prev_hash, "record": record}`). This is the
standard hash-chain construction — the same shape a blockchain's block
header or a certificate-transparency log uses — applied to the smallest
scope that actually needs it, one JSONL file.

`GENESIS_HASH = "0" * 64` is the documented sentinel the first entry in any
log chains from. It is not the digest of any real content; it exists so the
first entry has a defined, spelled-out previous-hash value rather than a
special-cased `None`. A genuine SHA-256 output could coincidentally equal
it, but only with probability 2⁻²⁵⁶ — not a property this design leans on
for security, only for having an unambiguous starting point.

### Canonical serialization

Hashing needs a byte sequence, and `json.dumps` does not produce one
deterministically by default — dict key order and whitespace choices both
vary. `_canonical_bytes` fixes both: `sort_keys=True` makes the encoding
independent of insertion order, and compact, fixed separators (`","`/`":"`,
no spaces) remove the one remaining source of whitespace variation in
`json.dumps`'s own default output. The result: the same logical content
always hashes to the same bytes, in this process or any reimplementation
that follows the same rule.

The *on-disk* line is still written with `json.dumps`'s default (spaced)
separators, matching the module's pre-existing "directly human-reviewable
with `cat`/`grep`/`jq`" goal. Canonicalization only governs what gets fed to
the hash function, not what a human reads.

### What `verify_chain` checks, and in what order

`reasoning/audit_chain.py::verify_chain` walks a log's entries in append
order and, for each one, checks two independent things:

1. **`prev_hash` matches the previous entry's `record_hash`** (or
   `GENESIS_HASH`, for the first entry) — catches a forged link, i.e. an
   entry made to claim a different position in the chain than it actually
   holds.
2. **`record_hash` matches `compute_record_hash(prev_hash, record)`** —
   catches a rewritten record whose `record_hash` field was never
   recomputed to match, which is what happens if someone edits a record's
   content directly without also updating its stored hash (the easy,
   naive kind of tamper).

Both checks matter, and they catch genuinely different tamper shapes: check
1 alone would miss a content edit that leaves the link fields untouched;
check 2 alone would miss a forged link whose own record content is
internally self-consistent. `verify_chain` stops at the first entry where
either check fails and reports that index — a broken chain means every
entry after the break is now unverifiable relative to a known-good head, not
just the one entry that was actually touched, so continuing past it would
not add real information.

### Interface stays append-only

`AuditLog` now exposes `append`, `read_all`, `read_entries`, and `path` --
`read_entries` is new (returns each entry's `record` alongside its
`prev_hash`/`record_hash`, for `verify_chain` to consume), `read_all` is
unchanged in signature and still returns bare `AuditRecord`s so every
existing caller (`service/main.py`'s `/audit/{session_id}` endpoint) needed
no changes. No mutation or deletion method was added.
`tests/test_audit_log.py::test_audit_log_exposes_no_mutation_or_deletion_method`
still asserts the exact public method set, updated for the one addition.

### CLI

`run_verify_audit_chain.py --log-path <file>` reads a log, walks the chain,
and prints either `chain intact: N record(s), genesis to head, no break
found` (exit 0) or `chain broken at index I of N: <prev_hash|record_hash>
mismatch` (exit 1) — a shape a human or a CI step can both use directly.

## A real bug found while building this, not invented for demonstration

This machine had a stray, gitignored, local-only `service_audit.jsonl` left
over from earlier live-HTTP demo/testing sessions, written in the *old*,
pre-chain, flat JSONL format — one bare `AuditRecord` dict per line, no
`prev_hash`/`record_hash`/`record` envelope. Running the full suite against
that file for the first time after this change
(`service/state.py::DEFAULT_AUDIT_LOG_PATH` points at it, and
`tests/test_service.py` uses the default) crashed every service test with
`KeyError: 'record_hash'` inside `AuditLog._last_hash()` — it read the old
file's last line looking for a key that format never had.

This is a genuine forward-compatibility question, not a test-fixture
problem: the new format is a breaking, forward-only change to what
`AuditLog` writes and expects to read, and there is no real historical audit
log in this project worth preserving across that break — every log this
project has ever produced is local, gitignored runtime demo data, regenerated
fresh by `service/demo_seed.py` every time the service restarts, never
shipped or committed. The stray file was deleted rather than migrated or
special-cased for. A real deployment adopting this format for the first time
starts a fresh log; nothing in this project claims to read an audit log
written in the old, pre-chain format.

## Consequences

**Per this project's standing constraint, nothing in `detect/`, `features/`,
or the generator was touched.** This change only extended
`reasoning/audit_log.py` and added `reasoning/audit_chain.py` plus one CLI
entry point — a genuinely new package boundary, not a modification to any
frozen evaluation surface.

**What this buys, stated precisely.** An operator who holds even one
trusted checkpoint of a log's true `record_hash` at some point in time can
detect, and localize to an exact entry, any edit to that log made after that
checkpoint — including an edit that also tries to rewrite the hash fields
naively (check 2 catches that) and an edit that only forges the link (check
1 catches that). What this does not buy: prevention (a bare file has no
access control beyond the filesystem's own), protection against someone who
rewrites *every* subsequent entry's hashes consistently from a chosen point
forward with no independent checkpoint to compare against, or multi-process
write safety (unchanged from the pre-existing, already-disclosed
no-file-locking tradeoff). The README's "Defense-only" section states this plainly rather than
implying the chain is a stronger guarantee than it is.
