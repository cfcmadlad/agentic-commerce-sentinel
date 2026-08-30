"""Generic append-only, hash-chained JSONL log.

Extracted as shared infrastructure the moment a second hash-chained log
(`escalation/log.py`, Tier 3) was needed alongside the first
(`reasoning/audit_log.py`, built for the tamper-evident audit trail) --
duplicating roughly 150 lines of security-relevant hashing/chaining logic a
second time is exactly the kind of duplication where a bug fixed in one
copy and not the other is a real risk, not a stylistic nitpick.

`reasoning/audit_log.py` itself predates this module and is deliberately
left as its own, independent implementation rather than migrated onto this
one: it is already shipped, tested, and carries a forward-compatibility
guarantee fixed once already (see `docs/adr/0008-counterfactual-
explanations.md`'s "real forward-compatibility bug" section) -- rewiring it
onto a new shared layer would risk that guarantee for no benefit this
project needs. Any *new* hash-chained log this project adds should build on
this module instead of copying either existing implementation.

Payload-agnostic by design: this module hashes, chains, and persists
already-JSON-safe `dict[str, object]` payloads. Converting a specific
record type to and from that shape is the caller's job (see
`escalation/log.py` for the pattern), matching the explicit field-by-field
mapping convention `reasoning/audit_log.py` and `eval/report_json.py`
already established, for the same reason: several real record types here
carry enum members, UUIDs, and datetimes that are not JSON-safe as-is.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# The previous-hash value the first entry in any log chains from. Not the
# digest of any real content -- a documented sentinel, matching
# `reasoning.audit_log.GENESIS_HASH`'s own reasoning.
GENESIS_HASH = "0" * 64

BROKEN_FIELD_PREV_HASH = "prev_hash"
BROKEN_FIELD_RECORD_HASH = "record_hash"


def canonical_bytes(payload: dict[str, object]) -> bytes:
    """Renders a JSON-safe dict as its canonical byte form, for hashing.

    Sorted keys make the encoding independent of dict insertion order;
    compact, fixed separators remove the one remaining source of
    insignificant whitespace variation in `json.dumps`'s default output --
    the same reasoning `reasoning.audit_log`'s own canonicalization states.

    Args:
        payload: A JSON-safe dict.

    Returns:
        The UTF-8 bytes to feed to a hash function.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_entry_hash(prev_hash: str, record_dict: dict[str, object]) -> str:
    """Computes one entry's chained hash.

    Args:
        prev_hash: The previous entry's own hash, or `GENESIS_HASH` for the
            first entry in a log.
        record_dict: The JSON-safe record payload to hash.

    Returns:
        The hex-encoded SHA-256 digest of the canonical serialization of
        `{"prev_hash": prev_hash, "record": record_dict}`.
    """
    payload: dict[str, object] = {"prev_hash": prev_hash, "record": record_dict}
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class StoredEntry:
    """One on-disk entry: a JSON-safe record dict plus its hash-chain fields.

    Attributes:
        record_dict: The record payload, as stored (and as a caller's own
            `_record_from_json_dict`-style function would reconstruct a
            typed record from).
        prev_hash: The previous entry's hash, or `GENESIS_HASH` if this was
            the first entry appended.
        record_hash: `compute_entry_hash(prev_hash, record_dict)` as it was
            stored at append time.
    """

    record_dict: dict[str, object]
    prev_hash: str
    record_hash: str


class HashChainedLog:
    """An append-only, hash-chained, JSONL-file-backed store of JSON-safe dicts.

    Mirrors `reasoning.audit_log.AuditLog`'s design exactly (see its own
    module docstring for the storage-mechanism and tamper-evidence
    rationale this repeats): a file opened once, created but never
    truncated; every `append` opens the file in append mode, writes one
    line, and closes it, so nothing here can seek backward and overwrite a
    previous line; the interface exposes only `append`, `read_entries`, and
    `path` -- no update, delete, clear, or truncate method exists.
    """

    def __init__(self, path: Path) -> None:
        """Initializes the log, creating an empty file if none exists.

        Args:
            path: File path to append records to and read records from.
        """
        self._path = path
        self._path.touch(exist_ok=True)

    @property
    def path(self) -> Path:
        """Returns the backing file path.

        Returns:
            The path this log reads from and appends to.
        """
        return self._path

    def _last_hash(self) -> str:
        """Returns the most recently appended entry's hash.

        Returns:
            The last entry's `record_hash`, or `GENESIS_HASH` if the log
            has no entries yet.
        """
        last_line: str | None = None
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if last_line is None:
            return GENESIS_HASH
        return str(json.loads(last_line)["record_hash"])

    def append(self, record_dict: dict[str, object]) -> None:
        """Appends one JSON-safe record, chained to whatever precedes it.

        Args:
            record_dict: The record to append. Must already be JSON-safe;
                this class performs no type conversion of its own.
        """
        prev_hash = self._last_hash()
        record_hash = compute_entry_hash(prev_hash, record_dict)
        entry_dict = {"record": record_dict, "prev_hash": prev_hash, "record_hash": record_hash}
        line = json.dumps(entry_dict, sort_keys=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        logger.info("appended hash-chained entry to %s", self._path)

    def read_entries(self) -> tuple[StoredEntry, ...]:
        """Reads every entry currently in the log, in append order.

        Returns:
            All entries, oldest first.
        """
        with self._path.open("r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        entries: list[StoredEntry] = []
        for line in lines:
            data = json.loads(line)
            entries.append(
                StoredEntry(
                    record_dict=dict(data["record"]),
                    prev_hash=str(data["prev_hash"]),
                    record_hash=str(data["record_hash"]),
                )
            )
        return tuple(entries)

    def __len__(self) -> int:
        """Returns the number of entries currently in the log.

        Returns:
            The entry count.
        """
        return len(self.read_entries())


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of walking one log's hash chain end to end.

    Attributes:
        total_records: Number of entries examined.
        first_break_index: The 0-based index (in append order) of the
            first entry whose `prev_hash` or `record_hash` does not match
            what the chain implies, or `None` if every entry checked out.
        broken_field: `BROKEN_FIELD_PREV_HASH` or `BROKEN_FIELD_RECORD_HASH`
            -- which check failed at `first_break_index` -- or `None` if
            the chain is intact.
    """

    total_records: int
    first_break_index: int | None
    broken_field: str | None

    @property
    def intact(self) -> bool:
        """Whether the chain is unbroken end-to-end.

        Returns:
            True if no break was found.
        """
        return self.first_break_index is None


def verify_hash_chain(entries: tuple[StoredEntry, ...]) -> ChainVerificationResult:
    """Walks a sequence of stored entries and finds the first tamper point, if any.

    Two independent checks per entry, matching
    `reasoning.audit_chain.verify_chain`'s own two checks: its stored
    `prev_hash` must equal the previous entry's `record_hash` (or
    `GENESIS_HASH` for the first entry), and its stored `record_hash` must
    equal `compute_entry_hash(entry.prev_hash, entry.record_dict)`. Stops
    at the first entry where either check fails.

    Args:
        entries: Entries in append order, as returned by
            `HashChainedLog.read_entries`.

    Returns:
        Where (if anywhere) the chain first breaks.
    """
    for index, entry in enumerate(entries):
        expected_prev = GENESIS_HASH if index == 0 else entries[index - 1].record_hash
        if entry.prev_hash != expected_prev:
            return ChainVerificationResult(len(entries), index, BROKEN_FIELD_PREV_HASH)
        if entry.record_hash != compute_entry_hash(entry.prev_hash, entry.record_dict):
            return ChainVerificationResult(len(entries), index, BROKEN_FIELD_RECORD_HASH)
    return ChainVerificationResult(len(entries), None, None)
