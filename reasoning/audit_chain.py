"""Tamper-evidence check for `reasoning.audit_log`'s hash-chained entries.

Kept separate from `AuditLog` itself so verifying a log's integrity is a
plain function over data already read from it (`AuditLog.read_entries`),
not a method that has to also own file access -- the same split this
project already uses elsewhere between "read/build a value" and "check a
property of it" (e.g. `formal.verify` against `formal.model`).
"""

from __future__ import annotations

from dataclasses import dataclass

from reasoning.audit_log import GENESIS_HASH, AuditLogEntry, compute_record_hash

# The two independent things that can go wrong with one entry: its link to
# the previous entry was rewritten, or its own record content was rewritten
# without the stored record_hash being recomputed to match.
BROKEN_FIELD_PREV_HASH = "prev_hash"
BROKEN_FIELD_RECORD_HASH = "record_hash"


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of walking one audit log's hash chain end to end.

    Attributes:
        total_records: Number of entries examined.
        first_break_index: The 0-based index (in append order) of the first
            entry whose `prev_hash` or `record_hash` does not match what the
            chain implies, or `None` if every entry checked out.
        broken_field: `BROKEN_FIELD_PREV_HASH` or `BROKEN_FIELD_RECORD_HASH`
            -- which check failed at `first_break_index` -- or `None` if the
            chain is intact.
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


def verify_chain(entries: tuple[AuditLogEntry, ...]) -> ChainVerificationResult:
    """Walks a sequence of audit-log entries and finds the first tamper point, if any.

    Two independent checks per entry, in order: its stored `prev_hash` must
    equal the previous entry's `record_hash` (or `GENESIS_HASH` for the
    first entry) -- catching a forged link -- and its stored `record_hash`
    must equal `compute_record_hash(entry.prev_hash, entry.record)` --
    catching a rewritten record whose hash field was never updated to
    match. Stops at the first entry where either check fails; later entries
    are not examined, since a broken chain has already been established.

    Args:
        entries: Entries in append order, as returned by
            `reasoning.audit_log.AuditLog.read_entries`.

    Returns:
        Where (if anywhere) the chain first breaks.
    """
    for index, entry in enumerate(entries):
        expected_prev = GENESIS_HASH if index == 0 else entries[index - 1].record_hash
        if entry.prev_hash != expected_prev:
            return ChainVerificationResult(len(entries), index, BROKEN_FIELD_PREV_HASH)
        if entry.record_hash != compute_record_hash(entry.prev_hash, entry.record):
            return ChainVerificationResult(len(entries), index, BROKEN_FIELD_RECORD_HASH)
    return ChainVerificationResult(len(entries), None, None)
