"""Append-only, hash-chained audit log for Layer 4 decisions.

Storage-mechanism decision: a JSONL file, one entry per line, written only
in file-append mode. Weighed against an in-memory list:

- A file survives process restart and is directly human-reviewable (`cat`,
  `grep`, `jq`) with no special tooling -- consistent with this project's
  "every decision ... is human-reviewable" claim (see THREAT_MODEL.md) in
  a way a process-local list cannot be, since the list vanishes with the
  process.
- Append-only is enforced by the interface, not by convention: `AuditLog`
  exposes exactly `append`, `read_all`, and `read_entries` -- no `update`,
  `delete`, `clear`, or `truncate` method exists anywhere on the class, and
  there is no way to reach the backing file except through those methods and
  through reopening it in true append mode (`"a"`), which cannot overwrite
  existing bytes. `tests/test_audit_log.py` checks this directly, both by
  listing the class's own methods and by writing, reading, writing more, and
  reading again. An in-memory list's append-only-ness would be a discipline
  someone has to remember; nothing stops `list.pop` from being called on it
  later.
- Tradeoff accepted deliberately: no file locking, so two processes writing
  to the same path concurrently could interleave or race. Acceptable for
  this project's single-process eval/demo use; a multi-writer production
  deployment would need a real append-only store (an insert-only database
  table with no delete grant, an object-store bucket with object-lock, or
  similar), not a bare file, and that is a real design change for later, not
  something this module tries to paper over.

Every `append` call opens the file, writes one line, and closes it -- no
handle is held open across calls, so nothing here can seek backward and
overwrite a previous line.

Tamper evidence: each entry embeds `prev_hash` (the previous entry's own
`record_hash`, or `GENESIS_HASH` for the first entry) and `record_hash` (the
SHA-256 of the canonical serialization of `{prev_hash, record}`). This
means the file being append-only is not the only thing standing between a
reader and undetected tampering with an *existing* line -- editing any byte
of a stored record, or forging a `prev_hash` to point somewhere else,
changes what `record_hash` should be, and `reasoning.audit_chain.verify_chain`
(or `run_verify_audit_chain.py`) detects the mismatch and reports exactly
which entry it first appears at. Canonical serialization is `json.dumps`
with `sort_keys=True` and compact, fixed separators (`","`/`":"`, no
whitespace): sorted keys make the encoding independent of dict insertion
order, and compact separators remove the one remaining source of
insignificant whitespace variation in `json.dumps`'s default output, so the
same logical content always hashes to the same bytes. The on-disk line
itself is still written with the default (spaced) separators, matching the
module's own "directly human-reviewable" goal -- canonicalization only
matters for what gets hashed, not for what a human reads with `cat`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

from reasoning.schema import AuditRecord, Counterfactual, CounterfactualEdit

logger = logging.getLogger(__name__)

# The previous-hash value the first entry in any log chains from. Not the
# digest of any real content -- a documented sentinel, the same role "0"*64
# plays as a genesis previous-hash in other hash-chained log designs. A
# genuine SHA-256 digest could in principle equal this value by chance, but
# only with probability 2^-256; that is not a property this design leans on
# for security, only for having an unambiguous, spelled-out starting point.
GENESIS_HASH = "0" * 64


def _record_to_json_dict(record: AuditRecord) -> dict[str, object]:
    """Renders one `AuditRecord` as a JSON-safe dict.

    Explicit field-by-field mapping, not a generic `dataclasses.asdict`
    walk: `record_id`/`session_id`/`mandate_id` (UUID), `created_at`
    (datetime), `top_features` (a tuple of tuples), and `counterfactual`
    (a nested dataclass) are not JSON-safe as-is, the same reasoning
    `eval/report_json.py` states for its own explicit mapping.

    `counterfactual` is omitted from the dict entirely when None, rather
    than written as an explicit `null` -- added specifically so this
    function's output for a `None` counterfactual is byte-identical to what
    it produced before this field existed. Every entry appended before this
    field was added has `counterfactual=None` on read-back (see
    `_counterfactual_from_json_dict`'s handling of an absent key), and its
    stored `record_hash` was computed by hashing a dict with no
    `"counterfactual"` key at all; including the key as `null` here would
    change the canonical bytes for those entries and make
    `reasoning.audit_chain.verify_chain` report every one of them as
    tampered, which they are not.

    Args:
        record: The record to render.

    Returns:
        A dict safe to pass to `json.dumps`.
    """
    payload: dict[str, object] = {
        "record_id": str(record.record_id),
        "session_id": str(record.session_id),
        "mandate_id": str(record.mandate_id) if record.mandate_id is not None else None,
        "blocked": record.blocked,
        "source": record.source,
        "rules_fired": list(record.rules_fired),
        "behavioral_score": record.behavioral_score,
        "top_features": [[name, value] for name, value in record.top_features],
        "narrative": record.narrative,
        "narrated_by_model": record.narrated_by_model,
        "created_at": record.created_at.isoformat(),
    }
    if record.counterfactual is not None:
        payload["counterfactual"] = _counterfactual_to_json_dict(record.counterfactual)
    return payload


def _counterfactual_to_json_dict(counterfactual: Counterfactual | None) -> dict[str, object] | None:
    """Renders one `Counterfactual` (or its absence) as a JSON-safe dict.

    Args:
        counterfactual: The counterfactual to render, or None.

    Returns:
        None if `counterfactual` is None, else a JSON-safe dict.
    """
    if counterfactual is None:
        return None
    return {
        "layer": counterfactual.layer,
        "feasible": counterfactual.feasible,
        "edits": [
            {"field": edit.field, "real_value": edit.real_value, "suggested_value": edit.suggested_value}
            for edit in counterfactual.edits
        ],
        "explanation": counterfactual.explanation,
    }


def _counterfactual_from_json_dict(data: object) -> Counterfactual | None:
    """Reconstructs one `Counterfactual` from a JSON-decoded value.

    Args:
        data: The decoded `"counterfactual"` value. None (including when
            the key is absent entirely, from an audit record written
            before this field existed) reconstructs as None -- an older
            entry is read back exactly as it was written, not treated as
            malformed.

    Returns:
        The reconstructed counterfactual, or None.

    Raises:
        ValueError: If `data` is present but not a dict, or an `edits`
            entry is not a `{"field", "real_value", "suggested_value"}`
            mapping.
    """
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("audit record 'counterfactual' must be a dict or null")
    edits_raw = data["edits"]
    if not isinstance(edits_raw, list):
        raise ValueError("audit record 'counterfactual.edits' must be a list")
    edits = tuple(
        CounterfactualEdit(
            field=str(edit["field"]),
            real_value=str(edit["real_value"]),
            suggested_value=str(edit["suggested_value"]),
        )
        for edit in edits_raw
    )
    return Counterfactual(
        layer=str(data["layer"]), feasible=bool(data["feasible"]), edits=edits, explanation=str(data["explanation"])
    )


def _record_from_json_dict(data: dict[str, object]) -> AuditRecord:
    """Reconstructs one `AuditRecord` from a JSON-decoded dict.

    Args:
        data: A dict previously produced by `_record_to_json_dict` (or an
            equivalently shaped one read back from the log file).

    Returns:
        The reconstructed record.

    Raises:
        ValueError: If `rules_fired` or `top_features` is not a list, if a
            `top_features` entry is not a two-element `[name, value]` pair,
            or if `counterfactual` is present but malformed.
        KeyError: If a required field is missing.
    """
    rules_fired_raw = data["rules_fired"]
    if not isinstance(rules_fired_raw, list):
        raise ValueError("audit record 'rules_fired' must be a list")

    top_features_raw = data["top_features"]
    if not isinstance(top_features_raw, list):
        raise ValueError("audit record 'top_features' must be a list")
    top_features: list[tuple[str, float]] = []
    for pair in top_features_raw:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("audit record 'top_features' entries must be [name, value] pairs")
        top_features.append((str(pair[0]), float(pair[1])))

    mandate_id_raw = data["mandate_id"]
    behavioral_score_raw = data["behavioral_score"]
    behavioral_score: float | None = None
    if behavioral_score_raw is not None:
        if not isinstance(behavioral_score_raw, int | float):
            raise ValueError("audit record 'behavioral_score' must be a number or null")
        behavioral_score = float(behavioral_score_raw)

    return AuditRecord(
        record_id=UUID(str(data["record_id"])),
        session_id=UUID(str(data["session_id"])),
        mandate_id=UUID(str(mandate_id_raw)) if mandate_id_raw is not None else None,
        blocked=bool(data["blocked"]),
        source=str(data["source"]),
        rules_fired=tuple(str(r) for r in rules_fired_raw),
        behavioral_score=behavioral_score,
        top_features=tuple(top_features),
        counterfactual=_counterfactual_from_json_dict(data.get("counterfactual")),
        narrative=str(data["narrative"]),
        narrated_by_model=str(data["narrated_by_model"]),
        created_at=datetime.fromisoformat(str(data["created_at"])),
    )


def _canonical_bytes(payload: dict[str, object]) -> bytes:
    """Renders a JSON-safe dict as its canonical byte form, for hashing.

    See the module docstring's "Tamper evidence" paragraph for why sorted
    keys and compact separators are what make this canonical.

    Args:
        payload: A JSON-safe dict.

    Returns:
        The UTF-8 bytes to feed to a hash function.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_record_hash(prev_hash: str, record: AuditRecord) -> str:
    """Computes one record's chained hash.

    Args:
        prev_hash: The previous entry's `record_hash`, or `GENESIS_HASH` if
            `record` is the first entry in its log.
        record: The record to hash.

    Returns:
        The hex-encoded SHA-256 digest of the canonical serialization of
        `{"prev_hash": prev_hash, "record": record}`.
    """
    payload: dict[str, object] = {"prev_hash": prev_hash, "record": _record_to_json_dict(record)}
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class AuditLogEntry:
    """One on-disk audit-log entry: a record plus its position in the hash chain.

    Attributes:
        record: The decision record itself.
        prev_hash: The previous entry's `record_hash`, or `GENESIS_HASH` if
            this was the first entry appended to its log.
        record_hash: `compute_record_hash(prev_hash, record)` as it was
            stored at append time -- kept alongside `record` rather than
            only recomputed on read, so `reasoning.audit_chain.verify_chain`
            can detect a mismatch between what is stored and what the
            content actually implies, not merely recompute a hash the file
            could just as easily have been edited to match.
    """

    record: AuditRecord
    prev_hash: str
    record_hash: str


class AuditLog:
    """An append-only, hash-chained, JSONL-file-backed store of `AuditRecord`s.

    See the module docstring for the storage-mechanism and tamper-evidence
    design. Construct one per log file; the file is created, but never
    truncated, if it does not already exist.
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
        """Returns the most recently appended entry's `record_hash`.

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

    def append(self, record: AuditRecord) -> None:
        """Appends one record to the log, chained to whatever precedes it.

        Args:
            record: The record to append.
        """
        prev_hash = self._last_hash()
        record_hash = compute_record_hash(prev_hash, record)
        entry_dict = {
            "record": _record_to_json_dict(record),
            "prev_hash": prev_hash,
            "record_hash": record_hash,
        }
        line = json.dumps(entry_dict, sort_keys=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        logger.info("appended audit record %s for session %s", record.record_id, record.session_id)

    def read_entries(self) -> tuple[AuditLogEntry, ...]:
        """Reads every entry currently in the log, in append order.

        Returns:
            All entries, oldest first, each carrying its stored hash-chain
            fields alongside its record.
        """
        with self._path.open("r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        entries: list[AuditLogEntry] = []
        for line in lines:
            data = json.loads(line)
            entries.append(
                AuditLogEntry(
                    record=_record_from_json_dict(data["record"]),
                    prev_hash=str(data["prev_hash"]),
                    record_hash=str(data["record_hash"]),
                )
            )
        return tuple(entries)

    def read_all(self) -> tuple[AuditRecord, ...]:
        """Reads every record currently in the log, in append order.

        Returns:
            All records, oldest first.
        """
        return tuple(entry.record for entry in self.read_entries())

    def __len__(self) -> int:
        """Returns the number of records currently in the log.

        Returns:
            The record count.
        """
        return len(self.read_all())
