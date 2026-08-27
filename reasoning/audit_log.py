"""Append-only audit log for Layer 4 decisions.

Storage-mechanism decision: a JSONL file, one `AuditRecord` per line,
written only in file-append mode. Weighed against an in-memory list:

- A file survives process restart and is directly human-reviewable (`cat`,
  `grep`, `jq`) with no special tooling -- consistent with this project's
  "every decision ... is human-reviewable" claim (README Section 3) in a
  way a process-local list cannot be, since the list vanishes with the
  process.
- Append-only is enforced by the interface, not by convention: `AuditLog`
  exposes exactly `append` and `read_all` -- no `update`, `delete`, `clear`,
  or `truncate` method exists anywhere on the class, and there is no way to
  reach the backing file except through those two methods and through
  reopening it in true append mode (`"a"`), which cannot overwrite existing
  bytes. `tests/test_audit_log.py` checks this directly, both by listing the
  class's own methods and by writing, reading, writing more, and reading
  again. An in-memory list's append-only-ness would be a discipline someone
  has to remember; nothing stops `list.pop` from being called on it later.
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
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from uuid import UUID

from reasoning.schema import AuditRecord

logger = logging.getLogger(__name__)


def _record_to_json_dict(record: AuditRecord) -> dict[str, object]:
    """Renders one `AuditRecord` as a JSON-safe dict.

    Explicit field-by-field mapping, not a generic `dataclasses.asdict`
    walk: `record_id`/`session_id`/`mandate_id` (UUID), `created_at`
    (datetime), and `top_features` (a tuple of tuples) are not JSON-safe
    as-is, the same reasoning `eval/report_json.py` states for its own
    explicit mapping.

    Args:
        record: The record to render.

    Returns:
        A dict safe to pass to `json.dumps`.
    """
    return {
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


def _record_from_json_dict(data: dict[str, object]) -> AuditRecord:
    """Reconstructs one `AuditRecord` from a JSON-decoded dict.

    Args:
        data: A dict previously produced by `_record_to_json_dict` (or an
            equivalently shaped one read back from the log file).

    Returns:
        The reconstructed record.

    Raises:
        ValueError: If `rules_fired` or `top_features` is not a list, or if
            a `top_features` entry is not a two-element `[name, value]`
            pair.
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
        narrative=str(data["narrative"]),
        narrated_by_model=str(data["narrated_by_model"]),
        created_at=datetime.fromisoformat(str(data["created_at"])),
    )


class AuditLog:
    """An append-only, JSONL-file-backed store of `AuditRecord`s.

    See the module docstring for the storage-mechanism tradeoff. Construct
    one per log file; the file is created, but never truncated, if it does
    not already exist.
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

    def append(self, record: AuditRecord) -> None:
        """Appends one record to the log.

        Args:
            record: The record to append.
        """
        line = json.dumps(_record_to_json_dict(record), sort_keys=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        logger.info("appended audit record %s for session %s", record.record_id, record.session_id)

    def read_all(self) -> tuple[AuditRecord, ...]:
        """Reads every record currently in the log, in append order.

        Returns:
            All records, oldest first.
        """
        with self._path.open("r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        return tuple(_record_from_json_dict(json.loads(line)) for line in lines)

    def __len__(self) -> int:
        """Returns the number of records currently in the log.

        Returns:
            The record count.
        """
        return len(self.read_all())
