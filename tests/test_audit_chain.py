"""Tests for `reasoning.audit_chain`: tamper detection over a hash-chained audit log."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from reasoning.audit_chain import (
    BROKEN_FIELD_PREV_HASH,
    BROKEN_FIELD_RECORD_HASH,
    verify_chain,
)
from reasoning.audit_log import AuditLog
from reasoning.schema import AuditRecord


def _record(**overrides: object) -> AuditRecord:
    """Builds a minimally valid `AuditRecord`, overridable per test.

    Args:
        **overrides: Field values to override.

    Returns:
        A valid `AuditRecord`.
    """
    defaults: dict[str, object] = {
        "record_id": uuid4(),
        "session_id": uuid4(),
        "mandate_id": uuid4(),
        "blocked": True,
        "source": "rules",
        "rules_fired": ("layer1:expired",),
        "behavioral_score": None,
        "top_features": (("agent_prior_session_count", 0.9), ("hour_of_day", -0.1)),
        "narrative": "Blocked because the mandate had expired.",
        "narrated_by_model": "openai/gpt-oss-120b",
        "created_at": datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return AuditRecord(**defaults)  # type: ignore[arg-type]


def test_an_untouched_log_verifies_intact(tmp_path: Path) -> None:
    """A log nothing has touched after writing must verify as fully intact."""
    log = AuditLog(tmp_path / "audit.jsonl")
    for _ in range(5):
        log.append(_record(session_id=uuid4()))

    result = verify_chain(log.read_entries())
    assert result.intact
    assert result.first_break_index is None
    assert result.broken_field is None
    assert result.total_records == 5


def test_an_empty_log_verifies_intact_with_zero_records(tmp_path: Path) -> None:
    """A freshly created, never-appended-to log must verify as trivially intact."""
    log = AuditLog(tmp_path / "audit.jsonl")
    result = verify_chain(log.read_entries())
    assert result.intact
    assert result.total_records == 0


def test_mutating_one_byte_of_a_records_content_is_detected_at_the_right_index(tmp_path: Path) -> None:
    """Editing a single character inside an existing record must be caught at that record's index."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(_record(session_id=uuid4()))
    log.append(_record(session_id=uuid4()))
    log.append(_record(session_id=uuid4()))

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered_entry = json.loads(lines[1])
    original_narrative = tampered_entry["record"]["narrative"]
    tampered_entry["record"]["narrative"] = "X" + original_narrative[1:]
    assert tampered_entry["record"]["narrative"] != original_narrative
    lines[1] = json.dumps(tampered_entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(AuditLog(path).read_entries())
    assert result.first_break_index == 1
    assert result.broken_field == BROKEN_FIELD_RECORD_HASH
    assert not result.intact


def test_forging_prev_hash_without_recomputing_record_hash_is_detected(tmp_path: Path) -> None:
    """Pointing an entry's prev_hash somewhere else must be caught even if record_hash is untouched."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(_record(session_id=uuid4()))
    log.append(_record(session_id=uuid4()))

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered_entry = json.loads(lines[1])
    tampered_entry["prev_hash"] = "f" * 64
    lines[1] = json.dumps(tampered_entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(AuditLog(path).read_entries())
    assert result.first_break_index == 1
    assert result.broken_field == BROKEN_FIELD_PREV_HASH


def test_break_is_reported_at_the_first_tampered_entry_not_a_later_one(tmp_path: Path) -> None:
    """With two tampered entries, verification must stop and report the earlier one."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for _ in range(4):
        log.append(_record(session_id=uuid4()))

    lines = path.read_text(encoding="utf-8").splitlines()
    for index in (1, 2):
        entry = json.loads(lines[index])
        entry["record"]["narrative"] = "TAMPERED"
        lines[index] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(AuditLog(path).read_entries())
    assert result.first_break_index == 1
