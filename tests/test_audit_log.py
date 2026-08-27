"""Tests for `reasoning.audit_log`: append-only persistence of decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

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


def test_append_then_read_all_round_trips(tmp_path: Path) -> None:
    """A record written must read back with every field intact."""
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _record()
    log.append(record)
    assert log.read_all() == (record,)


def test_records_are_read_back_in_append_order(tmp_path: Path) -> None:
    """Multiple records must replay in the order they were appended."""
    log = AuditLog(tmp_path / "audit.jsonl")
    first = _record(session_id=uuid4())
    second = _record(session_id=uuid4())
    log.append(first)
    log.append(second)
    assert log.read_all() == (first, second)


def test_no_mandate_id_round_trips_as_none(tmp_path: Path) -> None:
    """A session with no mandate presented must round-trip mandate_id=None, not a sentinel string."""
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _record(mandate_id=None)
    log.append(record)
    assert log.read_all()[0].mandate_id is None


def test_reopening_the_log_sees_records_from_a_prior_instance(tmp_path: Path) -> None:
    """A fresh `AuditLog` pointed at the same file must see everything already appended."""
    path = tmp_path / "audit.jsonl"
    first_instance = AuditLog(path)
    first_instance.append(_record())

    second_instance = AuditLog(path)
    second_instance.append(_record())

    assert len(second_instance.read_all()) == 2
    assert len(first_instance.read_all()) == 2


def test_len_reports_record_count(tmp_path: Path) -> None:
    """len() must reflect the number of appended records."""
    log = AuditLog(tmp_path / "audit.jsonl")
    assert len(log) == 0
    log.append(_record())
    assert len(log) == 1


def test_appending_never_shrinks_the_log(tmp_path: Path) -> None:
    """Each append must strictly grow the file; nothing here can overwrite prior lines."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    sizes = []
    for _ in range(5):
        log.append(_record())
        sizes.append(path.stat().st_size)
    assert sizes == sorted(sizes)
    assert len(set(sizes)) == len(sizes)


def test_audit_log_exposes_no_mutation_or_deletion_method() -> None:
    """The class must offer no way to update, delete, or clear an existing record.

    A maintainability guard, not just documentation: if a future change adds
    a `delete`, `remove`, `clear`, `truncate`, or `update` method to
    `AuditLog`, this test starts failing immediately.
    """
    forbidden_names = {"delete", "remove", "clear", "truncate", "update", "pop", "overwrite"}
    public_methods = {name for name in dir(AuditLog) if not name.startswith("_")}
    assert public_methods.isdisjoint(forbidden_names)
    assert public_methods == {"append", "read_all", "path"}


def test_constructing_over_an_existing_file_does_not_truncate_it(tmp_path: Path) -> None:
    """Pointing a new `AuditLog` at a file with content must not erase that content."""
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path)
    first.append(_record())
    assert len(AuditLog(path)) == 1


def test_top_features_round_trip_as_signed_floats(tmp_path: Path) -> None:
    """Signed SHAP-style values must survive the JSON round trip without truncation."""
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _record(top_features=(("agent_prior_session_count", 0.76051234), ("hour_of_day", -0.08321)))
    log.append(record)
    read_back = log.read_all()[0]
    assert read_back.top_features == record.top_features


def test_read_all_rejects_malformed_top_features(tmp_path: Path) -> None:
    """A corrupted line with a non-pair top_features entry must fail loudly, not silently drop data."""
    path = tmp_path / "audit.jsonl"
    path.write_text(
        '{"record_id": "' + str(uuid4()) + '", "session_id": "' + str(uuid4()) + '", '
        '"mandate_id": null, "blocked": true, "source": "rules", "rules_fired": [], '
        '"behavioral_score": null, "top_features": [["only_one_element"]], '
        '"narrative": "x", "narrated_by_model": "m", "created_at": "2026-08-27T00:00:00+00:00"}\n',
        encoding="utf-8",
    )
    log = AuditLog(path)
    with pytest.raises(ValueError, match=r"\[name, value\] pairs"):
        log.read_all()
