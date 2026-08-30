"""Tests for `reasoning.audit_log`: append-only, hash-chained persistence of decisions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from reasoning.audit_log import GENESIS_HASH, AuditLog, compute_record_hash
from reasoning.schema import AuditRecord, Counterfactual, CounterfactualEdit


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
        "counterfactual": None,
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


def test_record_with_counterfactual_round_trips(tmp_path: Path) -> None:
    """A record carrying a real counterfactual must read back with every edit intact."""
    log = AuditLog(tmp_path / "audit.jsonl")
    counterfactual = Counterfactual(
        layer="layer2_scope",
        feasible=True,
        edits=(CounterfactualEdit("trace.amount", "8000.00", "2000.00"),),
        explanation="This verdict flips to ALLOW if the amount were at most 2000.00 INR.",
    )
    record = _record(counterfactual=counterfactual)
    log.append(record)
    assert log.read_all() == (record,)


def test_absent_counterfactual_is_omitted_from_the_stored_line(tmp_path: Path) -> None:
    """A None counterfactual must not appear as an explicit null on disk.

    This is the property that keeps a hash computed before this field
    existed reproducible after it was added -- see
    `reasoning.audit_log._record_to_json_dict`'s own docstring for why.
    """
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(_record(counterfactual=None))
    line = log.path.read_text(encoding="utf-8").strip()
    stored_record = json.loads(line)["record"]
    assert "counterfactual" not in stored_record


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
    assert public_methods == {"append", "read_all", "read_entries", "path"}


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
    malformed_record = (
        '{"record_id": "' + str(uuid4()) + '", "session_id": "' + str(uuid4()) + '", '
        '"mandate_id": null, "blocked": true, "source": "rules", "rules_fired": [], '
        '"behavioral_score": null, "top_features": [["only_one_element"]], '
        '"narrative": "x", "narrated_by_model": "m", "created_at": "2026-08-27T00:00:00+00:00"}'
    )
    path.write_text(
        json.dumps({"record": json.loads(malformed_record), "prev_hash": GENESIS_HASH, "record_hash": "x"})
        + "\n",
        encoding="utf-8",
    )
    log = AuditLog(path)
    with pytest.raises(ValueError, match=r"\[name, value\] pairs"):
        log.read_all()


def test_first_record_chains_from_genesis_hash(tmp_path: Path) -> None:
    """The first entry in a fresh log must chain from the documented genesis sentinel."""
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _record()
    log.append(record)
    entry = log.read_entries()[0]
    assert entry.prev_hash == GENESIS_HASH
    assert entry.record_hash == compute_record_hash(GENESIS_HASH, record)


def test_second_record_chains_from_the_first_records_hash(tmp_path: Path) -> None:
    """Each entry after the first must chain from its predecessor's own record_hash."""
    log = AuditLog(tmp_path / "audit.jsonl")
    first = _record(session_id=uuid4())
    second = _record(session_id=uuid4())
    log.append(first)
    log.append(second)
    entries = log.read_entries()
    assert entries[1].prev_hash == entries[0].record_hash
    assert entries[1].record_hash == compute_record_hash(entries[0].record_hash, second)


def test_chain_continues_correctly_across_reopened_log_instances(tmp_path: Path) -> None:
    """A fresh `AuditLog` pointed at an existing file must chain the next append from its true head."""
    path = tmp_path / "audit.jsonl"
    first_instance = AuditLog(path)
    first_instance.append(_record())

    second_instance = AuditLog(path)
    second_instance.append(_record())

    entries = second_instance.read_entries()
    assert entries[1].prev_hash == entries[0].record_hash
