"""Tests for `common.hash_chain`: the generic hash-chain primitives `escalation/log.py` builds on."""

from __future__ import annotations

import json
from pathlib import Path

from common.hash_chain import GENESIS_HASH, HashChainedLog, compute_entry_hash, verify_hash_chain


def test_first_entry_chains_from_genesis(tmp_path: Path) -> None:
    """The first entry in a fresh log must chain from the documented genesis sentinel."""
    log = HashChainedLog(tmp_path / "chain.jsonl")
    log.append({"a": 1})
    entries = log.read_entries()
    assert len(entries) == 1
    assert entries[0].prev_hash == GENESIS_HASH
    assert entries[0].record_hash == compute_entry_hash(GENESIS_HASH, {"a": 1})


def test_second_entry_chains_from_the_first(tmp_path: Path) -> None:
    """Each entry after the first must chain from its immediate predecessor's hash."""
    log = HashChainedLog(tmp_path / "chain.jsonl")
    log.append({"a": 1})
    log.append({"a": 2})
    entries = log.read_entries()
    assert entries[1].prev_hash == entries[0].record_hash


def test_reopening_the_log_continues_the_same_chain(tmp_path: Path) -> None:
    """A fresh `HashChainedLog` instance pointed at the same file must chain from what's there."""
    path = tmp_path / "chain.jsonl"
    HashChainedLog(path).append({"a": 1})
    second = HashChainedLog(path)
    second.append({"a": 2})
    entries = second.read_entries()
    assert len(entries) == 2
    assert entries[1].prev_hash == entries[0].record_hash


def test_verify_hash_chain_reports_intact_for_an_untouched_log(tmp_path: Path) -> None:
    """A log nothing has touched after writing must verify as fully intact."""
    log = HashChainedLog(tmp_path / "chain.jsonl")
    for i in range(5):
        log.append({"i": i})
    result = verify_hash_chain(log.read_entries())
    assert result.intact
    assert result.total_records == 5


def test_verify_hash_chain_detects_a_tampered_record(tmp_path: Path) -> None:
    """Editing one entry's content without updating its hash must be caught at that index."""
    path = tmp_path / "chain.jsonl"
    log = HashChainedLog(path)
    log.append({"a": 1})
    log.append({"a": 2})
    log.append({"a": 3})

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["record"]["a"] = 999
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_hash_chain(HashChainedLog(path).read_entries())
    assert not result.intact
    assert result.first_break_index == 1
    assert result.broken_field == "record_hash"


def test_verify_hash_chain_detects_a_forged_link(tmp_path: Path) -> None:
    """Forging prev_hash without touching record content is a separate, also-caught break."""
    path = tmp_path / "chain.jsonl"
    log = HashChainedLog(path)
    log.append({"a": 1})
    log.append({"a": 2})

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["prev_hash"] = "f" * 64
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_hash_chain(HashChainedLog(path).read_entries())
    assert not result.intact
    assert result.first_break_index == 1
    assert result.broken_field == "prev_hash"


def test_empty_log_verifies_intact_with_zero_records(tmp_path: Path) -> None:
    """A freshly created, never-appended-to log must verify as trivially intact."""
    log = HashChainedLog(tmp_path / "chain.jsonl")
    result = verify_hash_chain(log.read_entries())
    assert result.intact
    assert result.total_records == 0


def test_exposes_no_mutation_or_deletion_method() -> None:
    """The public interface must stay append-only: no update, delete, or clear method."""
    public_methods = {name for name in dir(HashChainedLog) if not name.startswith("_")}
    assert public_methods == {"path", "append", "read_entries"}
