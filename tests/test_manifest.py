"""Tests for `manifest`: building, hashing, hash-chained logging, and verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

from generator.attacks.corpus import build_evaluation_corpus
from manifest.build import build_manifest, dependency_lock_hash, git_commit_state
from manifest.log import ManifestLog, verify_chain
from manifest.schema import RunManifest, manifest_from_json_dict, manifest_hash, manifest_to_json_dict
from manifest.verify import verify_manifest

_CORPUS = build_evaluation_corpus(500, seed=3)


def _manifest(repo_root: Path, metrics: dict[str, object] | None = None) -> RunManifest:
    """Builds a manifest against a given repo root, for tests that fake one out."""
    return build_manifest(
        "test_run",
        corpus=_CORPUS,
        n_legitimate=500,
        run_config={"bootstrap_resamples": 100},
        seeds={"pipeline_random_state": 42},
        metrics={"auc_pr": 0.9} if metrics is None else metrics,
        repo_root=repo_root,
    )


def test_dependency_lock_hash_matches_file_bytes(tmp_path: Path) -> None:
    """The hash must be a plain SHA-256 of the lock file's raw bytes."""
    lock_path = tmp_path / "requirements-lock.txt"
    lock_path.write_bytes(b"package==1.0.0\n")
    expected = hashlib.sha256(b"package==1.0.0\n").hexdigest()
    assert dependency_lock_hash(tmp_path) == expected


def test_dependency_lock_hash_missing_file_reports_missing(tmp_path: Path) -> None:
    """A repo root with no lock file must fail honestly, not raise or fabricate a hash."""
    assert dependency_lock_hash(tmp_path) == "missing"


def test_git_commit_state_on_non_git_directory_is_unknown_and_dirty(tmp_path: Path) -> None:
    """A directory that isn't a git repository must report honestly, not raise."""
    commit, dirty = git_commit_state(tmp_path)
    assert commit == "unknown"
    assert dirty is True


def test_build_manifest_reuses_the_corpus_own_fields(tmp_path: Path) -> None:
    """The manifest must not recompute what the corpus object already knows about itself."""
    manifest = _manifest(tmp_path)
    assert manifest.n_legitimate == 500
    assert manifest.seed == _CORPUS.seed
    assert manifest.attack_base_rate == _CORPUS.attack_base_rate
    assert manifest.corpus_params_digest == _CORPUS.params_digest


def test_manifest_hash_is_deterministic() -> None:
    """The same manifest content must always hash the same way."""
    manifest = _manifest(Path("."))
    assert manifest_hash(manifest) == manifest_hash(manifest)


def test_manifest_hash_is_sensitive_to_metrics() -> None:
    """Two manifests differing only in their embedded metrics must hash differently."""
    a = _manifest(Path("."), metrics={"auc_pr": 0.9})
    b = _manifest(Path("."), metrics={"auc_pr": 0.5})
    assert manifest_hash(a) != manifest_hash(b)


def test_manifest_round_trips_through_json() -> None:
    """A manifest must survive a to-dict/from-dict round trip unchanged."""
    manifest = _manifest(Path("."))
    restored = manifest_from_json_dict(manifest_to_json_dict(manifest))
    assert restored == manifest


def test_manifest_log_append_and_read_all(tmp_path: Path) -> None:
    """An appended manifest must read back identical and the chain must stay intact."""
    log = ManifestLog(tmp_path / "manifests.jsonl")
    manifest = _manifest(Path("."))
    content_hash = log.append(manifest)
    assert content_hash == manifest_hash(manifest)
    assert log.read_all() == (manifest,)
    assert len(log) == 1
    assert verify_chain(log).intact


def test_manifest_log_chains_multiple_entries(tmp_path: Path) -> None:
    """Multiple appends must all read back and the chain must stay intact across them."""
    log = ManifestLog(tmp_path / "manifests.jsonl")
    first = _manifest(Path("."), metrics={"auc_pr": 0.9})
    second = _manifest(Path("."), metrics={"auc_pr": 0.95})
    log.append(first)
    log.append(second)
    assert log.read_all() == (first, second)
    assert len(log) == 2
    assert verify_chain(log).intact


def test_verify_manifest_all_match_for_a_freshly_built_manifest() -> None:
    """A manifest built and immediately verified against the real repo must match on every input."""
    manifest = _manifest(Path("."))
    result = verify_manifest(manifest, repo_root=Path("."))
    assert result.git_commit_matches
    assert result.dependency_lock_matches
    assert result.default_corpus_params_match
    assert result.mismatched_fields == ()


def test_verify_manifest_detects_dependency_lock_drift(tmp_path: Path) -> None:
    """A lock file that changed after the manifest was built must be reported as mismatched."""
    (tmp_path / "requirements-lock.txt").write_bytes(b"package==1.0.0\n")
    manifest = _manifest(tmp_path)
    (tmp_path / "requirements-lock.txt").write_bytes(b"package==2.0.0\n")

    result = verify_manifest(manifest, repo_root=tmp_path)
    assert not result.dependency_lock_matches
    assert "dependency_lock_hash" in result.mismatched_fields


def test_verify_manifest_detects_corpus_params_drift() -> None:
    """A manifest recording a stale corpus-params digest must be reported as mismatched."""
    manifest = _manifest(Path("."))
    tampered = manifest_from_json_dict(
        {**manifest_to_json_dict(manifest), "corpus_params_digest": "0" * 64}
    )

    result = verify_manifest(tampered, repo_root=Path("."))
    assert not result.default_corpus_params_match
    assert "corpus_params_digest" in result.mismatched_fields
