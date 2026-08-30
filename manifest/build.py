"""Builds a `RunManifest` from one evaluation run's concrete inputs."""

from __future__ import annotations

import hashlib
import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from generator.attacks.corpus import EvaluationCorpus
from generator.config import digest_payload
from manifest.schema import RunManifest

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_LOCK_FILENAME = "requirements-lock.txt"

# Default hash-chained manifest log location, shared by run_full_eval.py
# (which appends to it) and run_verify_manifest.py (which looks manifests
# up in it) so the two never drift onto different literal paths.
DEFAULT_MANIFEST_LOG_PATH = Path("eval_manifests.jsonl")


def dependency_lock_hash(repo_root: Path = REPO_ROOT) -> str:
    """Hashes the dependency lock file's raw bytes.

    Args:
        repo_root: Repository root containing the lock file.

    Returns:
        A hex SHA-256 digest, or `"missing"` if the file does not exist --
        a manifest should still be buildable in that case, just honestly
        incomplete, the same disposition `git_commit` takes when `git`
        itself is unavailable.
    """
    lock_path = repo_root / DEPENDENCY_LOCK_FILENAME
    if not lock_path.is_file():
        logger.warning("dependency lock file not found at %s", lock_path)
        return "missing"
    return hashlib.sha256(lock_path.read_bytes()).hexdigest()


def git_commit_state(repo_root: Path = REPO_ROOT) -> tuple[str, bool]:
    """Reads the working tree's HEAD commit and whether it has uncommitted changes.

    Args:
        repo_root: Repository root to run `git` in.

    Returns:
        `(commit_hash, is_dirty)`. `commit_hash` is `"unknown"` and
        `is_dirty` is `True` if `git` is unavailable or `repo_root` is not
        a git repository -- a manifest built there is honestly not
        reproducible from a commit hash at all.
    """
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return commit, bool(status.strip())
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        logger.warning("could not read git state at %s", repo_root)
        return "unknown", True


def build_manifest(
    run_name: str,
    *,
    corpus: EvaluationCorpus,
    n_legitimate: int,
    run_config: dict[str, object],
    seeds: dict[str, int],
    metrics: dict[str, object],
    repo_root: Path = REPO_ROOT,
) -> RunManifest:
    """Builds a manifest recording everything this run's reproducibility depends on.

    Args:
        run_name: Which entry point produced this run (e.g.
            `"full_evaluation"`).
        corpus: The corpus this run evaluated. Its own `params_digest`,
            `seed`, and `attack_base_rate` are reused directly rather than
            recomputed.
        n_legitimate: The legitimate-session count requested when the
            corpus was built (not stored on `EvaluationCorpus` itself,
            since it records only the realized session mix).
        run_config: This run's own tunables (bootstrap resamples, cost
            ratio, sensitivity/latency sample counts, and so on) -- hashed
            exactly as given, not re-derived, so a caller passing an
            inconsistent dict gets an inconsistent hash rather than a
            silently "corrected" one.
        seeds: Every named seed this run's determinism depends on, beyond
            the corpus's own base seed.
        metrics: The run's own JSON-safe result dict.
        repo_root: Repository root, for reading git state and the
            dependency lock file. Overridable for tests.

    Returns:
        The built manifest, not yet hashed or logged -- see
        `manifest.schema.manifest_hash` and `manifest.log.ManifestLog`.
    """
    commit, dirty = git_commit_state(repo_root)
    return RunManifest(
        run_name=run_name,
        n_legitimate=n_legitimate,
        seed=corpus.seed,
        attack_base_rate=corpus.attack_base_rate,
        corpus_params_digest=corpus.params_digest,
        run_config_hash=digest_payload(run_config),
        seeds=dict(seeds),
        git_commit=commit,
        working_tree_dirty=dirty,
        dependency_lock_hash=dependency_lock_hash(repo_root),
        generated_at=datetime.now(UTC),
        metrics=metrics,
    )
