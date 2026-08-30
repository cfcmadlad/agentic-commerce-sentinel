"""The `RunManifest` record: what one evaluation run depended on and produced."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from common.hash_chain import canonical_bytes


@dataclass(frozen=True)
class RunManifest:
    """Everything needed to identify, and later re-verify, one evaluation run.

    Attributes:
        run_name: Which entry point produced this (e.g. `"full_evaluation"`).
        n_legitimate: Legitimate-session count the evaluated corpus used.
        seed: The corpus's base seed.
        attack_base_rate: The corpus's realized attack fraction.
        corpus_params_digest: The corpus's own `EvaluationCorpus.params_digest`
            -- the generator/attack parameter digest, reused directly rather
            than recomputed, so this field is always exactly what the corpus
            object itself already reports.
        run_config_hash: Digest of this run's own tunables (bootstrap
            resamples, cost ratio, sensitivity/latency sample counts,
            whether the sensitivity grid ran) -- separate from the corpus
            digest because it governs how the corpus was evaluated, not
            what data was generated.
        seeds: Every named seed this run's determinism depends on, beyond
            the corpus's own base `seed` above (per-attack-class offsets,
            the Layer 3 model's own `random_state`, and so on).
        git_commit: The working tree's HEAD commit hash at run time, or
            `"unknown"` if `git` was unavailable.
        working_tree_dirty: True if uncommitted changes were present at run
            time. A manifest built against a dirty tree is not reproducible
            from `git_commit` alone, and this field says so honestly rather
            than implying an exactness the run did not have.
        dependency_lock_hash: SHA-256 of `requirements-lock.txt`'s raw bytes
            at run time.
        generated_at: When this manifest was built.
        metrics: The run's own JSON-safe result dict (whatever
            `eval/report_json.py` or an equivalent produced), embedded in
            full -- a manifest is a self-contained record of what a given
            commit, config, and seed actually produced, not a pointer to a
            report that could itself go missing or drift.
    """

    run_name: str
    n_legitimate: int
    seed: int
    attack_base_rate: float
    corpus_params_digest: str
    run_config_hash: str
    seeds: dict[str, int]
    git_commit: str
    working_tree_dirty: bool
    dependency_lock_hash: str
    generated_at: datetime
    metrics: dict[str, object]


def manifest_to_json_dict(manifest: RunManifest) -> dict[str, object]:
    """Renders a `RunManifest` as a JSON-safe dict.

    Args:
        manifest: The manifest to render.

    Returns:
        A dict safe to pass to `json.dumps`.
    """
    return {
        "run_name": manifest.run_name,
        "n_legitimate": manifest.n_legitimate,
        "seed": manifest.seed,
        "attack_base_rate": manifest.attack_base_rate,
        "corpus_params_digest": manifest.corpus_params_digest,
        "run_config_hash": manifest.run_config_hash,
        "seeds": dict(manifest.seeds),
        "git_commit": manifest.git_commit,
        "working_tree_dirty": manifest.working_tree_dirty,
        "dependency_lock_hash": manifest.dependency_lock_hash,
        "generated_at": manifest.generated_at.isoformat(),
        "metrics": manifest.metrics,
    }


def manifest_from_json_dict(data: dict[str, object]) -> RunManifest:
    """Reconstructs a `RunManifest` from a JSON-decoded dict.

    Args:
        data: A dict previously produced by `manifest_to_json_dict`.

    Returns:
        The reconstructed manifest.
    """
    return RunManifest(
        run_name=str(data["run_name"]),
        n_legitimate=int(cast(int, data["n_legitimate"])),
        seed=int(cast(int, data["seed"])),
        attack_base_rate=float(cast(float, data["attack_base_rate"])),
        corpus_params_digest=str(data["corpus_params_digest"]),
        run_config_hash=str(data["run_config_hash"]),
        seeds=dict(cast(dict[str, int], data["seeds"])),
        git_commit=str(data["git_commit"]),
        working_tree_dirty=bool(data["working_tree_dirty"]),
        dependency_lock_hash=str(data["dependency_lock_hash"]),
        generated_at=datetime.fromisoformat(str(data["generated_at"])),
        metrics=dict(cast(dict[str, object], data["metrics"])),
    )


def manifest_hash(manifest: RunManifest) -> str:
    """Hashes a manifest's full content, including its embedded metrics.

    This is the value a README headline number cites and
    `manifest.verify.verify_manifest` (together with a rerun) is checked
    against -- computed the same way `common/hash_chain.py` hashes a
    chained log entry's own record, so a manifest's identity is stable
    under the same canonicalization rules as everything else this project
    hash-chains.

    Args:
        manifest: The manifest to hash.

    Returns:
        A hex SHA-256 digest over the manifest's canonical JSON form.
    """
    return hashlib.sha256(canonical_bytes(manifest_to_json_dict(manifest))).hexdigest()
