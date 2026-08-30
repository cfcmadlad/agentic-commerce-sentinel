"""Verifies a previously built manifest against the current working tree."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from generator.attack_config import DEFAULT_ATTACK_CONFIG, combined_params_digest
from generator.config import DEFAULT_GENERATOR_CONFIG
from manifest.build import REPO_ROOT, dependency_lock_hash, git_commit_state
from manifest.schema import RunManifest

FIELD_GIT_COMMIT = "git_commit"
FIELD_DEPENDENCY_LOCK = "dependency_lock_hash"
FIELD_DEFAULT_CORPUS_PARAMS = "corpus_params_digest"


@dataclass(frozen=True)
class ManifestVerificationResult:
    """Which of a manifest's recorded inputs still match the current working tree.

    Attributes:
        git_commit_matches: True if the manifest's recorded commit equals
            the working tree's current HEAD.
        current_git_commit: The working tree's actual current HEAD commit,
            for display regardless of whether it matches.
        dependency_lock_matches: True if `requirements-lock.txt`'s current
            hash equals the one recorded.
        default_corpus_params_match: True if `combined_params_digest`,
            recomputed from the *current* code's
            `DEFAULT_GENERATOR_CONFIG`/`DEFAULT_ATTACK_CONFIG`, still equals
            the manifest's recorded `corpus_params_digest`. Meaningful only
            because every current entry point evaluates the defaults with
            no override; a manifest from a hypothetical future
            custom-config run would need the actual config recorded to
            check this precisely, not just its digest.
        mismatched_fields: Names of every field above that did not match,
            for a caller that wants one flat list rather than three
            booleans.
    """

    git_commit_matches: bool
    current_git_commit: str
    dependency_lock_matches: bool
    default_corpus_params_match: bool
    mismatched_fields: tuple[str, ...]


def verify_manifest(manifest: RunManifest, repo_root: Path = REPO_ROOT) -> ManifestVerificationResult:
    """Recomputes each of a manifest's recorded inputs against the current working tree.

    Does not re-run the evaluation itself -- that is a separate, far more
    expensive operation (regenerating the corpus and refitting Layer 3).
    This checks only the cheap, structural inputs a manifest recorded:
    has the code, the dependency lock, or the default generator/attack
    parameters drifted since this manifest was built.

    Args:
        manifest: The manifest to check.
        repo_root: Repository root to check against. Overridable for tests.

    Returns:
        Which inputs still match and which have drifted.
    """
    current_commit, _ = git_commit_state(repo_root)
    current_lock_hash = dependency_lock_hash(repo_root)
    current_default_digest = combined_params_digest(DEFAULT_GENERATOR_CONFIG, DEFAULT_ATTACK_CONFIG)

    git_commit_matches = current_commit == manifest.git_commit
    dependency_lock_matches = current_lock_hash == manifest.dependency_lock_hash
    default_corpus_params_match = current_default_digest == manifest.corpus_params_digest

    mismatched = []
    if not git_commit_matches:
        mismatched.append(FIELD_GIT_COMMIT)
    if not dependency_lock_matches:
        mismatched.append(FIELD_DEPENDENCY_LOCK)
    if not default_corpus_params_match:
        mismatched.append(FIELD_DEFAULT_CORPUS_PARAMS)

    return ManifestVerificationResult(
        git_commit_matches=git_commit_matches,
        current_git_commit=current_commit,
        dependency_lock_matches=dependency_lock_matches,
        default_corpus_params_match=default_corpus_params_match,
        mismatched_fields=tuple(mismatched),
    )
