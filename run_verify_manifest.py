"""Command-line entry point for verifying a run manifest against the current working tree.

Checks a manifest's recorded git commit, dependency-lock hash, and default
generator/attack parameter digest against what the current working tree
actually has, and reports exactly which inputs differ, if any. Does not
re-run the evaluation itself -- see `manifest/verify.py`'s module docstring
for why that is a separate, far more expensive operation.

Reads a manifest from one of two places:

    python run_verify_manifest.py --manifest-path report.manifest.json
    python run_verify_manifest.py --manifest-log eval_manifests.jsonl --manifest-hash <hex>

The log form also verifies the log's own hash chain first (a manifest
found inside a tampered log is not trustworthy regardless of what it says).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from manifest.build import DEFAULT_MANIFEST_LOG_PATH, REPO_ROOT
from manifest.log import ManifestLog, verify_chain
from manifest.schema import RunManifest, manifest_from_json_dict, manifest_hash
from manifest.verify import verify_manifest


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments.

    Args:
        argv: Argument list, excluding the program name.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--manifest-path", type=Path, default=None,
        help="a standalone manifest JSON file, as written by run_full_eval.py --manifest-out",
    )
    source.add_argument(
        "--manifest-hash", type=str, default=None,
        help="the content hash of one manifest to look up inside --manifest-log",
    )
    parser.add_argument(
        "--manifest-log", type=Path, default=DEFAULT_MANIFEST_LOG_PATH,
        help=f"hash-chained manifest log to look up --manifest-hash in (default: {DEFAULT_MANIFEST_LOG_PATH})",
    )
    parser.add_argument(
        "--repo-root", type=Path, default=REPO_ROOT,
        help="repository root to verify the manifest's recorded inputs against",
    )
    return parser.parse_args(argv)


def _load_from_path(path: Path) -> RunManifest | None:
    """Loads a standalone manifest JSON file.

    Args:
        path: Path to the manifest file.

    Returns:
        The loaded manifest, or None if the file does not exist.
    """
    if not path.exists():
        return None
    return manifest_from_json_dict(json.loads(path.read_text(encoding="utf-8")))


def _load_from_log(log_path: Path, target_hash: str) -> tuple[RunManifest | None, str | None]:
    """Loads one manifest by content hash from a hash-chained log.

    Args:
        log_path: Path to the manifest log.
        target_hash: The content hash (`manifest.schema.manifest_hash`) to look up.

    Returns:
        `(manifest, error)`: exactly one of the two is None. `error` is a
        human-readable reason no manifest was returned -- the log is
        missing, its chain is broken, or no entry matches the hash.
    """
    if not log_path.exists():
        return None, f"no manifest log at {log_path}"
    log = ManifestLog(log_path)
    chain_result = verify_chain(log)
    if not chain_result.intact:
        return None, (
            f"manifest log chain broken at index {chain_result.first_break_index} "
            f"of {chain_result.total_records}: {chain_result.broken_field} mismatch"
        )
    matches = [m for m in log.read_all() if manifest_hash(m) == target_hash]
    if not matches:
        return None, f"no manifest with hash {target_hash} found in {log_path}"
    return matches[-1], None


def main(argv: list[str] | None = None) -> int:
    """Loads a manifest and verifies its recorded inputs against the current working tree.

    Args:
        argv: Argument list, excluding the program name. Defaults to sys.argv.

    Returns:
        A process exit code: 0 if every recorded input still matches, 1 if
        the manifest could not be loaded or at least one input has drifted.
    """
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if args.manifest_path is not None:
        manifest = _load_from_path(args.manifest_path)
        if manifest is None:
            print(f"no manifest at {args.manifest_path}", file=sys.stderr)
            return 1
    else:
        manifest, error = _load_from_log(args.manifest_log, args.manifest_hash)
        if manifest is None:
            print(error, file=sys.stderr)
            return 1

    print(
        f"manifest: {manifest.run_name}, n_legitimate={manifest.n_legitimate}, seed={manifest.seed}, "
        f"generated_at={manifest.generated_at.isoformat()}"
    )
    print(
        f"recorded git commit: {manifest.git_commit}"
        f"{' (working tree was dirty at run time)' if manifest.working_tree_dirty else ''}"
    )

    result = verify_manifest(manifest, repo_root=args.repo_root)
    print(f"current git commit:  {result.current_git_commit}")

    if not result.mismatched_fields:
        print("all recorded inputs match the current working tree")
        return 0

    print(f"MISMATCH in: {', '.join(result.mismatched_fields)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
