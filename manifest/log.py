"""Append-only, hash-chained persistence for `RunManifest`.

Built on `common/hash_chain.py`'s generic primitives rather than
duplicating `reasoning/audit_log.py`'s hash-chain logic a second time --
see that module's own docstring for why. This module owns only the
`RunManifest`-specific JSON mapping and the typed, narrow interface callers
actually use.
"""

from __future__ import annotations

import logging
from pathlib import Path

from common.hash_chain import ChainVerificationResult, HashChainedLog, StoredEntry, verify_hash_chain
from manifest.schema import RunManifest, manifest_from_json_dict, manifest_hash, manifest_to_json_dict

logger = logging.getLogger(__name__)


class ManifestLog:
    """A typed, hash-chained, append-only store of `RunManifest`s.

    Interface stays append-only, matching `reasoning.audit_log.AuditLog`
    and `escalation.log.EscalationLog`: `append`, `read_all`,
    `read_entries`, and `path` only -- no update, delete, or clear method
    exists anywhere on this class.
    """

    def __init__(self, path: Path) -> None:
        """Initializes the log, creating an empty file if none exists.

        Args:
            path: File path to append manifests to and read manifests from.
        """
        self._log = HashChainedLog(path)

    @property
    def path(self) -> Path:
        """Returns the backing file path.

        Returns:
            The path this log reads from and appends to.
        """
        return self._log.path

    def append(self, manifest: RunManifest) -> str:
        """Appends one manifest to the log, chained to whatever precedes it.

        Args:
            manifest: The manifest to append.

        Returns:
            `manifest_hash(manifest)` -- the value a README number cites
            and a later `verify_manifest` call is checked against. Distinct
            from the hash-chain's own `record_hash` (which also covers
            `prev_hash` and would change if the manifest were ever
            re-appended after an earlier log entry) -- this is the
            manifest's own content identity, stable regardless of its
            position in any particular log.
        """
        self._log.append(manifest_to_json_dict(manifest))
        content_hash = manifest_hash(manifest)
        logger.info("appended run manifest %s (%s) to %s", manifest.run_name, content_hash, self._log.path)
        return content_hash

    def read_entries(self) -> tuple[StoredEntry, ...]:
        """Reads every entry currently in the log, in append order.

        Returns:
            All entries, oldest first, each carrying its hash-chain fields.
        """
        return self._log.read_entries()

    def read_all(self) -> tuple[RunManifest, ...]:
        """Reads every manifest currently in the log, in append order.

        Returns:
            All manifests, oldest first.
        """
        return tuple(manifest_from_json_dict(entry.record_dict) for entry in self._log.read_entries())

    def __len__(self) -> int:
        """Returns the number of manifests currently in the log.

        Returns:
            The manifest count.
        """
        return len(self._log)


def verify_chain(log: ManifestLog) -> ChainVerificationResult:
    """Walks a manifest log's hash chain and finds the first tamper point, if any.

    Args:
        log: The log to verify.

    Returns:
        Where (if anywhere) the chain first breaks.
    """
    return verify_hash_chain(log.read_entries())
