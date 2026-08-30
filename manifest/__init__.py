"""Run manifests: reproducibility attestation for evaluation runs.

A `RunManifest` (`manifest/schema.py`) records everything a reported result
depends on -- the exact corpus, the run's own tunables, every seed, the
git commit and dependency-lock state, and the resulting metrics -- as one
self-contained, JSON-safe record. `manifest/build.py` builds one from an
evaluation run's concrete inputs; `manifest/log.py` appends it, hash-chained,
to an append-only log via `common/hash_chain.py`; `manifest/verify.py`
recomputes each recorded input against the current working tree and reports
which have drifted. See `docs/adr/0015-run-manifests.md`.
"""

from __future__ import annotations
