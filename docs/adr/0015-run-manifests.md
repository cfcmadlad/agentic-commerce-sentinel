# ADR 0015: Run manifests and reproducibility attestation

## Status

Accepted. Built, tested, and run for real against the project's own headline evaluation.

## Context

Every number in [README §7](../../README.md) traces back to a command a reader can rerun (`run_full_eval.py --n-legitimate 20000 --seed 42`), but nothing before this milestone recorded, as a single artifact, *exactly* what a given reported number depended on: which git commit, which dependency versions, which seeds, which corpus, which run-level tunables. A reviewer could rerun the command and get the same numbers, but had no single file to point at and say "this is the receipt for that specific claim." This milestone builds that receipt.

## Design

### One self-contained record, not a pointer

`manifest.schema.RunManifest` embeds the run's full metrics dict (whatever `eval/report_json.py` or an equivalent already produces) rather than referencing it by path. A manifest that only *pointed* at a metrics file could go stale the moment that file was regenerated; embedding means the manifest is the complete, standalone claim -- "commit X, corpus Y, seeds Z, produced exactly these numbers" -- with nothing else to go missing or drift out from under it later.

### Reusing what already exists, not re-deriving it

`corpus_params_digest` is `EvaluationCorpus.params_digest` itself, taken directly off the corpus object a run already built -- not recomputed. `run_config_hash` and the dependency-lock hash both go through `generator.config.digest_payload`, the same canonicalization (`json.dumps(sort_keys=True, default=str)` then SHA-256) `GeneratorConfig`/`AttackConfig` already use for their own digests, so a manifest's hashes are computed the same way every other parameter digest in this project already is. The manifest's own content hash (`manifest.schema.manifest_hash`) reuses `common/hash_chain.py::canonical_bytes` for the same reason. `manifest/log.py` is a thin, typed wrapper over `common/hash_chain.py::HashChainedLog` -- the third log built on that shared module (after `escalation/log.py`), matching its own stated purpose.

### Seeds are named and enumerated, not implied

A corpus's determinism actually depends on four numbers, not one: the base `seed`, and three fixed per-attack-class offsets (`SEED_OFFSET_REPLAY`/`SEED_OFFSET_SCOPE`/`SEED_OFFSET_IMPERSONATION`, `generator/attacks/corpus.py`) added to it. A fifth, Layer 3's own `random_state` (`eval/pipeline.py::DEFAULT_RANDOM_STATE`), and a sixth, the bootstrap's own seed, govern the rest of the pipeline. `RunManifest.seeds` names all of these explicitly rather than folding them silently into `corpus_params_digest`, so a reviewer reading the manifest JSON can see every number determinism depends on without reading the generator's source to find the offset constants.

### Verification checks structure, not a full rerun

`manifest.verify.verify_manifest` recomputes three cheap things against the current working tree -- the git commit, the dependency-lock hash, and `combined_params_digest(DEFAULT_GENERATOR_CONFIG, DEFAULT_ATTACK_CONFIG)` -- and reports exactly which no longer match. It deliberately does not rebuild the corpus or refit the model: that is a full rerun (minutes, per `run_full_eval.py`'s own docstring), a different and far more expensive operation than "has the code or environment drifted since this manifest was built." The `default_corpus_params_match` check is honest about its own limit: it is only meaningful because every current entry point evaluates `DEFAULT_GENERATOR_CONFIG`/`DEFAULT_ATTACK_CONFIG` with no override; a hypothetical future custom-config run would need its actual config recorded, not just a digest, to check this precisely.

### `run_full_eval.py` builds and logs one on every run

`--manifest-out PATH` writes a standalone manifest JSON (mirroring the existing `--json-out`); by default every run also appends to a hash-chained `eval_manifests.jsonl` (`--no-manifest-log` skips this, `--manifest-log PATH` redirects it). `run_verify_manifest.py` reads a manifest either standalone or by content hash out of the chained log -- the log-lookup path verifies the log's own chain integrity first, since a manifest read out of a tampered log is not trustworthy regardless of what it claims.

## Reproducibility, actually checked

Per the brief's own instruction, this was verified for real rather than assumed: `run_full_eval.py --n-legitimate 3000 --seed 42 --skip-sensitivity` was run twice in the same working tree and the two manifests diffed field by field.

**Finding:** every field matched exactly *except* `metrics.latency.*` (minimum/maximum/mean/percentiles). This is not a bug to fix -- it is the one metric in this report that is, by definition, a real wall-clock measurement of that specific run's own hardware and OS scheduling conditions, not a property of the seed, corpus, or model at all. Forcing it to be bit-identical across runs would mean it had stopped measuring anything real. Every other field -- `n_sessions`, every threshold, every precision/recall figure, every bootstrap-CI point estimate and interval bound for AUC-PR and AUC-ROC across the baseline/ensemble/Layer-3-alone breakdowns, the full calibration curve and Brier score, every SHAP attribution value -- reproduced byte-for-byte across the two independent runs.

**Disposition:** `metrics.latency` is embedded in the manifest (a manifest is a record of what a run actually reported, including its own timing), but it is explicitly *not* part of what this milestone's reproducibility claim covers. A manifest hash therefore never repeats across two runs of the same command, even on the same commit with the same seed -- correctly, since the latency numbers really did differ -- but every claim this project actually reports as a headline number (§7) is confirmed exactly reproducible field-for-field, which is the substantive guarantee this milestone set out to check.

The headline run itself (`--n-legitimate 20000 --seed 42`, matching README §7's own documented reproduction command) was run for real to produce the authoritative manifest this project's actual reported numbers cite -- see the README's own citation of its hash.

## Consequences

**New:** `manifest/` package (`schema.py`, `build.py`, `verify.py`, `log.py`); `run_verify_manifest.py`; `--manifest-out`/`--manifest-log`/`--no-manifest-log` added to `run_full_eval.py`; `eval_manifests.jsonl` gitignored, matching the existing disposition for `service_audit.jsonl`/`service_escalations.jsonl`. 12 new tests (`tests/test_manifest.py`); `ruff`/`mypy` clean.

**What this does not cover:** only `run_full_eval.py` is wired to build a manifest. The other `run_*_eval.py` entry points (`run_gate.py`, `run_ensemble_eval.py`, `run_held_out_eval.py`, `run_containment_eval.py`, `run_collusion_eval.py`) report real, already-tested results but do not yet emit manifests of their own -- `run_full_eval.py` is the one entry point whose numbers are the README's actual headline claims (§7), and extending the same pattern to the others is mechanical repetition of this milestone's design, not a new design question, if ever needed. `verify_manifest` checks structural drift, not full numerical reproducibility -- that guarantee is established once, above, by an actual rerun-and-diff, not re-proven by every `run_verify_manifest.py` invocation.
