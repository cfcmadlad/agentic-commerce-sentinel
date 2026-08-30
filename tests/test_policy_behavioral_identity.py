"""Proves the compiled default policy reproduces `enforce_scope`'s real decisions.

Per the brief: "prove behavioral identity with the existing hard-coded
rules via a test against the full existing corpus." Runs the same
generator-built corpus `run_gate.py` reports numbers against and checks,
for every session, that the compiled policy's fired reasons are
byte-for-byte identical (same reasons, same order) to `detect.scope
.enforce_scope`'s real ones -- not just "both agree on blocked/allowed,"
which would hide a policy that fires the wrong specific rule for the right
final verdict.
"""

from __future__ import annotations

from detect.scope import ScopeViolationReason, enforce_scope
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus
from policy.compiler import compile_policy
from policy.loader import load_default_policy

# Matches run_gate.py's own default scale -- large enough to exercise every
# scope rule at real generator proportions, small enough to run in seconds.
N_LEGITIMATE = 5000
SEED = 42


def test_compiled_default_policy_matches_enforce_scope_over_the_full_corpus() -> None:
    """Every session's compiled-policy reasons must match `enforce_scope`'s real reasons exactly."""
    corpus = build_evaluation_corpus(N_LEGITIMATE, seed=SEED, attack_base_rate=DEFAULT_ATTACK_BASE_RATE)
    compiled = compile_policy(load_default_policy())

    checked = 0
    mismatches: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    for labeled in corpus.labeled_sessions:
        trace = labeled.trace
        signed = corpus.resolver.resolve(trace.session_id)
        real = enforce_scope(trace, signed)

        if signed is None:
            # NO_MANDATE_PRESENTED is a precondition outside the compiled
            # rule set entirely -- see policy/default_policy.yaml's own
            # module-level comment on why.
            assert real.reasons == (ScopeViolationReason.NO_MANDATE_PRESENTED,)
            continue

        policy_reasons = compiled.evaluate(trace, signed)
        real_reasons = tuple(r.value for r in real.reasons)
        checked += 1
        if policy_reasons != real_reasons:
            mismatches.append((str(trace.session_id), real_reasons, policy_reasons))

    assert checked > 1000, f"expected a substantial corpus, only checked {checked} sessions"
    assert not mismatches, f"{len(mismatches)} session(s) disagreed with the real enforce_scope, e.g. {mismatches[:5]}"
