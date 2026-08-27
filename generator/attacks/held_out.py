"""Builds the held-out mandate-chaining evaluation corpus.

This is the only place `AttackClass.MANDATE_CHAINING` is ever assembled into
an `EvaluationCorpus`. That guarantee is a file-import boundary, not just a
convention: `generator/attacks/corpus.py` (the training/tuning corpus
builder) does not import this module, `generate_mandate_chaining_attacks`,
or anything from it, so `build_evaluation_corpus` cannot produce a chaining
session even under an accidental future parameter change --
`tests/test_corpus_and_gate.py` and `tests/test_milestone_a.py` already pin
that guarantee for the training path, and this module never touches it.

This corpus is evaluated exactly once, against the already-frozen Layers 1-3
pipeline, after Milestones A and B were both committed. See
`docs/adr/0003-held-out-class-evaluation.md` for the result and the standing
constraint against tuning anything -- rules, features, or the model -- in
response to it.
"""

from __future__ import annotations

import logging
from uuid import UUID

from detect.resolution import InMemoryMandateResolver
from generator.attack_config import DEFAULT_ATTACK_CONFIG
from generator.attacks.chaining import generate_mandate_chaining_attacks
from generator.attacks.common import build_world
from generator.attacks.corpus import EvaluationCorpus
from generator.config import DEFAULT_GENERATOR_CONFIG, GeneratorConfig
from generator.legitimate import generate_legitimate_sessions

logger = logging.getLogger(__name__)

# Higher than the three-class training base rate (0.04): five sub-variants
# need enough individual volume for a per-variant recall to mean anything,
# and this corpus is never used for training or threshold calibration, so
# there is no realism requirement pulling it toward a production-like rate.
DEFAULT_HELD_OUT_ATTACK_BASE_RATE = 0.15


def build_held_out_corpus(
    n_legitimate: int,
    seed: int,
    attack_base_rate: float = DEFAULT_HELD_OUT_ATTACK_BASE_RATE,
    generator_config: GeneratorConfig = DEFAULT_GENERATOR_CONFIG,
) -> EvaluationCorpus:
    """Generates legitimate traffic and mandate-chaining attacks together.

    Structurally mirrors `generator.attacks.corpus.build_evaluation_corpus`
    (chronological ordering, mandate resolution, variant tracking) but with a
    single attack source. Reuses the `EvaluationCorpus` type so the existing
    evaluation harness (`RulesOnlyBaseline`, `FeatureExtractor`,
    `eval.pipeline`) can score this corpus without a parallel code path;
    `EvaluationCorpus.attack_config` is populated with
    `DEFAULT_ATTACK_CONFIG` as inert metadata only -- this corpus has no
    variant-mix concept (there is one attack class here, not three), so none
    of that config's fields are read while building it.

    Args:
        n_legitimate: Number of legitimate sessions. Must be positive.
        seed: Corpus seed; the same seed always produces the same corpus. Use
            a seed clearly outside the range used for any training/tuning
            corpus, so this substrate and agent pool are never accidentally
            the same ones a model trained against.
        attack_base_rate: Target attack fraction. Must be in (0, 1).
        generator_config: Legitimate-traffic parameters. Defaults to the
            same parameter set the frozen headline evaluation used.

    Returns:
        The assembled held-out corpus.

    Raises:
        ValueError: If `n_legitimate` is not positive, `attack_base_rate` is
            outside (0, 1), or the resulting attack budget is empty.
    """
    if n_legitimate <= 0:
        raise ValueError(f"n_legitimate must be positive, got {n_legitimate}")
    if not 0.0 < attack_base_rate < 1.0:
        raise ValueError(f"attack_base_rate must be in (0, 1), got {attack_base_rate}")

    n_attacks = round(n_legitimate * attack_base_rate / (1.0 - attack_base_rate))
    if n_attacks < 1:
        raise ValueError(
            f"attack budget rounds to zero attacks for n_legitimate={n_legitimate}, "
            f"attack_base_rate={attack_base_rate}; increase either"
        )

    legitimate = generate_legitimate_sessions(n_legitimate, seed=seed, config=generator_config)
    world = build_world(legitimate)

    attacks = generate_mandate_chaining_attacks(world, n_attacks, seed=seed)

    presented = {}
    for labeled in legitimate.labeled_sessions:
        mandate_id = labeled.trace.mandate_id
        if mandate_id is not None:
            presented[labeled.trace.session_id] = legitimate.signed_mandates[mandate_id]

    variant_by_session: dict[UUID, str] = {}
    for attack in attacks:
        trace = attack.labeled.trace
        variant_by_session[trace.session_id] = attack.variant
        if attack.signed_mandate is not None:
            presented[trace.session_id] = attack.signed_mandate
        elif trace.mandate_id is not None:
            presented[trace.session_id] = legitimate.signed_mandates[trace.mandate_id]

    all_sessions = list(legitimate.labeled_sessions) + [a.labeled for a in attacks]
    all_sessions.sort(key=lambda s: (s.trace.started_at, str(s.trace.session_id)))

    realized_rate = len(attacks) / len(all_sessions)
    logger.info(
        "held-out corpus: %d sessions, %d mandate-chaining attacks, realized base rate %.4f",
        len(all_sessions), len(attacks), realized_rate,
    )

    return EvaluationCorpus(
        labeled_sessions=tuple(all_sessions),
        resolver=InMemoryMandateResolver(presented),
        registry=legitimate.registry,
        variant_by_session=variant_by_session,
        attack_base_rate=realized_rate,
        seed=seed,
        generator_config=generator_config,
        attack_config=DEFAULT_ATTACK_CONFIG,
        params_digest=generator_config.params_digest(),
    )
