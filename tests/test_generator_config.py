"""Tests for the injectable generator and attack parameter sets.

The property these tests exist to protect is narrow and load-bearing: the
default config must reproduce the exact corpus every reported headline number
was measured against. A refactor that quietly shifts one random draw would
leave every metric in the repository unreproducible while every other test
still passed, so the drift check pins a digest rather than a summary statistic.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal

import pytest

from generator.attack_config import (
    DEFAULT_ATTACK_CONFIG,
    RULES_INVISIBLE_VARIANTS,
    VARIANT_BEHAVIORAL_ONLY,
    VARIANT_RAPID_REUSE,
    AttackConfig,
    combined_params_digest,
)
from generator.attacks.corpus import build_evaluation_corpus
from generator.config import (
    DEFAULT_GENERATOR_CONFIG,
    CategoryConfig,
    GeneratorConfig,
)
from generator.legitimate import generate_legitimate_sessions

# Digest of the 2,000-session legitimate corpus at seed 42 under the default
# parameter set, captured from the generator as it stood when the ensemble
# evaluation's numbers were first measured. A change here means generated data has moved and every
# previously reported metric needs re-deriving; it is not a value to update
# casually to make a test pass.
EXPECTED_LEGITIMATE_DIGEST = "75b9e322e87cb5cb827b608a4509754c14937c4c2b2139f2a4ba71cd16a3e212"

_DRIFT_CHECK_SESSIONS = 2000
_DRIFT_CHECK_SEED = 42


def _corpus_digest(n_sessions: int, seed: int, config: GeneratorConfig) -> str:
    """Hashes every field of every generated session into one identifier.

    Args:
        n_sessions: Number of legitimate sessions to generate.
        seed: Generator seed.
        config: Parameter set to generate under.

    Returns:
        A hex SHA-256 digest over the full generated corpus.
    """
    output = generate_legitimate_sessions(n_sessions, seed=seed, config=config)
    digest = hashlib.sha256()
    for labeled in output.labeled_sessions:
        trace = labeled.trace
        digest.update(
            f"{trace.session_id}|{trace.agent_id}|{trace.user_id}|{trace.mandate_id}|"
            f"{trace.merchant_id}|{trace.merchant_category}|{trace.item_category}|"
            f"{trace.amount}|{trace.currency}|{trace.started_at.isoformat()}|"
            f"{trace.completed_at.isoformat()}|"
            f"{[(e.event_type.value, e.timestamp.isoformat()) for e in trace.events]}".encode()
        )
    return digest.hexdigest()


def test_default_config_reproduces_the_measured_corpus() -> None:
    """The default parameter set must generate byte-identical data over time."""
    assert (
        _corpus_digest(_DRIFT_CHECK_SESSIONS, _DRIFT_CHECK_SEED, DEFAULT_GENERATOR_CONFIG)
        == EXPECTED_LEGITIMATE_DIGEST
    )


def test_explicit_default_instance_matches_the_module_default() -> None:
    """Constructing a fresh config must equal the shared default instance."""
    assert GeneratorConfig() == DEFAULT_GENERATOR_CONFIG
    assert AttackConfig() == DEFAULT_ATTACK_CONFIG


def test_perturbed_config_changes_the_generated_corpus() -> None:
    """A parameter change must actually move the data, not be silently ignored.

    Without this, a config field could be threaded into a signature but never
    read, and the sensitivity analysis would report reassuring stability that
    reflected nothing but an unused argument.
    """
    faster = GeneratorConfig(min_event_gap_seconds=1, max_event_gap_seconds=3)
    assert _corpus_digest(500, 42, faster) != _corpus_digest(500, 42, DEFAULT_GENERATOR_CONFIG)


def test_digest_distinguishes_parameter_sets() -> None:
    """Two different parameter sets must not share a digest."""
    baseline = DEFAULT_GENERATOR_CONFIG.params_digest()
    perturbed = GeneratorConfig(recurring_mandate_probability=0.5).params_digest()
    assert baseline != perturbed
    assert GeneratorConfig().params_digest() == baseline


def test_combined_digest_reacts_to_either_half() -> None:
    """A grid point varying only attack parameters must still be identifiable."""
    baseline = combined_params_digest(DEFAULT_GENERATOR_CONFIG, DEFAULT_ATTACK_CONFIG)
    attack_only = combined_params_digest(
        DEFAULT_GENERATOR_CONFIG, AttackConfig(skip_browse_probability=0.5)
    )
    generator_only = combined_params_digest(
        GeneratorConfig(agent_pool_size=50), DEFAULT_ATTACK_CONFIG
    )
    assert len({baseline, attack_only, generator_only}) == 3


def test_corpus_carries_the_config_that_produced_it() -> None:
    """The corpus must record its own parameters for the sensitivity report."""
    attack_config = AttackConfig(skip_browse_probability=0.4)
    corpus = build_evaluation_corpus(600, seed=7, attack_config=attack_config)

    assert corpus.attack_config == attack_config
    assert corpus.generator_config == DEFAULT_GENERATOR_CONFIG
    assert corpus.params_digest == combined_params_digest(DEFAULT_GENERATOR_CONFIG, attack_config)


def test_attack_base_rate_argument_overrides_the_config_field() -> None:
    """An explicit rate must win over the config's own default."""
    corpus = build_evaluation_corpus(600, seed=7, attack_base_rate=0.10)
    assert corpus.attack_base_rate == pytest.approx(0.10, abs=0.01)


def test_variant_mix_weights_reach_the_generators() -> None:
    """Zeroing a variant's weight must remove it from generated traffic.

    This is the lever the sensitivity grid pulls on, so it has to demonstrably
    work rather than be assumed from the config being passed along.
    """
    no_rapid_reuse = AttackConfig(
        replay_mix_expired=0.5,
        replay_mix_budget_exhausted=0.5,
        replay_mix_rapid_reuse=0.0,
    )
    corpus = build_evaluation_corpus(3000, seed=11, attack_config=no_rapid_reuse)
    assert VARIANT_RAPID_REUSE not in set(corpus.variant_by_session.values())


def test_rules_invisible_variants_are_the_two_documented_ones() -> None:
    """The set the evaluation reports separately must match the taxonomy."""
    assert RULES_INVISIBLE_VARIANTS == {VARIANT_RAPID_REUSE, VARIANT_BEHAVIORAL_ONLY}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"categories": ()}, "categories must be non-empty"),
        ({"min_event_gap_seconds": 60, "max_event_gap_seconds": 5}, "precedes lower bound"),
        ({"recurring_mandate_probability": 1.5}, "must be in \\[0, 1\\]"),
        ({"agent_pool_size": 0}, "must be positive"),
    ],
)
def test_generator_config_rejects_invalid_parameters(
    kwargs: dict[str, object], message: str
) -> None:
    """Invalid parameters must fail at construction, not deep inside sampling."""
    with pytest.raises(ValueError, match=message):
        GeneratorConfig(**kwargs)  # type: ignore[arg-type]


def test_generator_config_rejects_a_non_positive_category_median() -> None:
    """A zero median would make the log-normal amount draw undefined."""
    broken = CategoryConfig(
        name="broken",
        gmv_weight=1.0,
        amount_median=Decimal("0.00"),
        amount_sigma=0.5,
        item_categories=("thing",),
        merchant_ids=("merchant",),
    )
    with pytest.raises(ValueError, match="amount_median must be positive"):
        GeneratorConfig(categories=(broken,))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"attack_base_rate": 0.0}, "must be in \\(0, 1\\)"),
        ({"skip_browse_probability": -0.1}, "must be in \\[0, 1\\]"),
        (
            {
                "replay_mix_expired": 0.0,
                "replay_mix_budget_exhausted": 0.0,
                "replay_mix_rapid_reuse": 0.0,
            },
            "must sum to a positive value",
        ),
        ({"replay_mix_expired": -1.0}, "must be non-negative"),
        ({"min_ceiling_overshoot": Decimal("0.99")}, "must exceed 1"),
    ],
)
def test_attack_config_rejects_invalid_parameters(
    kwargs: dict[str, object], message: str
) -> None:
    """Invalid attack parameters must fail at construction."""
    with pytest.raises(ValueError, match=message):
        AttackConfig(**kwargs)  # type: ignore[arg-type]
