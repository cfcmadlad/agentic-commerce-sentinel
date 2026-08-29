"""Shared, process-lifetime state for the API service.

Fits the Layer 3 model once, at startup, against the exact same corpus
parameters `run_full_eval.py` reports numbers against -- the running
service scores every request with the identical model and threshold this
project's own evaluation already measured, not a separately-tuned copy.
This means a cold start takes as long as fitting that corpus does (tens of
seconds); that tradeoff is accepted deliberately, in favor of never needing
a second, undocumented model-persistence path (a pickled artifact that
could silently drift from what the evaluation harness reports) -- see the
module docstring on why this project regenerates from a seed rather than
loading a serialized model anywhere else.

Every mutable piece of state here (the mandate ledger, the feature
extractor's per-agent/per-mandate history, the audit log) is a single
shared instance for the process's lifetime. That is what "causal,
session-ordered" and "stateful ledger" mean for a live service: unlike the
offline evaluation harness, which is handed a whole corpus in chronological
order up front, this service only has the order requests actually arrive
in. A request timestamped earlier than one already processed will still be
accepted, but its causal ("hours since X") features will be computed
against history that already includes later events -- a real limitation of
serving requests in arrival order rather than event order, stated here
rather than silently assumed away.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from detect.behavioral import BehavioralModel
from detect.calibration import DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO
from eval.pipeline import fit_pipeline
from features.session import FeatureExtractor
from generator.attack_config import DEFAULT_ATTACK_BASE_RATE
from generator.attacks.corpus import build_evaluation_corpus
from mandate.signing import key_id_for_public_key, keypair_from_seed_bytes
from mandate.verification import AgentKeyRegistry, MandateLedger
from reasoning.audit_log import AuditLog
from reasoning.narrate import DEFAULT_MODEL, GroqNarrationClient, NarrationClient

logger = logging.getLogger(__name__)

# Matches run_full_eval.py's defaults exactly, so this service's model is
# the one this project's own evaluation already reports on, not a second,
# separately-parameterized fit.
FITTING_N_LEGITIMATE = 20000
FITTING_SEED = 42

N_DEMO_AGENTS = 3
DEFAULT_AUDIT_LOG_PATH = Path("service_audit.jsonl")


@dataclass(frozen=True)
class DemoAgent:
    """A deterministically keyed agent, registered at startup for testing.

    Attributes:
        agent_id: The agent identifier.
        key_id: The registered public key's fingerprint.
        private_key: The matching private key, so a caller can sign a
            mandate and exercise the service end to end. Deterministically
            derived from a public, fixed seed string -- not a secret,
            since it can be re-derived by anyone who reads this module.
            Exposing it is safe specifically because it never protects
            anything real: every session in this project is synthetic,
            defense-only, and there is no real payment or user data
            anywhere behind it.
    """

    agent_id: str
    key_id: str
    private_key: Ed25519PrivateKey


@dataclass
class AppState:
    """Everything a request handler needs, built once at service startup.

    Attributes:
        registry: Public keys trusted to sign for each registered agent.
        ledger: Per-mandate usage counts, consumed only on allowed sessions.
        extractor: Causal feature extractor, shared so history accumulates
            across requests for the process's lifetime.
        model: The fitted Layer 3 classifier.
        threshold: The calibrated operating threshold.
        audit_log: The append-only audit record store.
        narration_client: The Layer 4 narration client, or None if
            `GROQ_API_KEY` was not set when the service started --
            narration is best-effort, never a precondition for a decision.
        narration_model: Model identifier recorded on narrations produced
            with `narration_client`.
        demo_agents: Agents registered at startup for exploratory testing.
    """

    registry: AgentKeyRegistry
    ledger: MandateLedger
    extractor: FeatureExtractor
    model: BehavioralModel
    threshold: float
    audit_log: AuditLog
    narration_client: NarrationClient | None
    narration_model: str
    demo_agents: tuple[DemoAgent, ...]


def _register_demo_agents(registry: AgentKeyRegistry) -> tuple[DemoAgent, ...]:
    """Registers a handful of deterministically keyed agents for testing.

    Args:
        registry: The registry to register keys into.

    Returns:
        The registered demo agents, private keys included -- see
        `DemoAgent`'s docstring for why that is safe here.
    """
    agents = []
    for i in range(N_DEMO_AGENTS):
        seed_bytes = hashlib.sha256(f"sentinel-demo-agent-{i}".encode("utf-8")).digest()
        private_key, public_key = keypair_from_seed_bytes(seed_bytes)
        agent_id = f"demo-agent-{i:02d}"
        key_id = key_id_for_public_key(public_key)
        registry.register(agent_id, key_id, public_key)
        agents.append(DemoAgent(agent_id=agent_id, key_id=key_id, private_key=private_key))
        logger.info("registered demo agent %s (%s)", agent_id, key_id)
    return tuple(agents)


def build_app_state(audit_log_path: Path = DEFAULT_AUDIT_LOG_PATH) -> AppState:
    """Fits the pipeline and assembles the shared state a running service needs.

    Args:
        audit_log_path: Where the append-only audit log is read from and
            appended to.

    Returns:
        The assembled application state.
    """
    logger.info(
        "fitting pipeline (n_legitimate=%d, seed=%d) -- this takes a while", FITTING_N_LEGITIMATE, FITTING_SEED
    )
    corpus = build_evaluation_corpus(
        FITTING_N_LEGITIMATE, seed=FITTING_SEED, attack_base_rate=DEFAULT_ATTACK_BASE_RATE
    )
    fit = fit_pipeline(corpus)
    logger.info(
        "pipeline fit complete: threshold=%.4f cost_ratio=%.1f",
        fit.threshold,
        DEFAULT_FALSE_NEGATIVE_TO_FALSE_POSITIVE_COST_RATIO,
    )

    registry = AgentKeyRegistry()
    demo_agents = _register_demo_agents(registry)

    narration_client: NarrationClient | None = None
    if os.environ.get("GROQ_API_KEY"):
        from groq import Groq

        narration_client = GroqNarrationClient(client=Groq())
        logger.info("narration enabled via Groq (%s)", DEFAULT_MODEL)
    else:
        logger.warning("GROQ_API_KEY not set: Layer 4 narration is disabled for this service instance")

    return AppState(
        registry=registry,
        ledger=MandateLedger(),
        extractor=FeatureExtractor(),
        model=fit.model,
        threshold=fit.threshold,
        audit_log=AuditLog(audit_log_path),
        narration_client=narration_client,
        narration_model=DEFAULT_MODEL,
        demo_agents=demo_agents,
    )
