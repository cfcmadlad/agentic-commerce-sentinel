"""Loads a policy document from YAML text or a file, with precise validation errors.

Strict by construction: `PolicyDocument`'s own `extra="forbid"` config
means an unrecognized key anywhere in the document -- a typo'd field name,
a stray top-level key -- fails to load with pydantic's own named-field
error rather than being silently ignored.
"""

from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from policy.schema import PolicyDocument

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "default_policy.yaml"


class PolicyLoadError(ValueError):
    """Raised when a policy document fails to parse or validate."""


def load_policy_text(text: str) -> PolicyDocument:
    """Parses and validates a policy document from YAML text.

    Args:
        text: The YAML document text.

    Returns:
        The validated document.

    Raises:
        PolicyLoadError: If `text` is not valid YAML, is not a mapping at
            the top level, or fails schema validation -- wraps the
            underlying YAML or pydantic error with its precise message
            rather than letting either exception type leak out directly.
    """
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise PolicyLoadError(f"invalid YAML: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyLoadError("policy document must be a YAML mapping at the top level")
    try:
        return PolicyDocument.model_validate(raw)
    except ValidationError as error:
        raise PolicyLoadError(f"policy document failed validation:\n{error}") from error


def load_policy_file(path: Path) -> PolicyDocument:
    """Parses and validates a policy document from a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        The validated document.

    Raises:
        PolicyLoadError: See `load_policy_text`.
    """
    return load_policy_text(path.read_text(encoding="utf-8"))


def load_default_policy() -> PolicyDocument:
    """Loads this project's own declarative re-encoding of Layer 2's rules.

    Returns:
        The validated default policy document.
    """
    return load_policy_file(DEFAULT_POLICY_PATH)
