"""Seeded-RNG helpers shared by the legitimate and attack generators.

Every generator in this project derives its identifiers here rather than
reimplementing the logic, so that all of them produce byte-identical output
for a given seed. A divergence would surface as a subtle reproducibility bug:
the same seed producing a different dataset on a different machine, which is
precisely the guarantee this project's evaluation rests on.
"""

from __future__ import annotations

from uuid import UUID

import numpy as np

# 16 bytes is the full width of a UUID; 16 bytes of nonce renders as 32 hex
# characters, comfortably above `Mandate.nonce`'s 16-character minimum.
UUID_BYTES = 16
NONCE_BYTES = 16


def rng_uuid(rng: np.random.Generator) -> UUID:
    """Derives a UUID from the seeded generator, instead of `uuid.uuid4`.

    `uuid.uuid4()` reads OS entropy directly and is not reproducible across
    runs regardless of any seed passed elsewhere; every ID in this project's
    generators must route through `rng` for a given seed to reproduce
    byte-identical output.

    Args:
        rng: Seeded random generator.

    Returns:
        A UUID built from 16 random bytes drawn from `rng`.
    """
    return UUID(bytes=rng.bytes(UUID_BYTES))


def rng_nonce(rng: np.random.Generator) -> str:
    """Derives a mandate nonce from the seeded generator.

    Args:
        rng: Seeded random generator.

    Returns:
        A 32-character hex string.
    """
    return rng.bytes(NONCE_BYTES).hex()