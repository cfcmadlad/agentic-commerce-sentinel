"""Device/IP fingerprint synthesis.

See `generator/collusion/__init__.py` for why a fingerprint is a
`session_id`-keyed auxiliary mapping rather than a `SessionTrace` field.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

# Bounds for the synthetic octets a fingerprint's IP-shaped identifier is
# built from. The first octet excludes 0 so no fingerprint renders as an
# all-zero address, which would look like a construction bug rather than a
# plausible synthetic value.
_IP_FIRST_OCTET_LOW = 1
_IP_OCTET_HIGH = 256
_DEVICE_ID_BITS = 32


@dataclass(frozen=True)
class DeviceFingerprint:
    """A synthetic device/network identity a session was observed from.

    Attributes:
        device_id: Opaque device identifier.
        ip_address: An IP-address-shaped identifier. Synthetic and used only
            for grouping sessions that share it -- never validated as, or
            intended to resemble, a real routable address.
    """

    device_id: str
    ip_address: str


def generate_fingerprint(rng: np.random.Generator) -> DeviceFingerprint:
    """Draws a fresh, independent device fingerprint.

    Args:
        rng: Seeded random generator.

    Returns:
        A new fingerprint, vanishingly unlikely to collide with another
        independently drawn one -- distinct, unrelated sessions are expected
        to each get their own.
    """
    device_id = f"device-{int(rng.integers(0, 2**_DEVICE_ID_BITS)):08x}"
    octets = [
        int(rng.integers(_IP_FIRST_OCTET_LOW, _IP_OCTET_HIGH)),
        int(rng.integers(0, _IP_OCTET_HIGH)),
        int(rng.integers(0, _IP_OCTET_HIGH)),
        int(rng.integers(_IP_FIRST_OCTET_LOW, _IP_OCTET_HIGH)),
    ]
    ip_address = ".".join(str(octet) for octet in octets)
    return DeviceFingerprint(device_id=device_id, ip_address=ip_address)
