"""Synthetic generation of coordinated multi-agent collusion patterns.

Every session this package produces is, individually, a completely ordinary,
correctly scoped, properly signed transaction -- Layers 1, 2, and 2.5 have no
reason to object to any single one of them. The pattern this package plants
is only visible across sessions and across agents: a device or network
fingerprint shared between "distinct" agent identities, several individually
small transactions from different agents converging on one counterparty
inside a tight window, or a small cluster of agents transacting with
overlapping counterparties in a coordinated window. `collusion/` is the
detection layer built to see exactly that.

A device/IP fingerprint is deliberately never added to `common.schema.
SessionTrace` -- doing so would touch the shared schema every existing
frozen corpus and detector consumes. It is out-of-band metadata instead, a
`session_id -> DeviceFingerprint` mapping produced and consumed only by this
milestone's own generator and detection code, the same way a presented
mandate is attached to a session by ID rather than embedded in it.

Defense-only, matching every other generator package in this project:
everything here produces synthetic sessions that violate no real system's
schema and are only ever valid inside this repository's own synthetic key
registry. Nothing here is a technique against a real payment system.
"""

from __future__ import annotations
