"""Graph-based detection of coordinated multi-agent (collusion-ring) abuse.

A detection layer operating across sessions and agents, not within one
session -- structurally distinct from Layer 3 (`detect/behavioral.py`),
which only ever looks at one agent's own history. Nothing here reasons
about a mandate's delegation chain either, so this is not a patch to
Milestone C's disclosed single-session gap or Milestone G's single-chain
gap: it targets a third, different failure mode -- several ostensibly
independent agent identities acting in coordination -- and makes no claim
of having addressed either of the other two. See
`docs/adr/0006-collusion-ring-detection.md`.

Pipeline: `collusion/graph.py` builds an agent graph from shared device
fingerprints and counterparty overlap inside a coordinated time window;
`collusion/community.py` applies Louvain community detection to surface
candidate rings; `collusion/scoring.py` computes a risk score per candidate,
combining fingerprint-sharing density with a structuring signal;
`collusion/detect.py` orchestrates the three into a verdict per candidate
community. Every one of these operates only on `common.schema.SessionTrace`
and the session-keyed fingerprint mapping -- never on ground truth, matching
this project's established label-isolation discipline (`features/session.py`,
`containment/`) elsewhere.
"""

from __future__ import annotations
