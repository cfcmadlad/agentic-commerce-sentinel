"""Configuration for the attack generators (training classes only).

Every difficulty knob in the attack taxonomy lives here rather than inline in
the generators, for two reasons. First, the evaluation reports a sensitivity
analysis across generator parameters, and that needs a single place to vary
them. Second, the question of whether the attacks are too easy to be worth
modelling is answered by moving the rules-invisible variant weights, so those
weights must be explicit and named rather than buried.

Scope note: the held-out class (mandate chaining / privilege escalation) is
deliberately absent from this module. It is specified in the attack taxonomy
but is not implemented, parameterized, or referenced anywhere in the training
or tuning code, and is generated and evaluated exactly once at the end.

Defense-only note: these parameters describe how to produce synthetic traffic
that violates this project's own mandate format, in order to measure this
project's own detector. They encode no technique against any real payment
system and do not generalize off this repo's synthetic schema.
"""

from __future__ import annotations

from decimal import Decimal

# Fraction of the generated corpus that is attack traffic. A low single-digit
# base rate rather than a balanced split, because that is what the real
# problem looks like; the realized rate is reported alongside every metric.
DEFAULT_ATTACK_BASE_RATE = 0.04

# Relative share of attack traffic assigned to each of the three training
# classes. Roughly even, tilted toward scope violation because that is the
# class Layer 2 exists to catch and therefore the one that most needs volume
# for its per-rule breakdown to mean anything.
CLASS_MIX_MANDATE_REPLAY = 0.30
CLASS_MIX_SCOPE_VIOLATION = 0.40
CLASS_MIX_AGENT_IMPERSONATION = 0.30

# --- Class 1: mandate replay -------------------------------------------------

# Within replay traffic, the share of each variant. RAPID_REUSE is the
# rules-invisible variant: the mandate is genuine, unexpired and still inside
# its transaction budget, so Layers 1 and 2 both pass and only behavioral
# signal can separate it. Raising this weight is the primary lever for making
# class 1 harder.
REPLAY_MIX_EXPIRED = 0.30
REPLAY_MIX_BUDGET_EXHAUSTED = 0.30
REPLAY_MIX_RAPID_REUSE = 0.40

# How long after a mandate's expiry an expired-replay attempt is made. Bounded
# to hours-to-days, not months: an attacker replaying a year-old mandate is a
# strawman, and a detector tuned on one would not transfer.
MIN_EXPIRED_REPLAY_LAG_HOURS = 1
MAX_EXPIRED_REPLAY_LAG_HOURS = 96

# Gap between a mandate's last legitimate use and a rapid-reuse replay. The
# legitimate generator enforces a minimum 6-hour gap between reuses, so this
# range sits entirely inside territory the legitimate generator never visits -
# which is precisely the behavioral signal Layer 3 is expected to learn.
MIN_RAPID_REUSE_GAP_SECONDS = 20
MAX_RAPID_REUSE_GAP_SECONDS = 900

# --- Class 2: scope violation ------------------------------------------------

SCOPE_MIX_AMOUNT_OVER_CEILING = 0.30
SCOPE_MIX_MERCHANT_NOT_ALLOWED = 0.15
SCOPE_MIX_CATEGORY_MISMATCH = 0.20
SCOPE_MIX_ITEM_CATEGORY_MISMATCH = 0.15
SCOPE_MIX_WINDOW_EDGE = 0.20

# Boundary hardness for over-ceiling violations: the overshoot is drawn from
# this multiplier range, so a violation typically sits fractions of a percent
# past the limit rather than at an obvious multiple of it. A detector that
# only catches 10x overshoots would report excellent recall here and fail in
# production; this range is what stops that from happening.
MIN_CEILING_OVERSHOOT = Decimal("1.0005")
MAX_CEILING_OVERSHOOT = Decimal("1.0400")

# How far past the mandate's valid_until a window-edge violation sits. Minutes,
# not days, for the same boundary-hardness reason.
MIN_WINDOW_OVERSHOOT_MINUTES = 2
MAX_WINDOW_OVERSHOOT_MINUTES = 240

# --- Class 3: agent impersonation --------------------------------------------

# BEHAVIORAL_ONLY is the rules-invisible variant: an impersonating client that
# has obtained a genuine, in-scope mandate and transacts entirely within it,
# betrayed only by how the session is driven. It is weighted heavily on
# purpose - impersonation that fails a signature check is the easy half of the
# class and over-weighting it would inflate the rules baseline's recall.
IMPERSONATION_MIX_UNREGISTERED_KEY = 0.25
IMPERSONATION_MIX_FORGED_SIGNATURE = 0.15
IMPERSONATION_MIX_AGENT_BINDING_MISMATCH = 0.15
IMPERSONATION_MIX_BEHAVIORAL_ONLY = 0.45

# Event pacing for a scripted client. Legitimate sessions jitter 2-45s between
# lifecycle stages; a scripted one is faster and far more regular. The ranges
# overlap the legitimate floor deliberately so the two distributions are not
# linearly separable on a single timing feature. Widened to 1-20s (rather
# than a narrower fast-only band) so the upper end of scripted pacing sits
# well inside legitimate territory - a model that separates this class has
# to use more than raw speed.
MIN_SCRIPTED_EVENT_GAP_SECONDS = 1
MAX_SCRIPTED_EVENT_GAP_SECONDS = 20

# Probability a behavioral-only impersonation skips the catalog-browse stage
# entirely (a scripted client that already knows the SKU it wants). Held
# below 0.5 so browse-skipping is a minority pattern within the class, not a
# majority one - an always-or-mostly-present marker would still function as
# a near-single-rule giveaway even at less than 1.0.
SKIP_BROWSE_PROBABILITY = 0.35