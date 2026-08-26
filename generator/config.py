"""Generator configuration: merchant categories, amount distributions, agent pool.

Amount medians and category weights are loosely grounded in public 2025-2026
Indian ecommerce market reporting (Mordor Intelligence, IMARC, Bain &
Company/Flipkart "How India Shops Online 2025", PaymentsCMI), not derived
from any proprietary dataset. Treat every number below as directional, not
precise: this is a synthetic generator, and Section 5 requires reporting a
sensitivity analysis across exactly these parameters rather than presenting
them as ground truth. Where a source gave a range, the midpoint (or a
value within the range) was chosen and is called out per field.

All values are named constants, not inlined, and are additionally exposed as
the field defaults of `GeneratorConfig` below, so the sensitivity sweep has a
single injectable place to vary each one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal


@dataclass(frozen=True)
class CategoryConfig:
    """Distributional parameters for one merchant category.

    Attributes:
        name: Category identifier, used as `merchant_category` on generated
            traces and as the category label in mandate scopes.
        gmv_weight: Relative likelihood a legitimate session falls in this
            category. Weights across all categories need not sum to 1; they
            are normalized at sampling time.
        amount_median: Decimal median transaction amount in INR. Sessions
            are drawn from a log-normal distribution around this median, so
            half of generated amounts fall below it by construction.
        amount_sigma: Log-normal shape parameter controlling spread. Larger
            values produce a longer right tail (occasional large baskets).
        item_categories: Item categories a session in this merchant category
            may report.
        merchant_ids: Illustrative merchant identifiers for this category.
            These are labels chosen for realism, not integrations with or
            claims about any actual merchant's systems.
    """

    name: str
    gmv_weight: float
    amount_median: Decimal
    amount_sigma: float
    item_categories: tuple[str, ...]
    merchant_ids: tuple[str, ...]


# Electronics: highest average order value of any major category, ~23-30%
# of GMV by most 2025-2026 market reports. amount_median set well above
# other categories to reflect that gap; sigma wide because phone/laptop
# purchases sit far out on the tail relative to accessories.
_ELECTRONICS = CategoryConfig(
    name="electronics",
    gmv_weight=0.24,
    amount_median=Decimal("12000.00"),
    amount_sigma=0.9,
    item_categories=("smartphone", "laptop", "audio", "accessories"),
    merchant_ids=("amazon_in", "flipkart", "croma"),
)

# Fashion & apparel: second-largest category by GMV share (~22-32% across
# sources), materially lower AOV than electronics.
_FASHION = CategoryConfig(
    name="fashion_apparel",
    gmv_weight=0.22,
    amount_median=Decimal("1400.00"),
    amount_sigma=0.6,
    item_categories=("apparel", "footwear", "accessories"),
    merchant_ids=("myntra", "ajio", "amazon_in"),
)

# Grocery / quick commerce: highest frequency, lowest basket size, per
# quick-commerce AOV benchmarks well under electronics or fashion.
_GROCERY = CategoryConfig(
    name="grocery",
    gmv_weight=0.23,
    amount_median=Decimal("550.00"),
    amount_sigma=0.5,
    item_categories=("packaged_food", "produce", "household_essentials"),
    merchant_ids=("bigbasket", "blinkit", "zepto", "swiggy_instamart"),
)

# Home & kitchen: mid-frequency, mid-to-high AOV per PaymentsCMI's reported
# ~$60-72 per basket range, converted to INR at a round approximate rate.
_HOME_KITCHEN = CategoryConfig(
    name="home_kitchen",
    gmv_weight=0.16,
    amount_median=Decimal("4800.00"),
    amount_sigma=0.7,
    item_categories=("kitchenware", "furnishing", "appliances_small"),
    merchant_ids=("amazon_in", "flipkart", "pepperfry"),
)

# Food delivery: very high frequency, low basket size, distinct from
# grocery quick-commerce in item category even though both are fast/local.
_FOOD_DELIVERY = CategoryConfig(
    name="food_delivery",
    gmv_weight=0.15,
    amount_median=Decimal("380.00"),
    amount_sigma=0.4,
    item_categories=("restaurant_order",),
    merchant_ids=("zomato", "swiggy"),
)

CATEGORY_CONFIGS: tuple[CategoryConfig, ...] = (
    _ELECTRONICS,
    _FASHION,
    _GROCERY,
    _HOME_KITCHEN,
    _FOOD_DELIVERY,
)

CURRENCY = "INR"

# Bounds a sampled log-normal amount is clipped to, so an extreme tail draw
# cannot produce an implausible ₹0.03 or ₹50,00,000 transaction. Expressed
# as multiples of amount_median at call time, not as absolute constants,
# since the appropriate floor/ceiling differs by category.
MIN_AMOUNT_MULTIPLE_OF_MEDIAN = 0.15
MAX_AMOUNT_MULTIPLE_OF_MEDIAN = 6.0

# Mandate scope ceiling is set above the actual transaction amount so a
# legitimate session sits inside its own mandate's budget, not at the exact
# edge. Sampled uniformly within this multiple range.
MIN_SCOPE_CEILING_MULTIPLE = 1.15
MAX_SCOPE_CEILING_MULTIPLE = 3.0

# Fraction of legitimate sessions that reuse an existing, still-valid
# mandate rather than being issued a fresh one. Models a standing grocery
# or subscription-style mandate covering several purchases, which is also
# what the mandate-replay attack generator needs a legitimate,
# already-partially-spent mandate to imitate.
RECURRING_MANDATE_PROBABILITY = 0.35

# Bounds on how many uses a freshly issued mandate is authorized for.
MIN_MANDATE_TRANSACTION_COUNT = 1
MAX_MANDATE_TRANSACTION_COUNT = 6

# Mandate lifetime bounds, in days, sampled uniformly.
MIN_MANDATE_LIFETIME_DAYS = 3
MAX_MANDATE_LIFETIME_DAYS = 30

# Size of the simulated agent population. Each agent has its own registered
# signing key; sessions are distributed across this pool rather than one
# agent per session, so the behavioral layer has per-agent history
# to compute features over.
AGENT_POOL_SIZE = 40

# Size of the simulated user population.
USER_POOL_SIZE = 500

# Session timing: seconds of jitter between consecutive lifecycle events,
# sampled uniformly per step. Wide enough to separate timestamps
# realistically without dominating session generation cost.
MIN_EVENT_GAP_SECONDS = 2
MAX_EVENT_GAP_SECONDS = 45

# Fixed anchor for "now" in generated data, rather than the system clock,
# so a full generation run is byte-for-byte reproducible from the same
# seed regardless of when it is executed.
GENERATION_ANCHOR = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)

# Sessions are spread uniformly over the this many days ending at
# GENERATION_ANCHOR.
SESSION_HORIZON_DAYS = 30

# Minimum gap enforced between successive uses of the same recurring
# mandate, so reused-mandate sessions don't cluster at implausible
# sub-minute intervals.
MIN_RECURRING_REUSE_GAP_HOURS = 6

# Probability an agent's category preferences are a single category rather
# than two. Most real deployed agents are single-purpose.
SINGLE_CATEGORY_PROBABILITY = 0.7

# Probability a freshly issued mandate is pinned to one specific merchant
# rather than to its whole category.
SINGLE_MERCHANT_SCOPE_PROBABILITY = 0.5

# Fraction of a reused mandate's remaining ceiling a session may consume, so
# a legitimate reuse sits inside budget with margin rather than at the edge.
REUSE_CEILING_HEADROOM = 0.98


def check_ordered(label: str, low: float, high: float) -> None:
    """Rejects an inverted (low, high) bound pair.

    Public because the attack-side config validates its own bound pairs under
    the same rules; two copies of this check could drift apart.

    Args:
        label: Human-readable name of the bound pair, for the error message.
        low: The lower bound.
        high: The upper bound.

    Raises:
        ValueError: If `high` precedes `low`.
    """
    if high < low:
        raise ValueError(f"{label}: upper bound {high} precedes lower bound {low}")


def check_probability(label: str, value: float) -> None:
    """Rejects a probability outside [0, 1].

    Args:
        label: Field name, for the error message.
        value: The value to check.

    Raises:
        ValueError: If `value` is outside [0, 1].
    """
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{label} must be in [0, 1], got {value}")


def check_positive(label: str, value: float) -> None:
    """Rejects a non-positive value.

    Args:
        label: Field name, for the error message.
        value: The value to check.

    Raises:
        ValueError: If `value` is not strictly positive.
    """
    if value <= 0:
        raise ValueError(f"{label} must be positive, got {value}")


def digest_payload(payload: dict[str, object]) -> str:
    """Canonicalizes a parameter payload and hashes it.

    Shared by `GeneratorConfig` and the attack-side config so both produce
    digests under identical encoding rules; two parameter sets that differ
    anywhere must not collide because one of them stringified a Decimal
    differently from the other.

    Args:
        payload: Nested parameter mapping. Values JSON cannot encode
            natively (Decimal, datetime) are stringified deterministically.

    Returns:
        A hex SHA-256 digest.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GeneratorConfig:
    """Every tunable parameter of the legitimate traffic generator.

    Field defaults are the module-level constants above, so
    `GeneratorConfig()` reproduces the generator's established behaviour
    byte-for-byte. The dataclass exists because the sensitivity analysis has
    to re-run generation under perturbed parameters, and the generator
    modules bind these constants by name at import time, which puts them out
    of a caller's reach without patching another module's namespace.
    Injecting a frozen config instead keeps the parameter set explicit,
    hashable, and reportable alongside the metrics it produced.

    Attributes:
        categories: Per-category amount distributions and merchant pools.
        currency: ISO 4217 code stamped on every generated session.
        min_amount_multiple_of_median: Lower clip on a sampled amount, as a
            multiple of the category median.
        max_amount_multiple_of_median: Upper clip on a sampled amount, as a
            multiple of the category median.
        min_scope_ceiling_multiple: Lower bound on a mandate's amount
            ceiling, as a multiple of the session amount it was issued for.
        max_scope_ceiling_multiple: Upper bound on the same.
        recurring_mandate_probability: Probability a session reuses the
            agent's standing mandate rather than being issued a fresh one.
        min_mandate_transaction_count: Lower bound on a mandate's authorized
            use count.
        max_mandate_transaction_count: Upper bound on the same.
        min_mandate_lifetime_days: Lower bound on a mandate's validity
            window, in days.
        max_mandate_lifetime_days: Upper bound on the same.
        agent_pool_size: Number of simulated agents, each with its own key.
        user_pool_size: Number of simulated human principals.
        min_event_gap_seconds: Lower bound on inter-event jitter within a
            legitimate session.
        max_event_gap_seconds: Upper bound on the same.
        generation_anchor: Fixed "now" the session horizon ends at, so a run
            does not depend on the system clock.
        session_horizon_days: Span of time sessions are spread across,
            ending at `generation_anchor`.
        min_recurring_reuse_gap_hours: Minimum spacing between successive
            uses of one recurring mandate.
        single_category_probability: Probability an agent prefers exactly one
            category rather than two.
        single_merchant_scope_probability: Probability a mandate is pinned to
            one merchant rather than a whole category.
        reuse_ceiling_headroom: Fraction of a reused mandate's ceiling a
            session may consume.

    Raises:
        ValueError: If `categories` is empty, if any bound pair is inverted,
            if any probability falls outside [0, 1], or if a pool size,
            horizon, or category scale parameter is not positive. A run under
            invalid parameters produces a corpus that looks plausible and
            silently is not, so these fail at construction rather than
            somewhere deep inside sampling.
    """

    categories: tuple[CategoryConfig, ...] = CATEGORY_CONFIGS
    currency: str = CURRENCY
    min_amount_multiple_of_median: float = MIN_AMOUNT_MULTIPLE_OF_MEDIAN
    max_amount_multiple_of_median: float = MAX_AMOUNT_MULTIPLE_OF_MEDIAN
    min_scope_ceiling_multiple: float = MIN_SCOPE_CEILING_MULTIPLE
    max_scope_ceiling_multiple: float = MAX_SCOPE_CEILING_MULTIPLE
    recurring_mandate_probability: float = RECURRING_MANDATE_PROBABILITY
    min_mandate_transaction_count: int = MIN_MANDATE_TRANSACTION_COUNT
    max_mandate_transaction_count: int = MAX_MANDATE_TRANSACTION_COUNT
    min_mandate_lifetime_days: int = MIN_MANDATE_LIFETIME_DAYS
    max_mandate_lifetime_days: int = MAX_MANDATE_LIFETIME_DAYS
    agent_pool_size: int = AGENT_POOL_SIZE
    user_pool_size: int = USER_POOL_SIZE
    min_event_gap_seconds: int = MIN_EVENT_GAP_SECONDS
    max_event_gap_seconds: int = MAX_EVENT_GAP_SECONDS
    generation_anchor: datetime = GENERATION_ANCHOR
    session_horizon_days: int = SESSION_HORIZON_DAYS
    min_recurring_reuse_gap_hours: int = MIN_RECURRING_REUSE_GAP_HOURS
    single_category_probability: float = SINGLE_CATEGORY_PROBABILITY
    single_merchant_scope_probability: float = SINGLE_MERCHANT_SCOPE_PROBABILITY
    reuse_ceiling_headroom: float = REUSE_CEILING_HEADROOM

    def __post_init__(self) -> None:
        """Validates the parameter set at construction time.

        Raises:
            ValueError: If any invariant in the class docstring is violated.
        """
        if not self.categories:
            raise ValueError("categories must be non-empty")
        check_ordered(
            "amount multiple of median",
            self.min_amount_multiple_of_median,
            self.max_amount_multiple_of_median,
        )
        check_ordered(
            "scope ceiling multiple",
            self.min_scope_ceiling_multiple,
            self.max_scope_ceiling_multiple,
        )
        check_ordered(
            "mandate transaction count",
            self.min_mandate_transaction_count,
            self.max_mandate_transaction_count,
        )
        check_ordered(
            "mandate lifetime days",
            self.min_mandate_lifetime_days,
            self.max_mandate_lifetime_days,
        )
        check_ordered("event gap seconds", self.min_event_gap_seconds, self.max_event_gap_seconds)
        check_probability("recurring_mandate_probability", self.recurring_mandate_probability)
        check_probability("single_category_probability", self.single_category_probability)
        check_probability(
            "single_merchant_scope_probability", self.single_merchant_scope_probability
        )
        check_probability("reuse_ceiling_headroom", self.reuse_ceiling_headroom)
        check_positive("agent_pool_size", self.agent_pool_size)
        check_positive("user_pool_size", self.user_pool_size)
        check_positive("session_horizon_days", self.session_horizon_days)
        check_positive("min_recurring_reuse_gap_hours", self.min_recurring_reuse_gap_hours)
        check_positive("min_mandate_transaction_count", self.min_mandate_transaction_count)
        check_positive("min_mandate_lifetime_days", self.min_mandate_lifetime_days)
        for category in self.categories:
            check_positive(f"{category.name} amount_sigma", category.amount_sigma)
            if category.amount_median <= 0:
                raise ValueError(
                    f"{category.name} amount_median must be positive, "
                    f"got {category.amount_median}"
                )

    def params_digest(self) -> str:
        """Hashes this parameter set into a stable identifier.

        Populates `LabeledSession.generator_params_digest`, so the
        sensitivity analysis can tell which parameter set produced a given
        corpus from the generated data alone, without re-running the
        generator. Two configs differing in any field produce different
        digests; two structurally equal configs always produce the same one.

        Returns:
            A hex SHA-256 digest of a canonical JSON encoding of every field.
        """
        return digest_payload({"generator": asdict(self)})


DEFAULT_GENERATOR_CONFIG = GeneratorConfig()
