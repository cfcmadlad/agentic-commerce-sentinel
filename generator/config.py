"""Generator configuration: merchant categories, amount distributions, agent pool.

Amount medians and category weights are loosely grounded in public 2025-2026
Indian ecommerce market reporting (Mordor Intelligence, IMARC, Bain &
Company/Flipkart "How India Shops Online 2025", PaymentsCMI), not derived
from any proprietary dataset. Treat every number below as directional, not
precise: this is a synthetic generator, and Section 5 requires reporting a
sensitivity analysis across exactly these parameters rather than presenting
them as ground truth. Where a source gave a range, the midpoint (or a
value within the range) was chosen and is called out per field.

All values are named constants, not inlined, so the Day 5 sensitivity sweep
has a single place to vary each one.
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
# what the Day 2 mandate-replay attack generator needs a legitimate,
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
# agent per session, so the behavioral layer (Day 4) has per-agent history
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


def compute_params_digest() -> str:
    """Hashes the full set of generator parameters currently in effect.

    Used to populate `LabeledSession.generator_params_digest`, so the
    Section 5 sensitivity analysis can tell, from generated data alone,
    which parameter set produced it, without re-running the generator.

    Returns:
        A hex SHA-256 digest of a canonical JSON encoding of every constant
        and category config in this module.
    """
    module_globals = globals()
    scalar_constants = {
        name: value
        for name, value in sorted(module_globals.items())
        if name.isupper() and isinstance(value, int | float | str)
    }
    payload = {
        "scalars": scalar_constants,
        "categories": [asdict(c) for c in CATEGORY_CONFIGS],
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()