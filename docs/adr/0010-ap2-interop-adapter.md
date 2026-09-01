# ADR 0010: AP2 interop adapter

## Status

Accepted. Built and tested; a real discrepancy between this project's earlier AP2 claim and the actual spec was found, disclosed, and corrected.

## Context

This project's mandate schema has cited AP2 (Google's Agent Payments Protocol) as its reference point since the schema was first written, and the README's AP2 section made a specific claim about the fit: that AP2's Intent Mandate "already defines exactly the kind of bounded authorization this project needs: a signed record of spending limits, category constraints, and an expiration." The brief for this milestone required verifying AP2's current field names and mandate structure against the published spec *before* writing anything, and flagging the user if what was found differed from what the brief assumed. It did.

## What was assumed vs. what was found

Fetched directly from the live repository (`google-agentic-commerce/AP2`, `code/sdk/python/ap2/models/mandate.py` and `payment_request.py`), not from memory or an earlier description:

| Assumed | Actually found |
|---|---|
| `IntentMandate` carries spending limits | It does not. Fields: `user_cart_confirmation_required`, `natural_language_description` (free text), `merchants: list[str]\|None`, `skus: list[str]\|None`, `requires_refundability`, `intent_expiry`. No amount field anywhere. |
| `IntentMandate` carries category constraints | It does not. `merchants`/`skus` are specific ID lists, not categories -- AP2 has no category concept anywhere in either file. |
| The user's own signed mandate states the ceiling | The actual price commitment lives three levels deep inside a *separate*, **merchant**-signed `CartMandate` (`contents.payment_request.details.total`), not the user-signed `IntentMandate`. |
| (unstated, but implicit in modeling a reusable budget) | AP2 mandates are single-transaction by construction: one Intent authorizes one Cart authorizes one Payment. There is no multi-use budget concept to map `max_transaction_count` from. |
| (unstated) | AP2 has no delegation-chain concept anywhere in its mandate schema -- this project's entire Layer 2.5 has no AP2 analogue. |
| (unstated) | AP2 signs via an external Verifiable-Credential scheme (`merchant_authorization`/`user_authorization`, opaque strings), structurally different from this project's raw Ed25519-over-canonical-bytes. |

This is a real, disclosed finding, the same evaluation-honesty standard this project holds its own numbers to (Milestone C's held-out result is the sharpest prior example). The README's AP2 section and `mandate/schema.py`'s own module docstring both made the now-corrected claim before this milestone; both were rewritten to state the actual relationship: AP2-*inspired*, independently designed for a reusable, category-scoped, multi-agent-delegation model AP2 does not represent, not an implementation of AP2's own schema.

## Design

### `interop/ap2_types.py` mirrors only what the adapter touches

Minimal Pydantic models with field names verified against the real repository, not the full AP2 protocol surface. Shipping options, the contact picker, payment-method-specific `data` payloads, and refund/pending flags are all real AP2 fields this project's own schema has nowhere to put, and are omitted outright rather than included and ignored -- the same "don't claim to touch what you don't" discipline as everywhere else in this project.

### The field mapping, and what has no AP2 source at all

Stated in full in `interop/adapter.py`'s own module docstring; summarized here:

| This project's field | AP2 source |
|---|---|
| `scope.max_amount` / `currency` | `cart.contents.payment_request.details.total.amount` |
| `scope.allowed_merchant_ids` | `intent.merchants` (a specific list, not a category) |
| `scope.valid_until` / `expires_at` | `min(intent.intent_expiry, cart.contents.cart_expiry)` |
| `scope.allowed_merchant_categories` | **none** -- caller-supplied |
| `scope.allowed_item_categories` | **none** -- caller-supplied |
| `scope.valid_from` / `issued_at` | **none** -- caller-supplied |
| `scope.max_transaction_count` | **none** -- defaults to 1 |
| `agent_id`, `user_id` | **none** -- caller-supplied |
| `signer_key_id` | **none** -- caller-supplied |
| `parent_mandate_id` | **no AP2 concept at all** |

Six of ten fields have no AP2 source. `ap2_to_mandate` makes every one of them an explicit, required (or explicitly-defaulted) keyword argument rather than inventing a plausible-looking value -- a caller cannot accidentally get a translated mandate with a silently-guessed category or a silently-assumed agent identity.

### Translates content, not trust

`ap2_to_mandate` returns an **unsigned** `Mandate`. AP2's VC-style signatures are not merely a different key encoding of the same scheme this project's `mandate.signing.signature_is_valid` checks -- they are a different scheme entirely, and no attempt is made to bridge that trust boundary. A caller wanting a translated mandate to actually flow through this project's Layers 1/2 must sign it with this project's own Ed25519 scheme, using a key it separately registers, exactly like any other mandate this project issues. `test_translated_mandate_can_be_signed_and_verified_with_this_projects_own_scheme` demonstrates this is a real, valid `Mandate` by doing exactly that end to end, not merely asserting its shape.

### Reverse direction and round-trip tests

`mandate_to_ap2` is lossy in the same places, mirrored: `agent_id`, `user_id`, `parent_mandate_id`, the category/SKU distinction, and `max_transaction_count` beyond "at least one use" have no AP2 field to land in and are dropped, not approximated. `natural_language_description` is synthesized from the mandate's own already-known scope fields (amount, category, merchant restriction) -- a real rendering of real data, never fabricated prose. The round-trip tests assert exactly the fields that are genuinely lossless (amount, currency, expiry, a single-merchant restriction) survive `Mandate -> AP2 -> Mandate`, and do not claim more than that.

### Deterministic mandate IDs

`_mandate_id_for_cart` derives the internal `mandate_id` via `uuid5` from the AP2 cart's own `id`, so translating the same AP2 cart twice yields the same internal identity -- matching this project's general preference for reproducible derivation over a fresh random ID wherever a stable source identity already exists (the same reasoning `mandate.signing.key_id_for_public_key`'s fingerprinting already uses).

## Consequences

**Per this project's standing constraint, `detect/`, `features/`, `mandate/verification.py`, `mandate/signing.py`, and the generator were untouched.** `mandate/schema.py`'s own module docstring was corrected (a documentation fix, not a schema or logic change) alongside the README's AP2 section.

**What this buys.** A real, tested, honestly-scoped translation for the fields that do map, and an explicit, un-skippable list of what does not -- useful as a genuine starting point for real AP2 interop, not a demo that would fall over the first time someone checked it against the actual spec.

**What this does not buy.** No cryptographic trust bridge (see above). No delegation-chain translation in either direction (AP2 has none to translate). No round-trip of category, SKU, or multi-transaction-budget information, because none of those concepts exist on both sides to round-trip between.
