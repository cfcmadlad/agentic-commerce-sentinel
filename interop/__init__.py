"""AP2 interop adapter: translating between this project's mandate schema and AP2's.

Built after directly verifying AP2's current schema against the live
repository (`google-agentic-commerce/AP2`, `code/sdk/python/ap2/models/`),
not assumed from an earlier description of it -- and what that verification
found differs enough from what an earlier draft of this project's own
README claimed that the README itself needed a correction (see the
README's AP2/UAP section and `docs/adr/0010-ap2-interop-adapter.md`'s
"what was assumed vs. what was found" section). This package's adapter is honest about the result: it
translates what genuinely maps, and requires the caller to explicitly
supply what does not exist on the AP2 side at all (merchant/item category,
`valid_from`, `agent_id`, `user_id`) rather than inventing a value or
silently dropping this project's own schema requirements.

`ap2_types.py` mirrors only the fields of AP2's real Pydantic models this
adapter actually reads or writes -- not the full protocol surface (shipping
options, the contact picker, payment-method-specific data), none of which
this project's own schema has anywhere to put.
"""

from __future__ import annotations
