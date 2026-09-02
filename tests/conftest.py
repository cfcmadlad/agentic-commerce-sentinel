"""Loads local secrets from a gitignored `.env` file before tests run.

Dev/test convenience only, not part of the shipped system: the tests that
call the real Groq API (`test_narrate.py`, `test_prompt_injection_
resistance.py`) are `skipif`-gated on `GROQ_API_KEY` being present in the
environment. This makes a `.env` file at the repo root -- copy `.env.example`
to `.env` and fill in a real key -- a working alternative to setting the
variable in a shell profile. `.env` itself stays gitignored; only
`.env.example` (no real key) is committed.

A real deployment of the API service sets `GROQ_API_KEY` through its own
environment or secrets manager, not through this file -- `load_dotenv()`
here only affects local `pytest` runs.

Also raises the rate limiter's own configurable ceiling
(`service.main._rate_limit_config`) for the whole test session, set here
-- before `service.main` is ever imported, since its `RateLimitMiddleware`
is wired in at module-import time -- rather than in `test_service.py`
itself, so it takes effect regardless of import order. `tests/test_service
.py`'s `client` fixture is deliberately session-scoped and shared across
every test in that module (building it fits the real Layer 3 model once);
without this, the real production default (60 requests/60s) is exactly
the kind of limit dozens of tests sharing one client in a fast test run
would trip, for a reason that has nothing to do with what any single test
is checking.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

os.environ.setdefault("SENTINEL_RATE_LIMIT_MAX_REQUESTS", "100000")

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass  # truststore is a dev-only workaround for a local TLS-inspecting proxy/AV;
    # normal reviewer machines resolve certs fine without it
