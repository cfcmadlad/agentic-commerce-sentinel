"""Loads local secrets from a gitignored `.env` file before tests run.

Dev/test convenience only, not part of the shipped system: the tests that
call the real Groq API (`test_narrate.py`, `test_prompt_injection_
resistance.py`) are `skipif`-gated on `GROQ_API_KEY` being present in the
environment. This makes a `.env` file at the repo root -- copy `.env.example`
to `.env` and fill in a real key -- a working alternative to setting the
variable in a shell profile. `.env` itself stays gitignored; only
`.env.example` (no real key) is committed.

A future Milestone E (the API service) would set `GROQ_API_KEY` through its
own deployment's environment or secrets manager, not through this file --
`load_dotenv()` here only affects local `pytest` runs.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
