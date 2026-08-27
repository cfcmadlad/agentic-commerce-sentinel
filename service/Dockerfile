# Builds the API service from a clean clone: one command, no manual setup.
#
#   docker build -f service/Dockerfile -t sentinel-service .
#   docker run -p 8000:8000 --env-file .env sentinel-service
#
# --env-file .env is optional: GROQ_API_KEY enables Layer 4 narration, but
# the service runs correctly without it (see service/state.py) -- narration
# degrades to a stated placeholder in the audit trail rather than failing.
#
# Built from the repo root (the build context needs every top-level
# package: mandate, common, generator, detect, features, eval, reasoning,
# service), not from inside service/ itself.

FROM python:3.12-slim

WORKDIR /app

COPY requirements-lock.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements-lock.txt

COPY mandate ./mandate
COPY common ./common
COPY generator ./generator
COPY detect ./detect
COPY features ./features
COPY eval ./eval
COPY reasoning ./reasoning
COPY service ./service

RUN pip install --no-cache-dir --no-deps -e .

EXPOSE 8000

# No --reload: this is the built image, not a dev loop. Startup fits Layer 3
# against the same 20,000-session corpus run_milestone_b.py reports on
# (service/state.py), so the container takes tens of seconds to become
# ready -- add a healthcheck against /health in orchestration if that
# matters for your deployment.
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8000"]
