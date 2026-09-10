# SentinelFlow backend image.
#
# Serves the FastAPI app (uvicorn) and is reused by the one-shot `migrate`
# service (alembic upgrade head) in docker-compose.yml. Runtime dependencies
# only (requirements/base.lock) — pytest / playwright are dev-only and stay out
# of the shipped image. Python 3.12 matches the version this project targets.
FROM python:3.12-slim

# No .pyc clutter, unbuffered logs (so `docker compose logs backend` is live),
# and no pip cache in the layer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching (code changes rarely
# invalidate the dependency layer). base.lock pins the exact, tested versions
# (compiled from base.txt via `uv pip compile`) so a build today and a build in
# six months install the identical dependency set.
COPY requirements/base.lock ./requirements/base.lock
RUN pip install --no-cache-dir -r requirements/base.lock

# Application code + migrations. COPY is selective on purpose: tests and the
# dev venv never enter the image.
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

# Least privilege: run as a non-root user. The container never uses privileged
# mode and mounts no host directory (state lives in Postgres, not the image).
RUN useradd --create-home --uid 10001 sentinelflow \
    && chown -R sentinelflow:sentinelflow /app
USER sentinelflow

EXPOSE 8000

# Readiness/liveness are probed by compose against /ready (see the compose
# healthcheck) — no HEALTHCHECK is baked in so the one-shot migrate service is
# not wrongly gated on a server it never starts.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
