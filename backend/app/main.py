import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.router import router as v1_router
from app.core.config import settings
from app.core.runtime_mode import (
    deployment_mode,
    validate_production_mode,
)
from app.core.database import get_db
from app.services.executions.registry import validate_adapter_config

logger = logging.getLogger("sentinelflow")


def _configure_logging() -> None:
    """Level from DEBUG (DEBUG when true, else INFO). Adds a handler only
    when neither this logger nor the root has one, so uvicorn/pytest keep
    their own config (no duplicate lines). Stack traces stay debug-only."""
    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    if not logger.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)


def _safe_config_summary() -> str:
    """Startup config summary — WHAT is enabled/disabled, never a secret
    value. Only the DB driver scheme, enums and configured/unconfigured
    booleans are emitted; credentials / tokens / URLs are never printed."""
    db_backend = settings.DATABASE_URL.split("://", 1)[0] or "unknown"
    return (
        f"mode={deployment_mode(settings)} "
        f"db={db_backend} "
        f"ai_provider={settings.AI_PROVIDER} "
        f"execution_adapter={settings.EXECUTION_ADAPTER} "
        f"policy={'enabled' if settings.EXECUTION_POLICY_ENABLED else 'disabled'} "
        f"operators={'configured' if settings.OPERATORS_JSON else 'none'} "
        f"execution_token={'set' if settings.EXECUTION_TOKEN else 'unset'} "
        f"shuffle={'configured' if settings.SHUFFLE_BASE_URL else 'disabled'} "
        f"wazuh={'configured' if settings.WAZUH_BASE_URL else 'disabled'} "
        f"thehive={'configured' if settings.THEHIVE_BASE_URL else 'disabled'} "
        f"compensation_experimental={'on' if settings.EXECUTION_COMPENSATION_EXPERIMENTAL else 'off'} "
        f"debug={'on' if settings.DEBUG else 'off'}"
    )


@asynccontextmanager
async def _lifespan(application: FastAPI):
    _configure_logging()
    # RC2 §7 + §20: PRODUCTION MODE IS FAIL-CLOSED BEFORE ANYTHING ELSE — an
    # unsafe deployment (missing OPERATORS_JSON auth / SQLite / mock adapter /
    # compensation / non-loopback BIND_HOST) refuses to boot with ONE
    # sanitized error naming keys only. Demo mode returns immediately.
    validate_production_mode(settings)
    # Startup fail-closed: a misconfigured execution adapter (unknown /
    # multi-value selection, or a real adapter missing its credentials)
    # refuses to BOOT — the platform never pretends to run and then fails
    # at the first Execute. mock needs no credentials.
    validate_adapter_config(settings)
    logger.info("SentinelFlow backend starting | %s", _safe_config_summary())
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.3.0",
    lifespan=_lifespan,
)

app.include_router(v1_router, prefix=settings.API_V1_PREFIX)


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Liveness: 200 whenever the process is up (DB state is reported in
    the body, never in the status code). Orchestrators should probe
    /ready for dependency readiness. ``database_driver`` is the non-sensitive
    URL scheme (e.g. ``postgresql`` / ``sqlite``) so doctor / smoke can detect
    the platform without ever reading the credential-bearing URL."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
    return {
        "status": "ok",
        "service": "sentinelflow-backend",
        "database": db_status,
        "database_driver": settings.DATABASE_URL.split("://", 1)[0] or "unknown",
    }


@app.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Readiness: 200 only when the database answers SELECT 1, else 503.
    This is the probe compose / orchestrators gate backend traffic on."""
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="database not ready")
    return {
        "status": "ready",
        "service": "sentinelflow-backend",
        "database": "connected",
    }
