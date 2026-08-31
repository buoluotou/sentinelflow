from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.router import router as v1_router
from app.core.config import settings
from app.core.database import get_db
from app.services.executions.registry import validate_adapter_config


@asynccontextmanager
async def _lifespan(application: FastAPI):
    # 3.2.1 startup fail-closed: a misconfigured execution adapter
    # (unknown / multi-value selection, or a real adapter missing its
    # credentials) refuses to BOOT — the platform never pretends to run
    # and then fails at the first Execute. mock needs no credentials.
    validate_adapter_config(settings)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0-phase1",
    lifespan=_lifespan,
)

app.include_router(v1_router, prefix=settings.API_V1_PREFIX)


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
    return {
        "status": "ok",
        "service": "sentinelflow-backend",
        "database": db_status,
    }
