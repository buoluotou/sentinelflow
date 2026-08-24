from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.router import router as v1_router
from app.core.config import settings
from app.core.database import get_db

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
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
