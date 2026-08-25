"""Dashboard API (Phase 1 Step 7.5).

One aggregated snapshot for the Web Console home page: the frontend
binds this single endpoint instead of calling /events, /incidents and
risk endpoints and computing client-side. Pure read, no writes.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.dashboard import DashboardSummary
from app.services.dashboard import get_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    """Real-time aggregated snapshot: active incidents (with severity
    breakdown), today's alerts/events and the event risk distribution."""
    return DashboardSummary.model_validate(get_summary(db))
