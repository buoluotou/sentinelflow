import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.models import Alert
from app.schemas.alert import AlertCreate, AlertDetail, AlertRead
from app.services.ingestion import ingest_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", status_code=201, response_model=AlertRead)
def create_alert(payload: AlertCreate, db: Session = Depends(get_db)) -> Alert:
    """Ingest a security alert (from the Simulator or any future adapter)."""
    return ingest_alert(db, payload)


@router.get("", response_model=list[AlertRead])
def list_alerts(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[Alert]:
    """List alerts, most recently seen first."""
    stmt = (
        select(Alert)
        .order_by(Alert.last_seen_at.desc(), Alert.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: uuid.UUID, db: Session = Depends(get_db)) -> Alert:
    """Get one alert including its raw contributing events."""
    stmt = (
        select(Alert)
        .options(selectinload(Alert.events))
        .where(Alert.id == alert_id)
    )
    alert = db.execute(stmt).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
