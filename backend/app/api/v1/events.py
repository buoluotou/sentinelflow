import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.event import (
    EventAlertItem,
    EventDetailResponse,
    EventInfo,
    EventListItem,
    EventListResponse,
)
from app.services.events import get_event, list_events

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventListResponse)
def events_list(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> EventListResponse:
    """List aggregated security events, most recently seen first."""
    total, groups = list_events(db, page=page, size=size)
    return EventListResponse(
        total=total,
        page=page,
        size=size,
        items=[EventListItem.model_validate(g) for g in groups],
    )


@router.get("/{group_id}", response_model=EventDetailResponse)
def event_detail(group_id: str, db: Session = Depends(get_db)) -> EventDetailResponse:
    """Get one security event with all its evidence alerts."""
    try:
        gid = uuid.UUID(group_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Event not found") from exc

    group = get_event(db, gid)
    if group is None:
        raise HTTPException(status_code=404, detail="Event not found")

    alerts = sorted(group.alerts, key=lambda a: (a.first_seen_at, a.created_at))
    return EventDetailResponse(
        event=EventInfo.model_validate(group),
        alerts=[EventAlertItem.model_validate(a) for a in alerts],
    )
