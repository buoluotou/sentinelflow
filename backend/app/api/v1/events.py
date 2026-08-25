import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.event import (
    EventAlertItem,
    EventDetailResponse,
    EventInfo,
    EventListItem,
    EventListResponse,
    EventRiskDetail,
)
from app.services.events import get_event, list_events

router = APIRouter(prefix="/events", tags=["events"])

RiskLevel = Literal["low", "medium", "high", "critical"]


@router.get("", response_model=EventListResponse)
def events_list(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    level: RiskLevel | None = Query(
        default=None, description="Filter events by current risk level"
    ),
    db: Session = Depends(get_db),
) -> EventListResponse:
    """List aggregated security events, most recently seen first.

    Each item carries the pre-computed risk snapshot (risk_score/risk_level);
    use ``level`` to keep only events at a given risk level.
    """
    total, groups = list_events(db, page=page, size=size, level=level)
    items = [
        EventListItem.model_validate(g).model_copy(
            update={
                "risk_score": g.risk.score if g.risk is not None else None,
                "risk_level": g.risk.level if g.risk is not None else None,
            }
        )
        for g in groups
    ]
    return EventListResponse(total=total, page=page, size=size, items=items)


@router.get("/{group_id}", response_model=EventDetailResponse)
def event_detail(group_id: str, db: Session = Depends(get_db)) -> EventDetailResponse:
    """Get one security event with its evidence alerts and risk factors."""
    try:
        gid = uuid.UUID(group_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Event not found") from exc

    group = get_event(db, gid)
    if group is None:
        raise HTTPException(status_code=404, detail="Event not found")

    alerts = sorted(group.alerts, key=lambda a: (a.first_seen_at, a.created_at))
    risk = (
        EventRiskDetail.model_validate(group.risk) if group.risk is not None else None
    )
    return EventDetailResponse(
        event=EventInfo.model_validate(group),
        alerts=[EventAlertItem.model_validate(a) for a in alerts],
        risk=risk,
    )
