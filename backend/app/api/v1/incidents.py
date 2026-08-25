"""Incident Management API (Phase 1 Step 7.3).

Thin HTTP layer: HTTP -> Schema -> services/incidents -> HTTP response.
The lifecycle state machine lives ONLY in the service; this module maps
business exceptions to status codes:

    IncidentNotFound            -> 404
    IncidentAlreadyExists       -> 409
    IncidentRiskMissing         -> 409  (no silent score=0 case)
    InvalidIncidentTransition   -> 409 Conflict
"""
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentListResponse,
    IncidentRead,
    IncidentStatusUpdate,
)
from app.services.incidents import (
    IncidentAlreadyExists,
    IncidentNotFound,
    IncidentRiskMissing,
    InvalidIncidentTransition,
    create_incident,
    get_incident,
    list_incidents,
    transition_status,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

#: ?status= filter vocabulary — invalid query values fail fast with 422,
#: mirroring the events API ``?level=`` behaviour.
StatusFilter = Literal["open", "in_progress", "resolved", "false_positive", "closed"]


@router.post("", response_model=IncidentRead, status_code=201)
def incident_create(payload: IncidentCreate, db: Session = Depends(get_db)) -> IncidentRead:
    """Open the SOC case of an event; the case record is auto-filled from
    the event and its risk snapshot."""
    try:
        incident = create_incident(db, payload.alert_group_id)
    except IncidentNotFound as exc:
        raise HTTPException(status_code=404, detail="Event not found") from exc
    except IncidentAlreadyExists as exc:
        raise HTTPException(
            status_code=409, detail="Event already has an incident"
        ) from exc
    except IncidentRiskMissing as exc:
        raise HTTPException(
            status_code=409, detail="Event has no risk assessment yet"
        ) from exc

    db.commit()
    db.refresh(incident)
    return IncidentRead.model_validate(incident)


@router.get("", response_model=IncidentListResponse)
def incident_list(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    status: StatusFilter | None = Query(
        default=None, description="Filter incidents by lifecycle status"
    ),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    """List incidents, newest first; optionally narrowed to one status."""
    total, incidents = list_incidents(db, page=page, size=size, status=status)
    return IncidentListResponse(
        total=total,
        page=page,
        size=size,
        items=[IncidentRead.model_validate(i) for i in incidents],
    )


@router.get("/{incident_id}", response_model=IncidentRead)
def incident_detail(incident_id: str, db: Session = Depends(get_db)) -> IncidentRead:
    """Get one case record with its full lifecycle fields."""
    incident = _load_incident(db, incident_id)
    return IncidentRead.model_validate(incident)


@router.patch("/{incident_id}/status", response_model=IncidentRead)
def incident_transition(
    incident_id: str, payload: IncidentStatusUpdate, db: Session = Depends(get_db)
) -> IncidentRead:
    """Request a lifecycle move; the service state machine decides.

    Invalid moves (e.g. closed -> open) answer 409 Conflict with
    ``Invalid incident status transition: {from} -> {to}``.
    """
    incident = _load_incident(db, incident_id)
    try:
        transition_status(db, incident.id, payload.status)
    except InvalidIncidentTransition as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Invalid incident status transition: {exc.current} -> {exc.target}"
            ),
        ) from exc

    db.commit()
    db.refresh(incident)
    return IncidentRead.model_validate(incident)


def _load_incident(db: Session, incident_id: str) -> Incident:
    try:
        iid = uuid.UUID(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found") from exc

    incident = get_incident(db, iid)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
