"""Pydantic schemas of the Incident Management API (Phase 1 Step 7.3)."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentCreate(BaseModel):
    """POST /incidents — only the event is given; the case record
    (title/severity/description/risk_score) is auto-filled by the service."""

    alert_group_id: uuid.UUID


class IncidentStatusUpdate(BaseModel):
    """PATCH /incidents/{id}/status — deliberately an explicit action route,
    not a generic PATCH: ``status`` here is a requested MOVE, validated by
    the service-layer state machine (unknown vocabulary -> 409, not 422)."""

    status: str


class IncidentRead(BaseModel):
    """Full case record as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_group_id: uuid.UUID
    title: str
    description: str | None
    severity: str
    risk_score: int
    status: str
    disposition: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None


class IncidentListResponse(BaseModel):
    """GET /incidents — paged, newest first."""

    total: int
    page: int
    size: int
    items: list[IncidentRead]
