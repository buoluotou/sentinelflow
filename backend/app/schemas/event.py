"""Schemas for the security events API (Phase 1 Step 4.4).

An "event" is the SOC-facing view of an AlertGroup: one aggregated
security event with N evidence alerts.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EventListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    category: str
    severity: str
    status: str
    alert_count: int
    first_seen: datetime
    last_seen: datetime


class EventListResponse(BaseModel):
    total: int
    page: int
    size: int
    items: list[EventListItem]


class EventAlertItem(BaseModel):
    """One evidence alert belonging to an event."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    event_type: str
    severity: str
    title: str | None = None
    host_name: str | None = None
    source_ip: str | None = None
    created_at: datetime


class EventInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    fingerprint: str
    title: str
    category: str
    severity: str
    status: str
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class EventDetailResponse(BaseModel):
    """GET /events/{id}: event summary + its evidence alerts."""

    event: EventInfo
    alerts: list[EventAlertItem]
