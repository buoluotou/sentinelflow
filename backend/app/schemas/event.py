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
    # Current risk assessment (Step 5.4) — None for legacy events without
    # a risk record; populated by the API layer from group.risk.
    risk_score: int | None = None
    risk_level: str | None = None


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


class RiskFactorItem(BaseModel):
    """One explainable contribution to the risk score ({name, score, reason})."""

    name: str
    score: int
    reason: str


class EventRiskDetail(BaseModel):
    """Full risk assessment of an event, including the factor breakdown."""

    model_config = ConfigDict(from_attributes=True)

    score: int
    level: str
    factors: list[RiskFactorItem]
    updated_at: datetime


class EventDetailResponse(BaseModel):
    """GET /events/{id}: event summary + evidence alerts + risk detail."""

    event: EventInfo
    alerts: list[EventAlertItem]
    risk: EventRiskDetail | None = None
