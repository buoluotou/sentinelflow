import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HostInfo(BaseModel):
    hostname: str | None = None
    ip: str | None = None


class AlertCreate(BaseModel):
    """Unified alert payload accepted by POST /api/v1/alerts."""

    source: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    severity: Severity = Severity.MEDIUM
    timestamp: datetime | None = None

    title: str | None = Field(default=None, max_length=512)
    message: str | None = None

    host: HostInfo | None = None
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    user: str | None = Field(default=None, max_length=255)

    raw_data: dict | None = None


class AlertEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    event_type: str
    event_timestamp: datetime
    raw_data: dict | None = None
    created_at: datetime


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    event_type: str
    severity: str
    status: str
    title: str | None = None
    message: str | None = None

    alert_group_id: uuid.UUID | None = None

    host_name: str | None = None
    host_ip: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user_name: str | None = None

    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int

    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertRead):
    """Alert with its contributing raw events."""

    events: list[AlertEventRead] = []
