"""Unified normalized alert model.

Every adapter converts source-specific raw events into this structure so
downstream services (deduplication, correlation, risk) only ever deal with
one schema.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from app.schemas.alert import Severity


class Category(str, Enum):
    """High level security category used for correlation and filtering."""

    AUTHENTICATION = "authentication"
    FILE_INTEGRITY = "file_integrity"
    WEB = "web"
    PROCESS = "process"
    THREAT_INTEL = "threat_intel"
    GENERIC = "generic"


class AssetInfo(BaseModel):
    """The protected asset the event happened on."""

    hostname: str | None = None
    ip: str | None = None


class ActorInfo(BaseModel):
    """The (suspected) actor causing the event."""

    ip: str | None = None
    user: str | None = None


class Observable(BaseModel):
    """A single extracted indicator/observable."""

    type: str = Field(description="ip | hostname | user | file | process | hash | domain | url")
    value: str


class NormalizedAlert(BaseModel):
    """SentinelFlow unified event model."""

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: str = Field(default="unknown", description="Original event type as reported by the source")
    source: str
    category: Category
    severity: Severity = Severity.MEDIUM
    title: str
    description: str | None = None

    asset: AssetInfo | None = None
    actor: ActorInfo | None = None
    observables: list[Observable] = Field(default_factory=list)

    raw_event: dict = Field(default_factory=dict)
    normalized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
