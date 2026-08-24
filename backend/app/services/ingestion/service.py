from app.models import Alert
from app.schemas.alert import AlertCreate
from app.services.deduplication import engine as dedup_engine
from app.services.normalization.adapters.simulator import EVENT_TYPE_MAP
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
)

from sqlalchemy.orm import Session


def ingest_alert(db: Session, payload: AlertCreate) -> Alert:
    """Ingest one unified alert into SentinelFlow.

    Phase 1 Step 4.4 behaviour: every entry point (this one and
    POST /api/v1/normalize) flows through the same
    Normalization -> Deduplication -> DB pipeline, so repeated alerts are
    aggregated into one AlertGroup while every event stays as evidence.
    """
    normalized = _to_normalized(payload)
    result = dedup_engine.process(db, normalized, payload)
    return result.alert


def _to_normalized(payload: AlertCreate) -> NormalizedAlert:
    """Map an already-unified AlertCreate onto the normalized model.

    Category and the title fallback come from the shared event-type map so
    that this entry point produces the SAME fingerprint as the adapter-based
    /normalize path for identical events. Unknown types fall back to GENERIC.
    """
    mapped = EVENT_TYPE_MAP.get(payload.event_type)
    category = mapped[0] if mapped else Category.GENERIC
    mapped_title = mapped[2] if mapped else None

    asset = None
    if payload.host and (payload.host.hostname or payload.host.ip):
        asset = AssetInfo(hostname=payload.host.hostname, ip=payload.host.ip)

    actor = None
    if payload.source_ip or payload.user:
        actor = ActorInfo(ip=payload.source_ip, user=payload.user)

    return NormalizedAlert(
        event_type=payload.event_type,
        source=payload.source,
        category=category,
        severity=payload.severity,
        title=payload.title or mapped_title or payload.event_type,
        description=payload.message,
        asset=asset,
        actor=actor,
        raw_event=payload.raw_data or {},
    )
