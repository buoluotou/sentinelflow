from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent
from app.schemas.alert import AlertCreate


def ingest_alert(db: Session, payload: AlertCreate) -> Alert:
    """Ingest one raw security event into SentinelFlow.

    Phase 1 Step 2 behaviour: every accepted event creates a new Alert with a
    single AlertEvent attached. Deduplication / aggregation (Step 4) will
    later merge events into existing Alerts instead.
    """
    event_time = payload.timestamp or datetime.now(timezone.utc)

    alert = Alert(
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity.value,
        status="open",
        title=payload.title,
        message=payload.message,
        host_name=payload.host.hostname if payload.host else None,
        host_ip=payload.host.ip if payload.host else None,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        user_name=payload.user,
        first_seen_at=event_time,
        last_seen_at=event_time,
        event_count=1,
    )

    # Always keep the original event for auditability; when the sender did not
    # provide an explicit raw_data block, persist the full original payload.
    raw_data = payload.raw_data
    if raw_data is None:
        raw_data = payload.model_dump(mode="json")

    event = AlertEvent(
        source=payload.source,
        event_type=payload.event_type,
        event_timestamp=event_time,
        raw_data=raw_data,
    )
    alert.events.append(event)

    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
