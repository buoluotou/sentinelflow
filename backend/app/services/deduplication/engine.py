"""Deduplication engine: aggregates normalized alerts into AlertGroups.

Phase 1 Step 4.3 flow:

    NormalizedAlert
        -> FingerprintGenerator  (stable SHA256 identity)
        -> find active AlertGroup (same fingerprint, within window)
            ├── hit  -> alert_count++, last_seen updated, Alert linked
            └── miss -> new AlertGroup created, Alert linked

Every individual alert is persisted as evidence; the group is the
SOC-facing "one security event" view.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, AlertGroup
from app.schemas.alert import AlertCreate
from app.services.deduplication.fingerprint import FingerprintGenerator
from app.services.deduplication.models import DeduplicationResult
from app.services.deduplication.rules import DEFAULT_RULE, AggregationRule
from app.services.normalization.models import NormalizedAlert


def _ensure_aware(dt: datetime) -> datetime:
    """SQLite drops tzinfo on read-back; treat naive datetimes as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class DeduplicationEngine:
    """Aggregates repeated alerts into AlertGroups based on fingerprint +
    time window."""

    def __init__(self, rule: AggregationRule = DEFAULT_RULE):
        self._rule = rule

    def process(
        self,
        db: Session,
        normalized: NormalizedAlert,
        alert_create: AlertCreate,
    ) -> DeduplicationResult:
        """Process one normalized alert: link it to an active group or open
        a new one, persist the alert as evidence and commit."""
        fingerprint = FingerprintGenerator.generate(normalized)
        event_time = _ensure_aware(
            alert_create.timestamp or datetime.now(timezone.utc)
        )

        group = self._find_active_group(db, fingerprint, event_time)
        created_group = group is None

        if created_group:
            group = AlertGroup(
                fingerprint=fingerprint,
                title=normalized.title,
                category=normalized.category.value,
                severity=alert_create.severity.value,
                alert_count=1,
                first_seen=event_time,
                last_seen=event_time,
            )
            db.add(group)
        else:
            group.alert_count += 1
            group.last_seen = max(_ensure_aware(group.last_seen), event_time)

        alert = self._build_alert(alert_create, event_time, group)
        db.add(alert)
        db.commit()
        db.refresh(group)
        db.refresh(alert)
        return DeduplicationResult(
            group=group, alert=alert, created_group=created_group
        )

    def _find_active_group(
        self, db: Session, fingerprint: str, event_time: datetime
    ) -> AlertGroup | None:
        """Latest group with this fingerprint still inside the window."""
        cutoff = event_time - timedelta(seconds=self._rule.window_seconds)
        return (
            db.query(AlertGroup)
            .filter(
                AlertGroup.fingerprint == fingerprint,
                AlertGroup.last_seen >= cutoff,
            )
            .order_by(AlertGroup.last_seen.desc())
            .first()
        )

    @staticmethod
    def _build_alert(
        payload: AlertCreate, event_time: datetime, group: AlertGroup
    ) -> Alert:
        """Build the evidence Alert (same mapping as ingestion; will be
        consolidated when the ingestion flow is rewired in Step 4.4)."""
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
            alert_group=group,
        )
        alert.events.append(
            AlertEvent(
                source=payload.source,
                event_type=payload.event_type,
                event_timestamp=event_time,
                raw_data=payload.raw_data
                or payload.model_dump(mode="json"),
            )
        )
        return alert


#: engine shared by the API layer (wired in Step 4.4)
engine = DeduplicationEngine()
