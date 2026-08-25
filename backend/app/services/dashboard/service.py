"""Dashboard aggregation service (Phase 1 Step 7.5).

Pure real-time aggregation for the Web Console home page — no new tables,
no caching: the console binds ONE endpoint instead of stitching
/events + /incidents + risk math on the client.

Frozen metric semantics:
- open_incidents / critical|high|medium_incidents
    ACTIVE cases only: status in (open, in_progress); the severity
    counters break those active cases down.
- today_alerts / today_events
    created since today 00:00 UTC.
- risk_distribution
    current EventRisk.level over ALL events (events without a risk
    snapshot contribute nothing).
"""
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AlertGroup, EventRisk, Incident

#: Lifecycle positions that count as an active SOC queue item.
ACTIVE_STATUSES = ("open", "in_progress")

RISK_LEVELS = ("critical", "high", "medium", "low")


def _today_start(now: datetime) -> datetime:
    """Today 00:00 UTC (aware; compares correctly against both SQLite's
    naive-UTC storage and PostgreSQL timestamptz)."""
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def get_summary(db: Session) -> dict:
    """Aggregate the dashboard snapshot; shaped exactly like the API
    response so the HTTP layer only wraps it in a schema."""
    now = datetime.now(timezone.utc)
    today_start = _today_start(now)

    active = Incident.status.in_(ACTIVE_STATUSES)
    open_incidents = db.execute(
        select(func.count(Incident.id)).where(active)
    ).scalar_one()

    def _active_by_severity(severity: str) -> int:
        return db.execute(
            select(func.count(Incident.id)).where(active, Incident.severity == severity)
        ).scalar_one()

    today_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= today_start)
    ).scalar_one()
    today_events = db.execute(
        select(func.count(AlertGroup.id)).where(AlertGroup.created_at >= today_start)
    ).scalar_one()

    risk_distribution = {level: 0 for level in RISK_LEVELS}
    rows = db.execute(
        select(EventRisk.level, func.count(EventRisk.id)).group_by(EventRisk.level)
    ).all()
    for level, count in rows:
        if level in risk_distribution:  # ignore any future unknown level
            risk_distribution[level] = count

    return {
        "open_incidents": open_incidents,
        "critical_incidents": _active_by_severity("critical"),
        "high_incidents": _active_by_severity("high"),
        "medium_incidents": _active_by_severity("medium"),
        "today_alerts": today_alerts,
        "today_events": today_events,
        "risk_distribution": risk_distribution,
    }
