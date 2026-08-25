"""Query service exposing aggregated AlertGroups as security events.

Phase 1 Step 4.4: the Events API is the read-side view of deduplication —
one AlertGroup == one security event, consumed by the Web Console, SOC
analysts and (later) the AI risk engine.

Phase 1 Step 5.4: the read path stays pure — risk data is JOINed from the
pre-computed event_risk table, never recalculated here.
"""
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import AlertGroup, EventRisk

MAX_PAGE_SIZE = 100


def list_events(
    db: Session,
    page: int = 1,
    size: int = 20,
    level: str | None = None,
) -> tuple[int, list[AlertGroup]]:
    """Return (total, page of groups) ordered by most recently seen first.

    With ``level`` set, only events whose current risk matches that level are
    returned (events without a risk record are excluded).
    """
    total_stmt = select(func.count()).select_from(AlertGroup)
    stmt = select(AlertGroup).options(selectinload(AlertGroup.risk))
    if level is not None:
        total_stmt = total_stmt.join(EventRisk).where(EventRisk.level == level)
        stmt = stmt.join(EventRisk).where(EventRisk.level == level)

    total = db.execute(total_stmt).scalar_one()
    stmt = (
        stmt.order_by(AlertGroup.last_seen.desc(), AlertGroup.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )
    groups = list(db.execute(stmt).scalars().all())
    return total, groups


def get_event(db: Session, group_id: uuid.UUID) -> AlertGroup | None:
    """Return one group with its evidence alerts and risk eagerly loaded."""
    stmt = (
        select(AlertGroup)
        .options(
            selectinload(AlertGroup.alerts),
            selectinload(AlertGroup.risk),
        )
        .where(AlertGroup.id == group_id)
    )
    return db.execute(stmt).scalar_one_or_none()
