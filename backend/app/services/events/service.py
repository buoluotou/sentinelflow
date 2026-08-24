"""Query service exposing aggregated AlertGroups as security events.

Phase 1 Step 4.4: the Events API is the read-side view of deduplication —
one AlertGroup == one security event, consumed by the Web Console, SOC
analysts and (later) the AI risk engine.
"""
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import AlertGroup

MAX_PAGE_SIZE = 100


def list_events(
    db: Session, page: int = 1, size: int = 20
) -> tuple[int, list[AlertGroup]]:
    """Return (total, page of groups) ordered by most recently seen first."""
    total = db.execute(select(func.count()).select_from(AlertGroup)).scalar_one()
    stmt = (
        select(AlertGroup)
        .order_by(AlertGroup.last_seen.desc(), AlertGroup.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )
    groups = list(db.execute(stmt).scalars().all())
    return total, groups


def get_event(db: Session, group_id: uuid.UUID) -> AlertGroup | None:
    """Return one group with its evidence alerts eagerly loaded."""
    stmt = (
        select(AlertGroup)
        .options(selectinload(AlertGroup.alerts))
        .where(AlertGroup.id == group_id)
    )
    return db.execute(stmt).scalar_one_or_none()
