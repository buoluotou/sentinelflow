"""Incident service: case creation + lifecycle state machine.

Phase 1 Step 7.2. Two write operations, both transaction-friendly:

    create_incident     AlertGroup + EventRisk -> open Incident (snapshot)
    transition_status   strict lifecycle moves with checkpoint timestamps

Neither function commits on its own — it flushes and returns, leaving the
transaction boundary to the caller (API layer / Step 7.4 pipeline). This
lets "Event -> Incident" join other writes in one transaction later.

Frozen semantics:
- Incident.risk_score COPIES EventRisk.score at creation (snapshot, not a
  link); live rescoring never touches an open case.
- disposition is set ONLY by transitions, always agreeing with the status:
  resolved -> "resolved", false_positive -> "false_positive",
  closed -> keeps the previous disposition.
- resolved_at / closed_at are written exactly on the matching transition.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AlertGroup, EventRisk, Incident
from app.services.incidents.models import (
    ALLOWED_TRANSITIONS,
    IncidentAlreadyExists,
    IncidentDisposition,
    IncidentNotFound,
    IncidentRiskMissing,
    IncidentStatus,
    InvalidIncidentTransition,
)

MAX_PAGE_SIZE = 100


def create_incident(db: Session, alert_group_id: uuid.UUID) -> Incident:
    """Open the SOC case of an event; case record auto-filled from it.

    Refuses (business errors, never silent):
    - unknown AlertGroup            -> IncidentNotFound
    - event already has a case      -> IncidentAlreadyExists
    - event has no EventRisk        -> IncidentRiskMissing (a score=0 case
      would mask a broken risk pipeline instead of surfacing it)
    """
    group = db.get(AlertGroup, alert_group_id)
    if group is None:
        raise IncidentNotFound(f"AlertGroup {alert_group_id} does not exist")
    if group.incident is not None:
        raise IncidentAlreadyExists(
            f"AlertGroup {alert_group_id} already has an open incident"
        )
    risk = group.risk
    if risk is None:
        raise IncidentRiskMissing(
            f"AlertGroup {alert_group_id} has no EventRisk snapshot yet"
        )

    incident = Incident(
        alert_group=group,  # relationship object, not the (maybe unflushed) id
        title=group.title,
        description=_case_description(group, risk),
        severity=group.severity,
        risk_score=risk.score,  # snapshot copy — NOT a foreign key
        status=IncidentStatus.OPEN.value,
    )
    db.add(incident)
    db.flush()
    return incident


def transition_status(
    db: Session, incident_id: uuid.UUID, target: str
) -> Incident:
    """Move an incident along the frozen lifecycle matrix.

    Raises InvalidIncidentTransition for unknown vocabulary, self-moves and
    every disallowed edge (e.g. closed -> open) — never returns a silent
    failure. Writes the lifecycle checkpoints:

        -> resolved        resolved_at = now, disposition = "resolved"
        -> false_positive  disposition = "false_positive"
        -> closed          closed_at = now, disposition preserved
    """
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise IncidentNotFound(f"Incident {incident_id} does not exist")

    try:
        target_status = IncidentStatus(target)
    except ValueError:
        raise InvalidIncidentTransition(
            f"'{target}' is not an incident status",
            current=incident.status,
            target=target,
        ) from None

    current = IncidentStatus(incident.status)
    if target_status not in ALLOWED_TRANSITIONS[current]:
        raise InvalidIncidentTransition(
            f"cannot transition from '{current.value}' to '{target_status.value}'",
            current=current.value,
            target=target_status.value,
        )

    incident.status = target_status.value
    now = datetime.now(timezone.utc)

    if target_status is IncidentStatus.RESOLVED:
        incident.resolved_at = now
        incident.disposition = IncidentDisposition.RESOLVED.value
    elif target_status is IncidentStatus.FALSE_POSITIVE:
        incident.disposition = IncidentDisposition.FALSE_POSITIVE.value
    elif target_status is IncidentStatus.CLOSED:
        incident.closed_at = now
        # disposition preserved — close records the previous analyst call
    incident.updated_at = now  # explicit, like RiskService._apply

    db.flush()
    return incident


def get_incident(db: Session, incident_id: uuid.UUID) -> Incident | None:
    """Read one case; None when unknown (the API maps it to 404)."""
    return db.get(Incident, incident_id)


def list_incidents(
    db: Session,
    page: int = 1,
    size: int = 20,
    status: str | None = None,
) -> tuple[int, list[Incident]]:
    """Return (total, page of incidents) newest first.

    Pure read. With ``status`` set, only cases at that lifecycle position
    are returned.
    """
    size = min(size, MAX_PAGE_SIZE)
    total_stmt = select(func.count(Incident.id))
    items_stmt = select(Incident)
    if status is not None:
        total_stmt = total_stmt.where(Incident.status == status)
        items_stmt = items_stmt.where(Incident.status == status)

    total = db.execute(total_stmt).scalar_one()
    items = db.execute(
        items_stmt.order_by(Incident.created_at.desc(), Incident.id.desc())
        .offset((page - 1) * size)
        .limit(size)
    ).scalars().all()
    return total, list(items)


def _case_description(group: AlertGroup, risk: EventRisk) -> str:
    """Auto-filled case record: event context + the explainable risk trail."""
    factor_trail = "; ".join(
        f"{f['name']} +{f['score']} ({f['reason']})" for f in (risk.factors or [])
    )
    # len(alerts), not alert_count: correct even for a group created in the
    # same transaction (the column default applies only at flush time).
    return (
        f"Auto-created from event '{group.title}' "
        f"({len(group.alerts)} alerts, severity {group.severity}). "
        f"Risk snapshot at creation: {risk.score}/{risk.level}"
        + (f" — factors: {factor_trail}." if factor_trail else ".")
    )
