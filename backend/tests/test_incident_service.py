"""Phase 1 Step 7.2: Incident Service + lifecycle state machine tests.

Covers the three frozen contracts:
- create_incident: AlertGroup + EventRisk -> Incident snapshot (title /
  severity / risk_score copied, status open); missing group, missing risk
  and duplicate case are all business errors
- transition_status: strict lifecycle matrix, invalid moves raise
  InvalidIncidentTransition (never a silent False)
- timestamp/disposition semantics: resolved_at / closed_at written only on
  the matching transition; status and disposition stay consistent
"""
import uuid
from datetime import datetime, timezone

import pytest

from app.models import AlertGroup, EventRisk, Incident
from app.services.incidents import (
    IncidentAlreadyExists,
    IncidentNotFound,
    IncidentRiskMissing,
    InvalidIncidentTransition,
    create_incident,
    transition_status,
)

FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64


def _make_group(fingerprint: str = FINGERPRINT_A) -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint=fingerprint,
        title="SSH login failure detected",
        category="authentication",
        severity="medium",
        first_seen=now,
        last_seen=now,
    )


def _seed(db_session, fingerprint: str = FINGERPRINT_A, score: int = 80, level: str = "high"):
    """AlertGroup + EventRisk, committed — the minimal createable event."""
    group = _make_group(fingerprint)
    db_session.add_all([group, EventRisk(alert_group=group, score=score, level=level)])
    db_session.commit()
    return group


# ---------------------------------------------------------------- creation


def test_create_incident_fills_case_record_from_event_and_risk(db_session):
    group = _seed(db_session, score=80, level="high")

    incident = create_incident(db_session, group.id)
    db_session.commit()
    db_session.refresh(incident)

    assert incident.alert_group_id == group.id
    assert incident.title == group.title
    assert incident.severity == group.severity
    assert incident.risk_score == 80  # snapshot of EventRisk.score
    assert incident.status == "open"
    assert incident.disposition is None
    assert incident.description  # auto-filled, non-empty
    assert incident.resolved_at is None
    assert incident.closed_at is None


def test_create_incident_snapshot_independent_of_later_rescoring(db_session):
    """EventRisk = 80 -> Incident = 80; rescoring to 90 must not move it."""
    group = _seed(db_session, score=80)

    incident = create_incident(db_session, group.id)
    db_session.commit()

    group.risk.score = 90
    db_session.commit()
    db_session.refresh(incident)
    assert incident.risk_score == 80


def test_create_incident_missing_group_raises(db_session):
    with pytest.raises(IncidentNotFound):
        create_incident(db_session, uuid.uuid4())
    assert db_session.query(Incident).count() == 0


def test_create_incident_without_risk_is_rejected(db_session):
    """No silent score=0 case — a missing risk hides a pipeline problem."""
    group = _make_group()
    db_session.add(group)
    db_session.commit()

    with pytest.raises(IncidentRiskMissing):
        create_incident(db_session, group.id)
    assert db_session.query(Incident).count() == 0


def test_create_duplicate_incident_is_rejected(db_session):
    group = _seed(db_session)
    create_incident(db_session, group.id)
    db_session.commit()

    with pytest.raises(IncidentAlreadyExists):
        create_incident(db_session, group.id)
    assert db_session.query(Incident).count() == 1


# ------------------------------------------------------- valid transitions


@pytest.mark.parametrize(
    "move",
    [
        ("open", "in_progress"),
        ("open", "false_positive"),
        ("open", "closed"),
        ("in_progress", "resolved"),
        ("in_progress", "false_positive"),
        ("in_progress", "closed"),
        ("resolved", "closed"),
        ("false_positive", "closed"),
    ],
)
def test_all_legal_lifecycle_transitions(db_session, move):
    start, target = move
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()
    # Drive the incident to the starting state along a legal path first.
    for step in _path_to(start):
        transition_status(db_session, incident.id, step)

    transition_status(db_session, incident.id, target)
    db_session.commit()
    db_session.refresh(incident)
    assert incident.status == target


def _path_to(status: str) -> list[str]:
    """A legal route from open to the given status (empty for open)."""
    return {
        "open": [],
        "in_progress": ["in_progress"],
        "resolved": ["in_progress", "resolved"],
        "false_positive": ["false_positive"],
        "closed": ["closed"],
    }[status]


def test_full_lifecycle_open_in_progress_resolved_closed(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    for step in ("in_progress", "resolved", "closed"):
        transition_status(db_session, incident.id, step)
        db_session.commit()

    db_session.refresh(incident)
    assert incident.status == "closed"
    assert incident.disposition == "resolved"  # preserved through close
    assert incident.resolved_at is not None
    assert incident.closed_at is not None


def test_full_lifecycle_open_false_positive_closed(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "false_positive")
    transition_status(db_session, incident.id, "closed")
    db_session.commit()

    db_session.refresh(incident)
    assert incident.status == "closed"
    assert incident.disposition == "false_positive"
    assert incident.resolved_at is None
    assert incident.closed_at is not None


# ----------------------------------------------------- invalid transitions


@pytest.mark.parametrize(
    "move",
    [
        ("closed", "open"),
        ("closed", "in_progress"),
        ("resolved", "in_progress"),
        ("resolved", "open"),
        ("false_positive", "open"),
        ("false_positive", "resolved"),
        ("open", "resolved"),  # must go through in_progress
    ],
)
def test_invalid_transitions_raise(db_session, move):
    start, target = move
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()
    for step in _path_to(start):
        transition_status(db_session, incident.id, step)
    db_session.commit()

    with pytest.raises(InvalidIncidentTransition):
        transition_status(db_session, incident.id, target)

    db_session.rollback()
    db_session.refresh(incident)
    assert incident.status == start  # unchanged, no silent failure


def test_transition_to_same_status_is_rejected(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    with pytest.raises(InvalidIncidentTransition):
        transition_status(db_session, incident.id, "open")


def test_transition_unknown_status_raises(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    with pytest.raises(InvalidIncidentTransition):
        transition_status(db_session, incident.id, "archived")


def test_transition_missing_incident_raises(db_session):
    with pytest.raises(IncidentNotFound):
        transition_status(db_session, uuid.uuid4(), "closed")


# ------------------------------------------ timestamps & disposition rules


def test_resolved_at_written_only_on_resolve(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "in_progress")
    db_session.commit()
    db_session.refresh(incident)
    assert incident.resolved_at is None
    assert incident.closed_at is None

    transition_status(db_session, incident.id, "resolved")
    db_session.commit()
    db_session.refresh(incident)
    assert incident.resolved_at is not None
    assert incident.closed_at is None


def test_closed_at_written_only_on_close(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "closed")
    db_session.commit()
    db_session.refresh(incident)
    assert incident.closed_at is not None
    assert incident.resolved_at is None


def test_false_positive_transition_sets_matching_disposition(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "in_progress")
    transition_status(db_session, incident.id, "false_positive")
    db_session.commit()
    db_session.refresh(incident)

    # status and disposition always agree — no contradictions possible
    assert incident.status == "false_positive"
    assert incident.disposition == "false_positive"


def test_resolve_transition_sets_matching_disposition(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "in_progress")
    transition_status(db_session, incident.id, "resolved")
    db_session.commit()
    db_session.refresh(incident)

    assert incident.status == "resolved"
    assert incident.disposition == "resolved"


def test_close_keeps_previous_disposition(db_session):
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    transition_status(db_session, incident.id, "in_progress")
    transition_status(db_session, incident.id, "resolved")
    transition_status(db_session, incident.id, "closed")
    db_session.commit()
    db_session.refresh(incident)

    assert incident.disposition == "resolved"  # close does not overwrite


def test_service_does_not_commit_on_its_own_for_failed_transition(db_session):
    """A rejected transition leaves nothing dirty to commit upstream."""
    group = _seed(db_session)
    incident = create_incident(db_session, group.id)
    db_session.commit()

    with pytest.raises(InvalidIncidentTransition):
        transition_status(db_session, incident.id, "resolved")

    assert not db_session.dirty
