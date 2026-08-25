"""Phase 1 Step 7.1: Incident data model tests.

An Incident is the SOC case layered on top of one AlertGroup ("event"):
Alert -> AlertGroup -> EventRisk (automatic) -> Incident (analyst case).
The state machine itself is Step 7.2; here we verify the data model only.
"""
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import AlertGroup, EventRisk, Incident

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


def _make_incident(group: AlertGroup, **overrides) -> Incident:
    # ORM pitfall guard: assign the relationship OBJECT, not group.id.
    fields = dict(
        alert_group=group,
        title=group.title,
        severity=group.severity,
        risk_score=80,
    )
    fields.update(overrides)
    return Incident(**fields)


def test_incident_creation_defaults(db_session):
    group = _make_group()
    incident = _make_incident(group)
    db_session.add_all([group, incident])
    db_session.commit()
    db_session.refresh(incident)

    assert incident.id is not None
    assert incident.alert_group_id == group.id
    assert incident.status == "open"
    assert incident.risk_score == 80
    assert incident.description is None
    assert incident.disposition is None
    assert incident.resolved_at is None
    assert incident.closed_at is None
    assert incident.created_at is not None
    assert incident.updated_at is not None


def test_incident_case_record_roundtrip(db_session):
    group = _make_group()
    incident = _make_incident(
        group,
        description="Analyst notes: brute force from 8.8.8.8",
        severity="high",
        risk_score=90,
        disposition="contained",
    )
    db_session.add_all([group, incident])
    db_session.commit()
    db_session.refresh(incident)

    assert incident.description == "Analyst notes: brute force from 8.8.8.8"
    assert incident.severity == "high"
    assert incident.risk_score == 90
    assert incident.disposition == "contained"


def test_group_links_to_incident_one_to_one(db_session):
    group = _make_group()
    db_session.add_all([group, _make_incident(group, risk_score=50)])
    db_session.commit()
    db_session.refresh(group)

    assert group.incident is not None
    assert group.incident.risk_score == 50
    assert group.incident.status == "open"


def test_group_without_incident_still_works(db_session):
    group = _make_group()
    db_session.add(group)
    db_session.commit()
    db_session.refresh(group)

    assert group.incident is None


def test_one_current_incident_per_event(db_session):
    """alert_group_id is unique: one event has at most one current case."""
    group = _make_group()
    db_session.add_all([group, _make_incident(group)])
    db_session.commit()

    with pytest.raises(IntegrityError):
        db_session.add(_make_incident(group, title="duplicate case"))
        db_session.flush()
    db_session.rollback()

    assert db_session.query(Incident).count() == 1


def test_distinct_events_each_get_their_own_incident(db_session):
    group_a = _make_group(FINGERPRINT_A)
    group_b = _make_group(FINGERPRINT_B)
    db_session.add_all(
        [
            group_a,
            group_b,
            _make_incident(group_a, risk_score=90),
            _make_incident(group_b, risk_score=25),
        ]
    )
    db_session.commit()

    assert db_session.query(Incident).count() == 2


def test_lifecycle_checkpoints_are_settable(db_session):
    """resolved_at / closed_at stay NULL until the matching transition."""
    group = _make_group()
    incident = _make_incident(group)
    db_session.add_all([group, incident])
    db_session.commit()

    now = datetime.now(timezone.utc)
    incident.status = "resolved"
    incident.resolved_at = now
    db_session.commit()
    db_session.refresh(incident)

    assert incident.status == "resolved"
    assert incident.resolved_at is not None
    assert incident.closed_at is None


def test_incident_coexists_with_risk_on_same_event(db_session):
    """EventRisk (automatic) and Incident (analyst case) are independent
    1:1 layers of the same event; risk_score is a snapshot, not a link."""
    group = _make_group()
    db_session.add_all(
        [
            group,
            EventRisk(alert_group=group, score=80, level="high"),
            _make_incident(group, risk_score=80),
        ]
    )
    db_session.commit()
    db_session.refresh(group)

    assert group.risk is not None and group.risk.score == 80
    assert group.incident is not None and group.incident.risk_score == 80

    # Rescoring the live assessment must NOT touch the case snapshot.
    group.risk.score = 90
    db_session.commit()
    db_session.refresh(group)
    assert group.incident.risk_score == 80


def test_deleting_group_cascades_to_incident(db_session):
    group = _make_group()
    db_session.add_all([group, _make_incident(group)])
    db_session.commit()

    db_session.delete(group)
    db_session.commit()
    assert db_session.query(Incident).count() == 0


def test_updated_at_refreshes_on_change(db_session):
    group = _make_group()
    incident = _make_incident(group)
    db_session.add_all([group, incident])
    db_session.commit()
    before = incident.updated_at

    time.sleep(0.01)
    incident.status = "in_progress"
    db_session.commit()
    db_session.refresh(incident)

    assert incident.updated_at is not None
    assert incident.updated_at != before
