"""Phase 1 Step 7.4: automatic incident creation from risk events.

Integration point: the deduplication pipeline. After every risk
recalculation the creation policy decides:

    EventRisk.score >= AUTO_CREATE_THRESHOLD (70)  ->  open Incident
    otherwise                                      ->  event only

Coverage: policy table, auto-create / no-create through the real
ingestion path, idempotency (100 alerts -> 1 group -> 1 incident),
threshold crossing on a later alert, and the already-exists guard.
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models import AlertGroup, EventRisk, Incident
from app.services.incidents import IncidentAlreadyExists, create_incident
from app.services.incidents.policy import (
    AUTO_CREATE_THRESHOLD,
    should_create_incident,
)


def _payload(severity: str, event_type: str = "scenario_event") -> dict:
    return {
        "source": "scenario-simulator",
        "event_type": event_type,
        "severity": severity,
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": "10.0.0.55",  # internal actor: no public-source bonus
        "message": "auto-create scenario",
    }


# -------------------------------------------------------------- the policy


def test_threshold_is_frozen_at_70():
    assert AUTO_CREATE_THRESHOLD == 70


@pytest.mark.parametrize(
    ("score", "expected"),
    [(69, False), (70, True), (71, True), (90, True), (100, True)],
)
def test_policy_boundary(score, expected):
    assert should_create_incident(score) is expected


# ----------------------------------------------- pipeline auto-creation


def test_high_risk_event_auto_creates_incident(client):
    """critical (70) + internal source -> score 70 >= threshold."""
    response = client.post("/api/v1/alerts", json=_payload("critical"))
    assert response.status_code == 201

    incidents = client.get("/api/v1/incidents").json()
    assert incidents["total"] == 1
    incident = incidents["items"][0]
    assert incident["status"] == "open"
    assert incident["risk_score"] == 70
    assert incident["alert_group_id"] == response.json()["alert_group_id"]


def test_low_risk_event_creates_no_incident(client):
    """low (10) stays far below the threshold: event only."""
    response = client.post("/api/v1/alerts", json=_payload("low"))
    assert response.status_code == 201

    assert client.get("/api/v1/incidents").json()["total"] == 0
    # the event and its risk snapshot still exist — only the case is skipped
    events = client.get("/api/v1/events").json()
    assert events["total"] == 1
    assert events["items"][0]["risk_score"] == 10


def test_100_repeated_alerts_yield_exactly_one_incident(client):
    """Idempotency: 100 alerts -> 1 group -> 1 incident, never 100."""
    for _ in range(100):
        response = client.post("/api/v1/alerts", json=_payload("critical"))
        assert response.status_code == 201

    events = client.get("/api/v1/events").json()
    assert events["total"] == 1
    assert events["items"][0]["alert_count"] == 100

    incidents = client.get("/api/v1/incidents").json()
    assert incidents["total"] == 1
    # snapshot taken at the FIRST crossing: 70 + frequency bonus at creation
    assert incidents["items"][0]["risk_score"] == 70


def test_incident_created_when_threshold_crossed_later(client):
    """high (50) starts below the threshold; the frequency bonus (+20 at
    alert_count 21) crosses it and the pipeline opens the case then."""
    for i in range(20):
        client.post("/api/v1/alerts", json=_payload("high"))
    assert client.get("/api/v1/incidents").json()["total"] == 0

    client.post("/api/v1/alerts", json=_payload("high"))  # 21st: 50+20=70
    incidents = client.get("/api/v1/incidents").json()
    assert incidents["total"] == 1
    assert incidents["items"][0]["risk_score"] == 70


def test_manual_create_after_auto_create_is_rejected(client, db_session):
    """The pipeline's case occupies the unique slot — manual creation of
    the same event must fail with the business error (API maps to 409)."""
    client.post("/api/v1/alerts", json=_payload("critical"))
    group_id = uuid.UUID(client.get("/api/v1/events").json()["items"][0]["id"])

    with pytest.raises(IncidentAlreadyExists):
        create_incident(db_session, group_id)

    # and via the API as well
    response = client.post(
        "/api/v1/incidents", json={"alert_group_id": str(group_id)}
    )
    assert response.status_code == 409


# ------------------------------------------------ legacy events untouched


def test_policy_does_not_backfill_existing_groups():
    """The policy runs on the write path only: an AlertGroup seeded
    directly (no pipeline) with high risk gets no incident by itself."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        group = AlertGroup(
            fingerprint="c" * 64,
            title="legacy event",
            category="authentication",
            severity="critical",
            first_seen=now,
            last_seen=now,
        )
        session.add_all([group, EventRisk(alert_group=group, score=90, level="high")])
        session.commit()

        assert group.incident is None  # no automatic backfill happened
    finally:
        session.close()
        engine.dispose()
