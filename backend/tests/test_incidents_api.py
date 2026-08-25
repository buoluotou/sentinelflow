"""Phase 1 Step 7.3: Incident Management API tests.

The API is a thin HTTP layer over services/incidents (no state machine
code here): POST /incidents (201), GET list (paged, created_at DESC),
GET detail, PATCH /incidents/{id}/status (invalid moves -> 409 Conflict).
"""
import time
import uuid
from datetime import datetime, timezone

from app.models import AlertGroup, EventRisk


def _seed_event(db_session, fingerprint: str, score: int = 80, level: str = "high") -> AlertGroup:
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=fingerprint,
        title="SSH login failure detected",
        category="authentication",
        severity="medium",
        first_seen=now,
        last_seen=now,
    )
    db_session.add_all([group, EventRisk(alert_group=group, score=score, level=level)])
    db_session.commit()
    return group


def _open_incident(client, db_session, fingerprint: str) -> dict:
    group = _seed_event(db_session, fingerprint)
    response = client.post(
        "/api/v1/incidents", json={"alert_group_id": str(group.id)}
    )
    assert response.status_code == 201
    return response.json()


# ---------------------------------------------------------------- creation


def test_create_incident_returns_201_with_case_record(client, db_session):
    group = _seed_event(db_session, "a" * 64, score=80, level="high")

    response = client.post(
        "/api/v1/incidents", json={"alert_group_id": str(group.id)}
    )
    assert response.status_code == 201

    body = response.json()
    assert body["alert_group_id"] == str(group.id)
    assert body["title"] == group.title
    assert body["severity"] == group.severity
    assert body["risk_score"] == 80  # snapshot from EventRisk
    assert body["status"] == "open"
    assert body["disposition"] is None
    assert body["description"]
    assert body["resolved_at"] is None
    assert body["closed_at"] is None
    assert body["created_at"] and body["updated_at"]


def test_create_duplicate_incident_returns_409(client, db_session):
    group = _seed_event(db_session, "a" * 64)
    first = client.post("/api/v1/incidents", json={"alert_group_id": str(group.id)})
    assert first.status_code == 201

    second = client.post("/api/v1/incidents", json={"alert_group_id": str(group.id)})
    assert second.status_code == 409


def test_create_incident_unknown_group_returns_404(client):
    response = client.post(
        "/api/v1/incidents", json={"alert_group_id": str(uuid.uuid4())}
    )
    assert response.status_code == 404


def test_create_incident_without_risk_returns_409(client, db_session):
    """A missing risk assessment is a pipeline conflict, not a 404 case —
    and the API must never fall back to a silent score=0 incident."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="b" * 64,
        title="File integrity change",
        category="integrity",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.commit()

    response = client.post(
        "/api/v1/incidents", json={"alert_group_id": str(group.id)}
    )
    assert response.status_code == 409


# ------------------------------------------------------------------- list


def test_list_incidents_paginated_newest_first(client, db_session):
    oldest = _open_incident(client, db_session, "a" * 64)
    time.sleep(1.05)  # SQLite CURRENT_TIMESTAMP has second granularity
    middle = _open_incident(client, db_session, "b" * 64)
    time.sleep(1.05)
    newest = _open_incident(client, db_session, "c" * 64)

    first_page = client.get("/api/v1/incidents", params={"page": 1, "size": 2}).json()
    assert first_page["total"] == 3
    assert [i["id"] for i in first_page["items"]] == [newest["id"], middle["id"]]

    second_page = client.get("/api/v1/incidents", params={"page": 2, "size": 2}).json()
    assert [i["id"] for i in second_page["items"]] == [oldest["id"]]


def test_list_incidents_filter_by_status(client, db_session):
    kept = _open_incident(client, db_session, "a" * 64)
    _open_incident(client, db_session, "b" * 64)
    client.patch(f"/api/v1/incidents/{kept['id']}/status", json={"status": "in_progress"})

    filtered = client.get("/api/v1/incidents", params={"status": "in_progress"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["id"] == kept["id"]


def test_list_incidents_invalid_status_filter_returns_422(client):
    response = client.get("/api/v1/incidents", params={"status": "archived"})
    assert response.status_code == 422


# ----------------------------------------------------------------- detail


def test_get_incident_detail_returns_full_record(client, db_session):
    created = _open_incident(client, db_session, "a" * 64)

    response = client.get(f"/api/v1/incidents/{created['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body == created
    for field in (
        "id",
        "alert_group_id",
        "title",
        "description",
        "severity",
        "risk_score",
        "status",
        "disposition",
        "created_at",
        "updated_at",
        "resolved_at",
        "closed_at",
    ):
        assert field in body


def test_get_incident_unknown_returns_404(client):
    assert client.get(f"/api/v1/incidents/{uuid.uuid4()}").status_code == 404


def test_get_incident_invalid_uuid_returns_404(client):
    assert client.get("/api/v1/incidents/not-a-uuid").status_code == 404


# -------------------------------------------------------- status endpoint


def test_transition_open_to_in_progress_returns_200(client, db_session):
    incident = _open_incident(client, db_session, "a" * 64)

    response = client.patch(
        f"/api/v1/incidents/{incident['id']}/status", json={"status": "in_progress"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"

    # persisted: the detail endpoint agrees
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "in_progress"


def test_transition_invalid_move_returns_409_with_detail(client, db_session):
    incident = _open_incident(client, db_session, "a" * 64)
    client.patch(f"/api/v1/incidents/{incident['id']}/status", json={"status": "closed"})

    response = client.patch(
        f"/api/v1/incidents/{incident['id']}/status", json={"status": "open"}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Invalid incident status transition: closed -> open"
    )

    # untouched: still closed
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "closed"


def test_transition_unknown_vocabulary_returns_409(client, db_session):
    incident = _open_incident(client, db_session, "a" * 64)

    response = client.patch(
        f"/api/v1/incidents/{incident['id']}/status", json={"status": "archived"}
    )
    assert response.status_code == 409


def test_transition_unknown_incident_returns_404(client):
    response = client.patch(
        f"/api/v1/incidents/{uuid.uuid4()}/status", json={"status": "closed"}
    )
    assert response.status_code == 404


def test_transition_updates_lifecycle_fields_in_response(client, db_session):
    incident = _open_incident(client, db_session, "a" * 64)
    incident_id = incident["id"]

    client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "in_progress"})
    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "resolved"}
    ).json()
    assert resolved["status"] == "resolved"
    assert resolved["disposition"] == "resolved"
    assert resolved["resolved_at"] is not None
    assert resolved["closed_at"] is None

    closed = client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "closed"}
    ).json()
    assert closed["status"] == "closed"
    assert closed["disposition"] == "resolved"  # preserved through close
    assert closed["closed_at"] is not None
