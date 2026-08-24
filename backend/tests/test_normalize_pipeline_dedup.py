"""Phase 1 Step 4.3: end-to-end Normalize -> Deduplication -> DB pipeline.

Exercises POST /api/v1/normalize, which now routes every normalized alert
through the DeduplicationEngine.
"""

from app.models import Alert, AlertGroup


def _ssh_event(source_ip: str = "10.0.0.55") -> dict:
    return {
        "event_type": "ssh_failed_login",
        "severity": "medium",
        "timestamp": "2026-08-24T10:30:00Z",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": source_ip,
        "user": "root",
        "message": "Multiple SSH login failures detected",
        "raw_data": {"attempts": 8},
    }


def _post(client, raw: dict):
    return client.post(
        "/api/v1/normalize", json={"source": "simulator", "raw_data": raw}
    )


def test_repeated_events_aggregate_into_one_group(client):
    first = _post(client, _ssh_event())
    assert first.status_code == 200
    body1 = first.json()
    assert body1["created_group"] is True
    assert body1["group_alert_count"] == 1

    counts = []
    alert_ids = [body1["alert_id"]]
    for _ in range(4):
        body = _post(client, _ssh_event()).json()
        assert body["created_group"] is False
        assert body["group_id"] == body1["group_id"]
        counts.append(body["group_alert_count"])
        alert_ids.append(body["alert_id"])

    assert counts == [2, 3, 4, 5]
    # every event still gets its own evidence alert
    assert len(set(alert_ids)) == 5


def test_repeated_events_db_state(client, db_session):
    for _ in range(10):
        assert _post(client, _ssh_event()).status_code == 200

    groups = db_session.query(AlertGroup).all()
    assert len(groups) == 1
    assert groups[0].alert_count == 10
    assert db_session.query(Alert).count() == 10
    assert all(a.alert_group_id == groups[0].id for a in db_session.query(Alert))


def test_different_actors_create_separate_groups(client, db_session):
    body_a = _post(client, _ssh_event("10.10.10.5")).json()
    body_b = _post(client, _ssh_event("10.10.10.6")).json()

    assert body_a["created_group"] is True
    assert body_b["created_group"] is True
    assert body_a["group_id"] != body_b["group_id"]
    assert db_session.query(AlertGroup).count() == 2


def test_different_scenarios_create_separate_groups(client, db_session):
    _post(client, _ssh_event())
    ioc = _post(
        client,
        {
            "event_type": "malicious_ioc",
            "host": {"hostname": "db-server-01", "ip": "192.168.1.50"},
            "source_ip": "198.51.100.77",
            "message": "Outbound connection to known C2 server",
            "raw_data": {"ioc_type": "ip", "ioc_value": "198.51.100.77"},
        },
    )
    assert ioc.status_code == 200

    groups = db_session.query(AlertGroup).all()
    assert len(groups) == 2
    assert {g.category for g in groups} == {"authentication", "threat_intel"}
