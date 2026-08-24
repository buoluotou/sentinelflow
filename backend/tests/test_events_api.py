"""Phase 1 Step 4.4: Events API tests.

Covers GET /api/v1/events (list + pagination) and GET /api/v1/events/{id}
(detail + evidence alerts), plus the unified dedup behaviour of
POST /api/v1/alerts.
"""
import uuid


def _ssh_payload(source_ip: str = "10.10.10.5") -> dict:
    return {
        "source": "scenario-simulator",
        "event_type": "ssh_failed_login",
        "severity": "medium",
        "timestamp": "2026-08-24T10:30:00Z",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": source_ip,
        "user": "root",
        "message": "Multiple SSH login failures detected",
        "raw_data": {"attempts": 8},
    }


def _post_alerts(client, payload: dict, times: int = 1) -> list[dict]:
    bodies = []
    for _ in range(times):
        response = client.post("/api/v1/alerts", json=payload)
        assert response.status_code == 201
        bodies.append(response.json())
    return bodies


def test_case1_100_alerts_collapse_into_one_event(client):
    _post_alerts(client, _ssh_payload(), times=100)

    response = client.get("/api/v1/events")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    event = body["items"][0]
    assert event["alert_count"] == 100
    assert event["title"] == "SSH login failure detected"
    assert event["category"] == "authentication"
    assert event["severity"] == "medium"
    assert event["status"] == "open"


def test_case2_event_detail_returns_all_evidence(client, db_session):
    _post_alerts(client, _ssh_payload(), times=100)

    from app.models import AlertGroup

    group_id = db_session.query(AlertGroup).first().id
    response = client.get(f"/api/v1/events/{group_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["event"]["id"] == str(group_id)
    assert body["event"]["alert_count"] == 100
    assert len(body["event"]["fingerprint"]) == 64
    assert len(body["alerts"]) == 100
    assert all(a["source"] == "scenario-simulator" for a in body["alerts"])


def test_case3_missing_or_malformed_event_returns_404(client):
    assert client.get("/api/v1/events/random").status_code == 404
    assert client.get(f"/api/v1/events/{uuid.uuid4()}").status_code == 404


def test_events_list_pagination(client):
    # three distinct actors -> three distinct events
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _post_alerts(client, _ssh_payload(ip))

    page1 = client.get("/api/v1/events?page=1&size=2").json()
    page2 = client.get("/api/v1/events?page=2&size=2").json()
    assert page1["total"] == 3 and len(page1["items"]) == 2
    assert page2["total"] == 3 and len(page2["items"]) == 1
    assert client.get("/api/v1/events?size=101").status_code == 422
    assert client.get("/api/v1/events?page=0").status_code == 422


def test_post_alerts_now_shares_dedup_with_normalize(client, db_session):
    """Both entry points aggregate into the SAME group when the identity
    matches (same source/category/title/asset/actor)."""
    from app.models import AlertGroup

    # entry point A: unified payload (source matches the adapter identity)
    payload = _ssh_payload()
    payload["source"] = "simulator"
    _post_alerts(client, payload, times=2)
    # entry point B: raw simulator event through normalization
    raw = {
        "event_type": "ssh_failed_login",
        "severity": "medium",
        "timestamp": "2026-08-24T10:30:30Z",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": "10.10.10.5",
        "user": "root",
        "raw_data": {"attempts": 8},
    }
    normalize_response = client.post(
        "/api/v1/normalize", json={"source": "simulator", "raw_data": raw}
    )
    assert normalize_response.status_code == 200

    groups = db_session.query(AlertGroup).all()
    assert len(groups) == 1
    assert groups[0].alert_count == 3


def test_post_alerts_response_exposes_group_link(client):
    body = _post_alerts(client, _ssh_payload())[0]
    assert body["alert_group_id"] is not None
