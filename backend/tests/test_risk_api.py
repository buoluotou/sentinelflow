"""Phase 1 Step 5.4: Risk API tests.

The Events API exposes the persisted risk assessment (pure read — scoring
happens only on the write path):
- GET /api/v1/events items carry risk_score / risk_level
- GET /api/v1/events/{id} returns the full factor breakdown
- GET /api/v1/events?level=... filters events by risk level
"""
from app.models import AlertGroup


def _ssh_payload(source_ip: str = "8.8.8.8") -> dict:
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


def _post_alerts(client, payload: dict, times: int = 1) -> None:
    for _ in range(times):
        assert client.post("/api/v1/alerts", json=payload).status_code == 201


def test_list_items_carry_risk_score_and_level(client):
    # 100 medium-severity alerts from a public IP -> 30 + 30 + 20 = 80/high
    _post_alerts(client, _ssh_payload(), times=100)

    body = client.get("/api/v1/events").json()
    item = body["items"][0]
    assert item["risk_score"] == 80
    assert item["risk_level"] == "high"


def test_list_item_risk_is_null_when_no_risk_record(client, db_session):
    # Legacy-style group inserted without going through the risk pipeline
    db_session.add(
        AlertGroup(
            fingerprint="f" * 64,
            title="Legacy event",
            category="authentication",
            severity="medium",
        )
    )
    db_session.commit()

    body = client.get("/api/v1/events").json()
    item = body["items"][0]
    assert item["risk_score"] is None
    assert item["risk_level"] is None


def test_detail_returns_full_factor_breakdown(client, db_session):
    _post_alerts(client, _ssh_payload(), times=100)

    group_id = db_session.query(AlertGroup).first().id
    body = client.get(f"/api/v1/events/{group_id}").json()

    risk = body["risk"]
    assert risk is not None
    assert risk["score"] == 80
    assert risk["level"] == "high"
    assert "updated_at" in risk
    names = {f["name"] for f in risk["factors"]}
    assert names == {"severity", "frequency", "public_source"}
    for factor in risk["factors"]:
        assert set(factor.keys()) == {"name", "score", "reason"}
        assert isinstance(factor["score"], int)
        assert factor["reason"]
    assert sum(f["score"] for f in risk["factors"]) == 80


def test_detail_risk_is_null_when_no_risk_record(client, db_session):
    db_session.add(
        AlertGroup(
            fingerprint="e" * 64,
            title="Legacy event",
            category="authentication",
            severity="medium",
        )
    )
    db_session.commit()

    group_id = db_session.query(AlertGroup).first().id
    body = client.get(f"/api/v1/events/{group_id}").json()
    assert body["risk"] is None


def test_filter_by_level_high(client):
    # high: public source + 100 alerts; low: internal source + 1 alert
    _post_alerts(client, _ssh_payload("8.8.8.8"), times=100)
    _post_alerts(client, _ssh_payload("10.0.0.9"), times=1)

    body = client.get("/api/v1/events?level=high").json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["risk_level"] == "high"


def test_filter_by_level_returns_empty_when_no_match(client):
    _post_alerts(client, _ssh_payload("10.0.0.9"), times=1)

    body = client.get("/api/v1/events?level=critical").json()
    assert body["total"] == 0
    assert body["items"] == []


def test_filter_excludes_events_without_risk(client, db_session):
    db_session.add(
        AlertGroup(
            fingerprint="d" * 64,
            title="Legacy event",
            category="authentication",
            severity="medium",
        )
    )
    db_session.commit()

    body = client.get("/api/v1/events?level=low").json()
    assert body["total"] == 0


def test_filter_invalid_level_returns_422(client):
    assert client.get("/api/v1/events?level=urgent").status_code == 422


def test_filter_combines_with_pagination(client):
    # three distinct internal actors, one alert each -> medium(30)+0 = 30/low
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _post_alerts(client, _ssh_payload(ip))

    page1 = client.get("/api/v1/events?level=low&page=1&size=2").json()
    page2 = client.get("/api/v1/events?level=low&page=2&size=2").json()
    assert page1["total"] == 3 and len(page1["items"]) == 2
    assert page2["total"] == 3 and len(page2["items"]) == 1
