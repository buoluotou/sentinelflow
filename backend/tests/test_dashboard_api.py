"""Phase 1 Step 7.5: Dashboard summary API tests.

GET /api/v1/dashboard/summary aggregates everything the React Console
home page needs in ONE backend call — no new tables, pure real-time
aggregation over incidents / alerts / alert_groups / event_risk.

Frozen metric semantics:
- open_incidents            active cases: status in (open, in_progress)
- critical/high/medium_incidents  severity breakdown of ACTIVE incidents
- today_alerts / today_events     created since today 00:00 UTC
- risk_distribution         current EventRisk.level over ALL events
"""
from datetime import datetime, timedelta, timezone

from app.models import Alert, AlertGroup, EventRisk


def _seed_group(db_session, fingerprint: str, severity: str = "medium") -> AlertGroup:
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=fingerprint,
        title=f"event {fingerprint[:6]}",
        category="authentication",
        severity=severity,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.flush()
    return group


def _seed_alert(db_session, group: AlertGroup, created_at: datetime) -> Alert:
    alert = Alert(
        source="scenario-simulator",
        event_type="ssh_failed_login",
        severity="medium",
        status="open",
        title="evidence",
        first_seen_at=created_at,
        last_seen_at=created_at,
        event_count=1,
        alert_group=group,
        created_at=created_at,
    )
    db_session.add(alert)
    return alert


# ---------------------------------------------------------------- empty db


def test_empty_dashboard_is_all_zeros(client):
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    assert response.json() == {
        "open_incidents": 0,
        "critical_incidents": 0,
        "high_incidents": 0,
        "medium_incidents": 0,
        "today_alerts": 0,
        "today_events": 0,
        "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }


# ------------------------------------------------------- risk distribution


def test_risk_distribution_counts_event_risk_levels(client, db_session):
    """5 events: 2 high + 1 critical + 2 medium -> {critical:1, high:2,
    medium:2, low:0}; an event WITHOUT risk contributes nothing."""
    levels = ["high", "high", "critical", "medium", "medium"]
    for i, level in enumerate(levels):
        group = _seed_group(db_session, f"{i:064d}", severity="high")
        db_session.add(EventRisk(alert_group=group, score=80, level=level))
    no_risk = _seed_group(db_session, "f" * 64)
    db_session.commit()

    body = client.get("/api/v1/dashboard/summary").json()
    assert body["risk_distribution"] == {
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 0,
    }
    assert body["today_events"] == 6  # all groups created today
    assert no_risk.id is not None


def test_today_events_excludes_yesterday(client, db_session):
    group = _seed_group(db_session, "a" * 64)
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    group.created_at = yesterday  # backdate after construction
    db_session.commit()

    body = client.get("/api/v1/dashboard/summary").json()
    assert body["today_events"] == 0


# ------------------------------------------------------------- today alerts


def test_today_alerts_counts_only_today(client, db_session):
    group = _seed_group(db_session, "a" * 64)
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    _seed_alert(db_session, group, yesterday)
    _seed_alert(db_session, group, yesterday)
    for _ in range(3):
        _seed_alert(db_session, group, now)
    db_session.commit()

    assert client.get("/api/v1/dashboard/summary").json()["today_alerts"] == 3


# ----------------------------------------------------- incident aggregates


def test_auto_created_incident_increments_open_incidents(client):
    """The Step 7.4 pipeline: risk >= 70 -> incident -> dashboard +1."""
    payload = {
        "source": "scenario-simulator",
        "event_type": "malicious_ioc",
        "severity": "critical",
        "host": {"hostname": "server-01", "ip": "192.168.1.10"},
        "source_ip": "10.0.0.55",
        "message": "dashboard scenario",
    }
    assert client.get("/api/v1/dashboard/summary").json()["open_incidents"] == 0

    client.post("/api/v1/alerts", json=payload)
    body = client.get("/api/v1/dashboard/summary").json()
    assert body["open_incidents"] == 1
    assert body["critical_incidents"] == 1  # severity breakdown of active cases
    assert body["high_incidents"] == 0
    assert body["medium_incidents"] == 0
    assert body["today_alerts"] == 1
    assert body["today_events"] == 1


def test_in_progress_still_counts_as_open(client):
    payload = {
        "source": "scenario-simulator",
        "event_type": "malicious_ioc",
        "severity": "critical",
        "source_ip": "10.0.0.55",
    }
    client.post("/api/v1/alerts", json=payload)
    incident_id = client.get("/api/v1/incidents").json()["items"][0]["id"]

    client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "in_progress"}
    )
    assert client.get("/api/v1/dashboard/summary").json()["open_incidents"] == 1

    client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "closed"}
    )
    body = client.get("/api/v1/dashboard/summary").json()
    assert body["open_incidents"] == 0  # closed cases drop out of the queue
    assert body["critical_incidents"] == 0


def test_mixed_active_incident_severities(client, db_session):
    """Severity counters reflect ACTIVE cases only (open + in_progress)."""
    # three critical events -> three auto incidents
    for i, event_type in enumerate(("ioc_a", "ioc_b", "ioc_c")):
        client.post(
            "/api/v1/alerts",
            json={
                "source": "scenario-simulator",
                "event_type": event_type,
                "severity": "critical",
                "source_ip": "10.0.0.55",
            },
        )
    items = client.get("/api/v1/incidents").json()["items"]
    assert len(items) == 3

    # one high-severity case via a high event that crosses the threshold
    high_group = _seed_group(db_session, "d" * 64, severity="high")
    db_session.add(EventRisk(alert_group=high_group, score=75, level="high"))
    db_session.commit()
    client.post(
        "/api/v1/incidents", json={"alert_group_id": str(high_group.id)}
    )

    # close one critical case -> it leaves the active breakdown
    closed_id = items[0]["id"]
    client.patch(f"/api/v1/incidents/{closed_id}/status", json={"status": "closed"})

    body = client.get("/api/v1/dashboard/summary").json()
    assert body["open_incidents"] == 3  # 2 critical + 1 high still active
    assert body["critical_incidents"] == 2
    assert body["high_incidents"] == 1
    assert body["medium_incidents"] == 0
