"""Phase 2 Step 10.2: AIRequest builder tests.

AlertGroup + EventRisk + evidence alerts -> the frozen AIRequest contract.
No provider and no database involved: pure translation rules.
"""
import json
from datetime import datetime, timezone

from app.models import Alert, AlertGroup, EventRisk
from app.services.ai import MAX_EVIDENCE, build_alert_explanation


def _group() -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint="a" * 64,
        title="SSH login failure detected",
        category="authentication",
        severity="medium",
        first_seen=now,
        last_seen=now,
    )


def _risk(group: AlertGroup, score: int = 70, level: str = "medium") -> EventRisk:
    return EventRisk(
        alert_group=group,
        score=score,
        level=level,
        factors=[
            {"name": "severity", "score": 30, "reason": "Alert severity is medium"},
            {"name": "frequency", "score": 40, "reason": "101 alerts observed"},
        ],
    )


def _alert(index: int, seen: datetime | None = None) -> Alert:
    ts = seen or datetime.now(timezone.utc)
    return Alert(
        source="scenario-simulator",
        event_type="ssh_failed_login",
        severity="medium",
        source_ip=f"10.0.0.{index % 250}",
        user_name="root" if index % 2 == 0 else None,
        first_seen_at=ts,
        last_seen_at=ts,
    )


def test_builds_frozen_alert_explanation_request():
    group = _group()
    risk = _risk(group)
    alerts = [_alert(i) for i in range(3)]

    request = build_alert_explanation(group, risk, alerts)

    assert request.task == "alert_explanation"
    assert request.event_title == "SSH login failure detected"
    assert request.event_category == "authentication"
    assert request.severity == "medium"
    assert request.risk_score == 70
    assert request.risk_level == "medium"
    assert request.risk_factors == risk.factors  # factor trail passed through
    assert len(request.evidence) == 3
    # Evidence items are JSON projections of the evidence alerts.
    item = json.loads(request.evidence[0])
    assert item["event_type"] == "ssh_failed_login"
    assert item["source_ip"] == "10.0.0.0"
    assert item["user_name"] == "root"


def test_missing_risk_degrades_instead_of_failing():
    request = build_alert_explanation(_group(), None, [_alert(0)])

    assert request.risk_score == 0
    assert request.risk_level == "unassessed"
    assert request.risk_factors == []
    assert len(request.evidence) == 1


def test_evidence_capped_at_max():
    alerts = [_alert(i) for i in range(MAX_EVIDENCE + 5)]

    request = build_alert_explanation(_group(), None, alerts)

    assert len(request.evidence) == MAX_EVIDENCE
    # Order preserved: the first MAX_EVIDENCE alerts, earliest handed first.
    assert json.loads(request.evidence[0])["source_ip"] == "10.0.0.0"
    assert json.loads(request.evidence[-1])["source_ip"] == "10.0.0.19"


def test_evidence_item_drops_none_fields():
    request = build_alert_explanation(_group(), None, [_alert(1)])  # user_name None

    item = json.loads(request.evidence[0])
    assert "user_name" not in item
    assert "destination_ip" not in item  # never set
    # event_count is a column default (applies at flush), so in-memory it is
    # dropped like any other unset field.
    assert "event_count" not in item
    assert item["event_type"] == "ssh_failed_login"


def test_evidence_timestamps_serialize():
    seen = datetime(2026, 8, 25, 10, 30, 0, tzinfo=timezone.utc)
    request = build_alert_explanation(_group(), None, [_alert(0, seen=seen)])

    item = json.loads(request.evidence[0])
    assert "2026-08-25" in item["first_seen_at"]
