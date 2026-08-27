"""Phase 2 Step 14.3: Incident AI Context API tests.

GET /api/v1/incidents/{incident_id}/ai-context is a thin read-only HTTP
passthrough into ``get_incident_ai_context`` (Step 14.2). Five blocks,
mirroring the frozen contract:

  A. unknown incident -> 404 with the unified "Incident not found" detail,
     no context body, and no leak of other incidents' AI data
  B. incident without any AI history -> 200 with EMPTY lists (legal state)
  C. full context: snapshot + complete histories, approved/rejected
     approvals attached, approval=null meaning pending (derived, not stored)
  D. isolation: requesting incident A never exposes incident B's AI data
  E. HTTP read-only boundary: the GET changes nothing — incident status,
     risk_score, AI history row counts and approval row counts stay put
"""
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.models import (
    AIAnalysis,
    AIResponseApproval,
    AIResponseRecommendation,
    AIRiskSummary,
    AlertGroup,
    EventRisk,
    Incident,
)
from app.services.ai import AIResponseApprovalService

SNAPSHOT_SCORE = 80
CONTEXT_PATH = "/api/v1/incidents/{}/ai-context"


def _seed_incident(db, fingerprint: str, score: int = SNAPSHOT_SCORE) -> Incident:
    """AlertGroup + EventRisk + Incident (Step 7 snapshot semantics)."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=fingerprint,
        title=f"Event {fingerprint[:4]}",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    risk = EventRisk(alert_group=group, score=score, level="high", factors=[])
    incident = Incident(
        alert_group=group,
        title=group.title,
        severity=group.severity,
        risk_score=risk.score,
    )
    db.add_all([group, risk, incident])
    db.commit()
    return incident


def _add_analysis(db, incident: Incident, offset_seconds: int = 0) -> AIAnalysis:
    row = AIAnalysis(
        alert_group=incident.alert_group,
        provider="mock",
        model="mock-model",
        summary=f"Analysis +{offset_seconds}s",
        attack_type="brute_force",
        why_risky=["high failure rate"],
        confidence=0.9,
        created_at=datetime.now(timezone.utc) + timedelta(seconds=offset_seconds),
    )
    db.add(row)
    db.commit()
    return row


def _add_summary(db, incident: Incident, offset_seconds: int = 0) -> AIRiskSummary:
    row = AIRiskSummary(
        alert_group=incident.alert_group,
        provider="mock",
        model="mock-model",
        summary=f"Summary +{offset_seconds}s",
        key_findings=["8 attempts in 30s"],
        risk_drivers=["severity"],
        analyst_priority="high",
        confidence=0.88,
        created_at=datetime.now(timezone.utc) + timedelta(seconds=offset_seconds),
    )
    db.add(row)
    db.commit()
    return row


def _add_recommendation(db, incident: Incident) -> AIResponseRecommendation:
    row = AIResponseRecommendation(
        alert_group=incident.alert_group,
        provider="mock",
        model="mock-model",
        overall_rationale="Block the abusive source.",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.10", "rationale": "abuse"}
        ],
        confidence=0.92,
    )
    db.add(row)
    db.commit()
    return row


def _decide(db, recommendation_id, status: str) -> AIResponseApproval:
    service = AIResponseApprovalService()
    decide = service.approve if status == "approved" else service.reject
    approval = decide(db, recommendation_id, "analyst-01", "e2e note")
    db.commit()
    return approval


def _ai_counts(db) -> dict:
    return {
        model.__tablename__: db.scalar(select(func.count()).select_from(model))
        for model in (
            AIAnalysis,
            AIRiskSummary,
            AIResponseRecommendation,
            AIResponseApproval,
            Incident,
        )
    }


# ---------------------------------------------------------------------------
# A. unknown incident -> 404, unified detail, no leak
# ---------------------------------------------------------------------------


def test_unknown_incident_returns_404_with_unified_detail(client, db_session):
    incident = _seed_incident(db_session, "a" * 64)
    _add_analysis(db_session, incident)  # real AI data exists elsewhere

    response = client.get(CONTEXT_PATH.format(uuid.uuid4()))

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"
    # The error body carries no context payload of any kind.
    assert "analyses" not in response.json()


def test_invalid_uuid_returns_404(client):
    assert client.get(CONTEXT_PATH.format("not-a-uuid")).status_code == 404


def test_unknown_incident_leaks_no_other_ai_data(client, db_session):
    """404 after other cases hold AI history: the response must never echo
    any of it (the service raises before assembling anything)."""
    incident = _seed_incident(db_session, "b" * 64)
    analysis = _add_analysis(db_session, incident)
    rec = _add_recommendation(db_session, incident)
    _decide(db_session, rec.id, "approved")

    response = client.get(CONTEXT_PATH.format(uuid.uuid4()))

    assert response.status_code == 404
    text = response.text
    assert str(incident.id) not in text
    assert str(analysis.id) not in text
    assert str(rec.id) not in text


# ---------------------------------------------------------------------------
# B. empty context is a legal 200, not a 404
# ---------------------------------------------------------------------------


def test_incident_without_ai_history_returns_empty_context(client, db_session):
    incident = _seed_incident(db_session, "c" * 64)

    response = client.get(CONTEXT_PATH.format(incident.id))

    assert response.status_code == 200
    body = response.json()
    assert body["analyses"] == []
    assert body["risk_summaries"] == []
    assert body["response_recommendations"] == []
    assert body["incident"]["id"] == str(incident.id)
    assert body["incident"]["status"] == "open"
    assert body["incident"]["severity"] == "high"
    assert body["incident"]["risk_score_snapshot"] == SNAPSHOT_SCORE


# ---------------------------------------------------------------------------
# C. full context: snapshot + every history + approval semantics
# ---------------------------------------------------------------------------


def test_full_context_returns_every_history_with_approvals(client, db_session):
    incident = _seed_incident(db_session, "d" * 64)
    a_old = _add_analysis(db_session, incident, offset_seconds=0)
    a_new = _add_analysis(db_session, incident, offset_seconds=10)
    _add_summary(db_session, incident, offset_seconds=0)
    _add_summary(db_session, incident, offset_seconds=10)
    rec_approved = _add_recommendation(db_session, incident)
    rec_rejected = _add_recommendation(db_session, incident)
    rec_pending = _add_recommendation(db_session, incident)
    _decide(db_session, rec_approved.id, "approved")
    _decide(db_session, rec_rejected.id, "rejected")

    response = client.get(CONTEXT_PATH.format(incident.id))

    assert response.status_code == 200
    body = response.json()
    # Incident snapshot, untouched semantics.
    assert body["incident"]["id"] == str(incident.id)
    assert body["incident"]["risk_score_snapshot"] == SNAPSHOT_SCORE
    # Complete histories, created_at ASC.
    assert [a["id"] for a in body["analyses"]] == [str(a_old.id), str(a_new.id)]
    assert len(body["risk_summaries"]) == 2
    rec_ids = [r["recommendation"]["id"] for r in body["response_recommendations"]]
    assert rec_ids == [str(rec_approved.id), str(rec_rejected.id), str(rec_pending.id)]
    # approved / rejected approvals hang on their recommendation...
    by_id = {r["recommendation"]["id"]: r["approval"] for r in body["response_recommendations"]}
    assert by_id[str(rec_approved.id)]["status"] == "approved"
    assert by_id[str(rec_approved.id)]["reviewer"] == "analyst-01"
    assert by_id[str(rec_rejected.id)]["status"] == "rejected"
    # ...and approval=null IS the pending state — derived, never persisted.
    assert by_id[str(rec_pending.id)] is None


# ---------------------------------------------------------------------------
# D. isolation between incidents
# ---------------------------------------------------------------------------


def test_incident_a_context_never_contains_incident_b_data(client, db_session):
    incident_a = _seed_incident(db_session, "e" * 64)
    incident_b = _seed_incident(db_session, "f" * 64)
    b_analysis = _add_analysis(db_session, incident_b)
    b_summary = _add_summary(db_session, incident_b)
    b_rec = _add_recommendation(db_session, incident_b)
    b_approval = _decide(db_session, b_rec.id, "approved")

    response = client.get(CONTEXT_PATH.format(incident_a.id))

    assert response.status_code == 200
    body = response.json()
    assert body["analyses"] == []
    assert body["risk_summaries"] == []
    assert body["response_recommendations"] == []
    # Belt and braces: none of B's identifiers appear anywhere in the body.
    text = response.text
    for foreign in (incident_b.id, b_analysis.id, b_summary.id, b_rec.id, b_approval.id):
        assert str(foreign) not in text


# ---------------------------------------------------------------------------
# E. HTTP read-only boundary: the GET mutates nothing
# ---------------------------------------------------------------------------


def test_get_ai_context_is_strictly_read_only(client, db_session):
    incident = _seed_incident(db_session, "0" * 64)
    _add_analysis(db_session, incident)
    _add_summary(db_session, incident)
    rec = _add_recommendation(db_session, incident)
    _decide(db_session, rec.id, "approved")
    before = {
        "status": incident.status,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "counts": _ai_counts(db_session),
    }

    response = client.get(CONTEXT_PATH.format(incident.id))
    assert response.status_code == 200

    db_session.refresh(incident)
    assert incident.status == before["status"]
    assert incident.risk_score == before["risk_score"]
    assert incident.severity == before["severity"]
    # Zero new rows anywhere; zero rows deleted.
    assert _ai_counts(db_session) == before["counts"]
    # The detail endpoint agrees: the case record is untouched over HTTP too.
    detail = client.get(f"/api/v1/incidents/{incident.id}").json()
    assert detail["status"] == before["status"]
    assert detail["risk_score"] == before["risk_score"]
