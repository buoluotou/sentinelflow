"""Phase 2 Step 14.1: Incident <-> AI association protocol tests.

Freezes the incident-centric case view WITHOUT an executor:

    Incident -> alert_group -> ai_analyses               (Step 10)
                             -> ai_risk_summaries         (Step 11)
                             -> ai_response_recommendations (Step 12)
                                   -> approval            (Step 13)

The Incident CONNECTS the chain, it never swallows it:

1. the AI rows remain the AlertGroup's append-only history — the Incident
   only gains read-only (viewonly) traversals over the same alert_group_id
2. Incident.risk_score stays the creation-time snapshot of EventRisk.score;
   no AI result (analysis / summary / recommendation / approval) writes it
3. an approved decision is auditable through the chain but is NEVER
   auto-consumed by the incident (status / severity / score untouched)
4. zero schema change: no new column on incidents, no incident FK on any
   AI table — the associations are pure ORM projections
"""
import time
from datetime import datetime, timedelta, timezone

from app.models import (
    AIAnalysis,
    AIResponseApproval,
    AIResponseRecommendation,
    AIRiskSummary,
    AlertGroup,
    EventRisk,
    Incident,
)
from app.models.incident import Incident as IncidentModel
from app.services.ai import AIResponseApprovalService

FINGERPRINT = "f" * 64
SNAPSHOT_SCORE = 80


def _make_group() -> AlertGroup:
    now = datetime.now(timezone.utc)
    return AlertGroup(
        fingerprint=FINGERPRINT,
        title="SSH brute force detected",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )


def _seed_case(db) -> tuple[AlertGroup, EventRisk, Incident]:
    """AlertGroup + EventRisk + Incident (snapshot semantics of Step 7)."""
    group = _make_group()
    risk = EventRisk(
        alert_group=group, score=SNAPSHOT_SCORE, level="high", factors=[]
    )
    incident = Incident(
        alert_group=group,
        title=group.title,
        severity=group.severity,
        risk_score=risk.score,  # snapshot copy at creation — Step 7 freeze
    )
    db.add_all([group, risk, incident])
    db.commit()
    return group, risk, incident


def _make_analysis(group: AlertGroup, offset_seconds: int = 0) -> AIAnalysis:
    return AIAnalysis(
        alert_group=group,
        provider="mock",
        model="mock-model",
        summary="Repeated SSH authentication abuse.",
        attack_type="brute_force",
        why_risky=["high failure rate", "public source"],
        confidence=0.9,
        created_at=datetime.now(timezone.utc) + timedelta(seconds=offset_seconds),
    )


def _make_summary(group: AlertGroup, offset_seconds: int = 0) -> AIRiskSummary:
    return AIRiskSummary(
        alert_group=group,
        provider="mock",
        model="mock-model",
        summary="Coordinated brute force campaign.",
        key_findings=["8 attempts in 30s"],
        risk_drivers=["severity"],
        analyst_priority="high",
        confidence=0.88,
        created_at=datetime.now(timezone.utc) + timedelta(seconds=offset_seconds),
    )


def _make_recommendation(group: AlertGroup) -> AIResponseRecommendation:
    return AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-model",
        overall_rationale="Block the abusive source.",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.10", "rationale": "abuse"}
        ],
        confidence=0.92,
    )


# ---------------------------------------------------------------------------
# 1. The association chain is complete and read-only
# ---------------------------------------------------------------------------


def test_full_chain_traversal_from_incident(db_session):
    group, risk, incident = _seed_case(db_session)
    analysis = _make_analysis(group)
    summary = _make_summary(group)
    recommendation = _make_recommendation(group)
    db_session.add_all([analysis, summary, recommendation])
    db_session.commit()

    approval_service = AIResponseApprovalService()
    approval_service.approve(db_session, recommendation.id, "analyst-01")
    db_session.commit()

    assert [a.id for a in incident.ai_analyses] == [analysis.id]
    assert [s.id for s in incident.ai_risk_summaries] == [summary.id]
    assert [r.id for r in incident.ai_response_recommendations] == [recommendation.id]
    # Approval hangs off the recommendation, reachable from the incident:
    assert incident.ai_response_recommendations[0].approval.status == "approved"
    assert isinstance(incident.ai_response_recommendations[0].approval, AIResponseApproval)


def test_traversal_agrees_with_the_alert_group_view(db_session):
    """Incident adds NO second history — it projects the AlertGroup's."""
    group, risk, incident = _seed_case(db_session)
    db_session.add_all([_make_analysis(group), _make_summary(group)])
    db_session.commit()

    assert incident.ai_analyses == group.ai_analyses
    assert incident.ai_risk_summaries == group.ai_risk_summaries
    assert incident.ai_response_recommendations == group.ai_response_recommendations


def test_traversal_is_history_ordered_oldest_first(db_session):
    group, risk, incident = _seed_case(db_session)
    old = _make_analysis(group, offset_seconds=0)
    new = _make_analysis(group, offset_seconds=10)
    db_session.add_all([new, old])  # inserted out of order on purpose
    db_session.commit()

    assert [a.created_at for a in incident.ai_analyses] == sorted(
        a.created_at for a in incident.ai_analyses
    )
    assert incident.ai_analyses[0].id == old.id


def test_fresh_incident_has_empty_ai_views(db_session):
    group, risk, incident = _seed_case(db_session)

    assert incident.ai_analyses == []
    assert incident.ai_risk_summaries == []
    assert incident.ai_response_recommendations == []


def test_deleting_the_incident_keeps_the_ai_history(db_session):
    """viewonly = no cascade through the Incident; the AlertGroup owns the
    AI rows (and still cascades their deletion — pinned in Step 10 tests)."""
    group, risk, incident = _seed_case(db_session)
    analysis = _make_analysis(group)
    recommendation = _make_recommendation(group)
    db_session.add_all([analysis, recommendation])
    db_session.commit()
    analysis_id, recommendation_id = analysis.id, recommendation.id

    db_session.delete(incident)
    db_session.commit()

    assert db_session.get(AIAnalysis, analysis_id) is not None
    assert db_session.get(AIResponseRecommendation, recommendation_id) is not None


# ---------------------------------------------------------------------------
# 2. The risk-score snapshot is frozen against every AI artifact
# ---------------------------------------------------------------------------


def test_ai_history_never_touches_the_risk_score_snapshot(db_session):
    group, risk, incident = _seed_case(db_session)
    before = (incident.risk_score, incident.severity, incident.status)

    db_session.add_all(
        [_make_analysis(group), _make_summary(group), _make_recommendation(group)]
    )
    db_session.commit()
    db_session.refresh(incident)

    assert (incident.risk_score, incident.severity, incident.status) == before
    assert incident.risk_score == SNAPSHOT_SCORE == risk.score


def test_approved_decision_is_never_consumed_by_the_incident(db_session):
    """approved = auditable through the chain, NOT an input to the case:
    no status transition, no severity change, no score writeback."""
    group, risk, incident = _seed_case(db_session)
    recommendation = _make_recommendation(group)
    db_session.add(recommendation)
    db_session.commit()
    snapshot = (incident.risk_score, incident.severity, incident.status)
    time.sleep(0.01)

    approval_service = AIResponseApprovalService()
    approval = approval_service.approve(
        db_session, recommendation.id, "analyst-01", "confirmed malicious"
    )
    db_session.commit()
    db_session.refresh(incident)

    assert approval.status == "approved"
    # The approval is reachable from the case view ...
    assert incident.ai_response_recommendations[0].approval.id == approval.id
    # ... yet the case record itself is completely unchanged.
    assert (incident.risk_score, incident.severity, incident.status) == snapshot


# ---------------------------------------------------------------------------
# 3. Zero schema change — the associations are pure ORM projections
# ---------------------------------------------------------------------------


def test_incidents_table_keeps_the_frozen_step7_columns(db_session):
    """14.1 must not add columns to incidents (no ai_* FK, nothing)."""
    columns = {c.name for c in IncidentModel.__table__.columns}
    assert columns == {
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
    }


def test_no_ai_table_gains_an_incident_foreign_key(db_session):
    """AI history stays anchored on AlertGroup only — Incident never becomes
    the owner of AI rows."""
    for model in (AIAnalysis, AIRiskSummary, AIResponseRecommendation, AIResponseApproval):
        fks = {fk.target_fullname for fk in model.__table__.foreign_keys}
        assert not any("incident" in fk for fk in fks), model.__tablename__
        assert "alert_groups.id" in fks or "ai_response_recommendations.id" in fks
