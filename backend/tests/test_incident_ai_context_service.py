"""Phase 2 Step 14.2: IncidentAIContextService tests.

The context service is a pure READ aggregation of the Step 14.1 viewonly
traversals. Six blocks, mirroring the frozen plan:

  A. unknown incident -> the project's unified IncidentNotFound, and no AI
     data of other cases leaks through the error path
  B. an incident without any AI history -> a valid EMPTY context (not an error)
  C. full context: complete histories, created_at ASC, approvals attached
     to their recommendations, every row owned by the incident's AlertGroup
  D. isolation: incident A never sees incident B's AI history
  E. read-only boundary: zero writes — incident fields, AI row counts and
     approval counts are unchanged and the session stays clean
  F. an approved recommendation produces no business side effect at all
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
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
from app.schemas.ai_analysis import AIAnalysisRead
from app.schemas.ai_risk_summary import AIRiskSummaryRead
from app.schemas.incident_ai_context import (
    IncidentAIContext,
    IncidentSnapshot,
    RecommendationWithApproval,
)
from app.schemas.response_approval import AIResponseApprovalRead
from app.services.ai import AIResponseApprovalService
from app.services.incidents import IncidentNotFound, get_incident_ai_context

SNAPSHOT_SCORE = 80


def _seed_case(db, fingerprint: str, score: int = SNAPSHOT_SCORE) -> Incident:
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
        for model in (AIAnalysis, AIRiskSummary, AIResponseRecommendation, AIResponseApproval, Incident)
    }


# ---------------------------------------------------------------------------
# A. unknown incident -> unified NotFound, no leak
# ---------------------------------------------------------------------------


def test_unknown_incident_raises_the_project_not_found(db_session):
    missing = uuid.uuid4()
    with pytest.raises(IncidentNotFound) as exc:
        get_incident_ai_context(db_session, missing)
    assert str(missing) in str(exc.value)


def test_unknown_incident_leaks_nothing_even_when_ai_data_exists(db_session):
    """The error path must raise BEFORE assembling anything — other cases'
    AI history can never surface through an unknown id."""
    incident = _seed_case(db_session, "a" * 64)
    _add_analysis(db_session, incident)

    with pytest.raises(IncidentNotFound):
        get_incident_ai_context(db_session, uuid.uuid4())


# ---------------------------------------------------------------------------
# B. empty AI context is a valid state
# ---------------------------------------------------------------------------


def test_incident_without_ai_history_returns_an_empty_context(db_session):
    incident = _seed_case(db_session, "b" * 64)

    context = get_incident_ai_context(db_session, incident.id)

    assert isinstance(context, IncidentAIContext)
    assert context.analyses == []
    assert context.risk_summaries == []
    assert context.response_recommendations == []
    assert context.incident.id == incident.id
    assert context.incident.status == "open"
    assert context.incident.severity == "high"
    assert context.incident.risk_score_snapshot == SNAPSHOT_SCORE


# ---------------------------------------------------------------------------
# C. full context: complete history, order, ownership, approval attachment
# ---------------------------------------------------------------------------


def test_full_context_aggregates_every_history(db_session):
    incident = _seed_case(db_session, "c" * 64)
    a_old = _add_analysis(db_session, incident, offset_seconds=0)
    a_new = _add_analysis(db_session, incident, offset_seconds=10)
    _add_summary(db_session, incident, offset_seconds=0)
    _add_summary(db_session, incident, offset_seconds=10)
    rec_approved = _add_recommendation(db_session, incident)
    rec_rejected = _add_recommendation(db_session, incident)
    rec_pending = _add_recommendation(db_session, incident)
    approval_ok = _decide(db_session, rec_approved.id, "approved")
    approval_no = _decide(db_session, rec_rejected.id, "rejected")

    context = get_incident_ai_context(db_session, incident.id)

    assert [a.id for a in context.analyses] == [a_old.id, a_new.id]  # ASC
    assert len(context.risk_summaries) == 2
    assert [r.recommendation.id for r in context.response_recommendations] == [
        rec_approved.id,
        rec_rejected.id,
        rec_pending.id,
    ]
    # Approvals hang on exactly their recommendation.
    by_id = {r.recommendation.id: r.approval for r in context.response_recommendations}
    assert by_id[rec_approved.id].id == approval_ok.id
    assert by_id[rec_approved.id].status == "approved"
    assert by_id[rec_rejected.id].id == approval_no.id
    assert by_id[rec_rejected.id].status == "rejected"
    # approval=None IS the pending state — derived, never persisted.
    assert by_id[rec_pending.id] is None
    # Every artifact belongs to THIS incident's AlertGroup.
    group_id = incident.alert_group_id
    assert all(a.alert_group_id == group_id for a in context.analyses)
    assert all(s.alert_group_id == group_id for s in context.risk_summaries)
    assert all(
        r.recommendation.alert_group_id == group_id
        for r in context.response_recommendations
    )


def test_histories_are_ordered_created_at_asc(db_session):
    incident = _seed_case(db_session, "d" * 64)
    _add_analysis(db_session, incident, offset_seconds=30)   # newest first on purpose
    _add_analysis(db_session, incident, offset_seconds=0)
    _add_analysis(db_session, incident, offset_seconds=15)

    context = get_incident_ai_context(db_session, incident.id)

    stamps = [a.created_at for a in context.analyses]
    assert stamps == sorted(stamps)


def test_pending_is_derived_and_never_persisted_by_the_service(db_session):
    incident = _seed_case(db_session, "e" * 64)
    _add_recommendation(db_session, incident)  # stays undecided

    get_incident_ai_context(db_session, incident.id)

    # The only stored approval statuses anywhere remain the terminal ones.
    stored = db_session.scalars(select(AIResponseApproval.status)).all()
    assert stored == []  # nothing decided yet -> nothing stored
    rows = db_session.scalars(select(AIResponseApproval)).all()
    assert all(row.status in {"approved", "rejected"} for row in rows)


# ---------------------------------------------------------------------------
# D. isolation between incidents
# ---------------------------------------------------------------------------


def test_incident_a_never_sees_incident_b_history(db_session):
    incident_a = _seed_case(db_session, "f" * 64)
    incident_b = _seed_case(db_session, "0" * 64)
    b_analysis = _add_analysis(db_session, incident_b)
    b_rec = _add_recommendation(db_session, incident_b)
    _decide(db_session, b_rec.id, "approved")

    context_a = get_incident_ai_context(db_session, incident_a.id)
    context_b = get_incident_ai_context(db_session, incident_b.id)

    assert context_a.analyses == []
    assert context_a.risk_summaries == []
    assert context_a.response_recommendations == []
    assert [a.id for a in context_b.analyses] == [b_analysis.id]
    assert [r.recommendation.id for r in context_b.response_recommendations] == [b_rec.id]
    assert all(a.alert_group_id == incident_b.alert_group_id for a in context_b.analyses)


# ---------------------------------------------------------------------------
# E. read-only boundary — zero writes
# ---------------------------------------------------------------------------


def test_reading_the_context_writes_nothing(db_session):
    incident = _seed_case(db_session, "1" * 64)
    _add_analysis(db_session, incident)
    _add_summary(db_session, incident)
    rec = _add_recommendation(db_session, incident)
    _decide(db_session, rec.id, "approved")

    before = {
        "risk_score": incident.risk_score,
        "status": incident.status,
        "severity": incident.severity,
        "counts": _ai_counts(db_session),
    }

    context = get_incident_ai_context(db_session, incident.id)

    db_session.refresh(incident)
    assert incident.risk_score == before["risk_score"]
    assert incident.status == before["status"]
    assert incident.severity == before["severity"]
    assert _ai_counts(db_session) == before["counts"]
    # The session itself never received a write.
    assert not db_session.new
    assert not db_session.dirty
    assert context.incident.risk_score_snapshot == before["risk_score"]


# ---------------------------------------------------------------------------
# F. an approved recommendation has no side effects on read
# ---------------------------------------------------------------------------


def test_approved_recommendation_causes_no_side_effect(db_session):
    incident = _seed_case(db_session, "2" * 64)
    rec = _add_recommendation(db_session, incident)
    _decide(db_session, rec.id, "approved")
    counts_before = _ai_counts(db_session)
    snapshot = (incident.risk_score, incident.status, incident.severity)

    context = get_incident_ai_context(db_session, incident.id)

    db_session.refresh(incident)
    # No new incident, recommendation or approval; nothing mutated.
    assert _ai_counts(db_session) == counts_before
    assert (incident.risk_score, incident.status, incident.severity) == snapshot
    # The approval is visible as AUDIT information only.
    assert context.response_recommendations[0].approval.status == "approved"


# ---------------------------------------------------------------------------
# DTO shape: frozen schemas, never raw ORM
# ---------------------------------------------------------------------------


def test_context_is_composed_of_the_frozen_schemas(db_session):
    incident = _seed_case(db_session, "3" * 64)
    _add_analysis(db_session, incident)
    _add_summary(db_session, incident)
    rec = _add_recommendation(db_session, incident)
    _decide(db_session, rec.id, "rejected")

    context = get_incident_ai_context(db_session, incident.id)

    assert isinstance(context.incident, IncidentSnapshot)
    assert all(isinstance(a, AIAnalysisRead) for a in context.analyses)
    assert all(isinstance(s, AIRiskSummaryRead) for s in context.risk_summaries)
    assert all(
        isinstance(r, RecommendationWithApproval)
        for r in context.response_recommendations
    )
    assert isinstance(context.response_recommendations[0].approval, AIResponseApprovalRead)
