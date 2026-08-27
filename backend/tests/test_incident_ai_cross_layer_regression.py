"""Phase 2 Step 14.4: Incident AI Integration cross-layer regression.

Proves that Steps 14.1–14.3 keep the WHOLE frozen chain intact once the
layers are COMBINED:

    AlertGroup -> EventRisk -> Incident -> AI Context
        ├── AI Explanation        (Step 10)
        ├── Risk Summary          (Step 11)
        ├── Response Recommendation (Step 12)
        └── Approval              (Step 13)

Unlike the per-step unit tests, every AI row here is produced by the REAL
production endpoints (POST /events/{id}/ai-analysis | ai-risk-summary |
response-recommendation with the mock provider, POST .../approve|reject)
and then observed through ALL three layers — ORM traversal, Step 14.2
service and the Step 14.3 HTTP API. Frozen guarantees under test:

  A. full-lifecycle read: API body matches the database rows exactly
     (no copies, no lost history, no foreign data)
  B. history completeness: many rows per kind, approved + rejected +
     pending coexist — context is HISTORY, never "latest overwrites"
  C. risk snapshot frozen across layers: AI activity and context reads
     never touch Incident.risk_score or EventRisk.score
  D. incident isolation at ORM / service / API simultaneously
  E. approve != execute: a fully-read approved chain leaves zero side
     effects — no status move, no execution row, no new recommendation
  F. empty / partial AI pipelines are legal context states
"""
import uuid
from datetime import datetime, timezone

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
from app.services.incidents import get_incident_ai_context

SNAPSHOT_SCORE = 80
CONTEXT_PATH = "/api/v1/incidents/{}/ai-context"


def _seed_event(db, fingerprint: str, score: int = SNAPSHOT_SCORE) -> AlertGroup:
    """AlertGroup + EventRisk, the event half of the chain."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=fingerprint,
        title=f"Event {fingerprint[:4]}",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db.add_all([group, EventRisk(alert_group=group, score=score, level="high", factors=[])])
    db.commit()
    return group


def _open_incident_via_api(client, group: AlertGroup) -> dict:
    response = client.post("/api/v1/incidents", json={"alert_group_id": str(group.id)})
    assert response.status_code == 201
    return response.json()


def _generate_full_chain(client, group: AlertGroup) -> None:
    """Drive the real production AI endpoints (mock provider) for one event."""
    assert client.post(f"/api/v1/events/{group.id}/ai-analysis").status_code == 201
    assert client.post(f"/api/v1/events/{group.id}/ai-risk-summary").status_code == 201
    assert (
        client.post(f"/api/v1/events/{group.id}/response-recommendation").status_code
        == 201
    )


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


def _uuid_of(value: str) -> uuid.UUID:
    return uuid.UUID(value)


# ---------------------------------------------------------------------------
# A. full lifecycle: API read matches the database exactly
# ---------------------------------------------------------------------------


def test_full_lifecycle_context_matches_the_database_rows(client, db_session):
    group = _seed_event(db_session, "a" * 64)
    incident = _open_incident_via_api(client, group)
    _generate_full_chain(client, group)
    rec_id = db_session.scalar(
        select(AIResponseRecommendation.id).where(
            AIResponseRecommendation.alert_group_id == group.id
        )
    )
    approve = client.post(
        f"/api/v1/response-recommendations/{rec_id}/approve",
        json={"reviewer": "analyst-01", "review_comment": "confirmed"},
    )
    assert approve.status_code == 201

    response = client.get(CONTEXT_PATH.format(incident["id"]))
    assert response.status_code == 200
    body = response.json()

    # Every id the API returned IS a database row — no copies, no projections.
    db_analysis_ids = {
        str(i)
        for i in db_session.scalars(
            select(AIAnalysis.id).where(AIAnalysis.alert_group_id == group.id)
        )
    }
    db_summary_ids = {
        str(i)
        for i in db_session.scalars(
            select(AIRiskSummary.id).where(AIRiskSummary.alert_group_id == group.id)
        )
    }
    db_approval_ids = {str(i) for i in db_session.scalars(select(AIResponseApproval.id))}
    assert {a["id"] for a in body["analyses"]} == db_analysis_ids
    assert {s["id"] for s in body["risk_summaries"]} == db_summary_ids
    returned_recs = body["response_recommendations"]
    assert {r["recommendation"]["id"] for r in returned_recs} == {str(rec_id)}
    assert {r["approval"]["id"] for r in returned_recs} == db_approval_ids
    # And nothing from another case slipped in.
    assert body["incident"]["id"] == incident["id"]
    assert body["incident"]["risk_score_snapshot"] == SNAPSHOT_SCORE


# ---------------------------------------------------------------------------
# B. history completeness: never "latest overwrites previous"
# ---------------------------------------------------------------------------


def test_context_keeps_every_history_row_and_every_approval_state(client, db_session):
    group = _seed_event(db_session, "b" * 64)
    incident = _open_incident_via_api(client, group)
    # Three rounds of every AI layer through the real endpoints.
    for _ in range(3):
        _generate_full_chain(client, group)

    rec_ids = list(
        db_session.scalars(
            select(AIResponseRecommendation.id)
            .where(AIResponseRecommendation.alert_group_id == group.id)
            .order_by(AIResponseRecommendation.created_at)
        )
    )
    assert len(rec_ids) == 3
    # approved / rejected / pending — all three states coexist in one case.
    assert client.post(
        f"/api/v1/response-recommendations/{rec_ids[0]}/approve",
        json={"reviewer": "analyst-01"},
    ).status_code == 201
    assert client.post(
        f"/api/v1/response-recommendations/{rec_ids[1]}/reject",
        json={"reviewer": "analyst-02", "review_comment": "too broad"},
    ).status_code == 201

    body = client.get(CONTEXT_PATH.format(incident["id"])).json()

    # Complete histories, oldest first — nothing collapsed into a "latest".
    assert len(body["analyses"]) == 3
    assert len(body["risk_summaries"]) == 3
    assert len(body["response_recommendations"]) == 3
    for key in ("analyses", "risk_summaries"):
        stamps = [row["created_at"] for row in body[key]]
        assert stamps == sorted(stamps)
    # Same for the service layer — API and service agree row-for-row.
    context = get_incident_ai_context(db_session, _uuid_of(body["incident"]["id"]))
    assert [a.id for a in context.analyses] == [
        a.id for a in db_session.scalars(
            select(AIAnalysis)
            .where(AIAnalysis.alert_group_id == group.id)
            .order_by(AIAnalysis.created_at)
        )
    ]
    # Approval states: approved / rejected / None (pending, derived).
    by_rec = {r["recommendation"]["id"]: r["approval"] for r in body["response_recommendations"]}
    assert by_rec[str(rec_ids[0])]["status"] == "approved"
    assert by_rec[str(rec_ids[1])]["status"] == "rejected"
    assert by_rec[str(rec_ids[2])] is None
    # Pending was never persisted anywhere.
    stored = db_session.scalars(select(AIResponseApproval.status)).all()
    assert set(stored) == {"approved", "rejected"}


# ---------------------------------------------------------------------------
# C. risk snapshot frozen across layers
# ---------------------------------------------------------------------------


def test_risk_snapshot_survives_ai_activity_and_context_reads(client, db_session):
    group = _seed_event(db_session, "c" * 64)
    risk = db_session.scalar(select(EventRisk).where(EventRisk.alert_group_id == group.id))
    incident = _open_incident_via_api(client, group)

    _generate_full_chain(client, group)
    rec_id = db_session.scalar(
        select(AIResponseRecommendation.id).where(
            AIResponseRecommendation.alert_group_id == group.id
        )
    )
    assert client.post(
        f"/api/v1/response-recommendations/{rec_id}/approve",
        json={"reviewer": "analyst-01"},
    ).status_code == 201

    # Two reads: the context endpoint must not mutate formal risk data.
    first = client.get(CONTEXT_PATH.format(incident["id"])).json()
    second = client.get(CONTEXT_PATH.format(incident["id"])).json()

    db_session.refresh(risk)
    db_incident = db_session.get(Incident, _uuid_of(incident["id"]))
    assert risk.score == SNAPSHOT_SCORE  # EventRisk untouched by AI + reads
    assert db_incident.risk_score == SNAPSHOT_SCORE  # snapshot never recomputed
    assert db_incident.status == "open" and db_incident.severity == "high"
    for body in (first, second):
        assert body["incident"]["risk_score_snapshot"] == SNAPSHOT_SCORE
        assert body["incident"]["status"] == "open"
    # The event-side read endpoint agrees.
    detail = client.get(f"/api/v1/incidents/{incident['id']}").json()
    assert detail["risk_score"] == SNAPSHOT_SCORE


# ---------------------------------------------------------------------------
# D. isolation, observed at ORM / service / API simultaneously
# ---------------------------------------------------------------------------


def test_isolation_holds_at_every_observation_layer(client, db_session):
    group_a = _seed_event(db_session, "d" * 64)
    group_b = _seed_event(db_session, "e" * 64)
    incident_a = _open_incident_via_api(client, group_a)
    incident_b = _open_incident_via_api(client, group_b)
    _generate_full_chain(client, group_b)  # only B has AI history
    rec_b = db_session.scalar(
        select(AIResponseRecommendation.id).where(
            AIResponseRecommendation.alert_group_id == group_b.id
        )
    )
    assert client.post(
        f"/api/v1/response-recommendations/{rec_b}/approve",
        json={"reviewer": "analyst-01"},
    ).status_code == 201

    db_incident_a = db_session.get(Incident, _uuid_of(incident_a["id"]))
    # ORM layer: viewonly traversals see nothing foreign.
    assert db_incident_a.ai_analyses == []
    assert db_incident_a.ai_risk_summaries == []
    assert db_incident_a.ai_response_recommendations == []
    # Service layer: the aggregated DTO is empty for A, complete for B.
    context_a = get_incident_ai_context(db_session, db_incident_a.id)
    context_b = get_incident_ai_context(db_session, _uuid_of(incident_b["id"]))
    assert context_a.analyses == context_a.risk_summaries == []
    assert context_a.response_recommendations == []
    assert len(context_b.analyses) == len(context_b.risk_summaries) == 1
    assert len(context_b.response_recommendations) == 1
    # API layer: A's body carries zero trace of B's rows.
    body_a = client.get(CONTEXT_PATH.format(incident_a["id"])).json()
    assert body_a["analyses"] == [] and body_a["risk_summaries"] == []
    assert body_a["response_recommendations"] == []
    text_a = client.get(CONTEXT_PATH.format(incident_a["id"])).text
    for foreign in (incident_b["id"], str(group_b.id), str(rec_b)):
        assert foreign not in text_a


# ---------------------------------------------------------------------------
# E. approve != execute: full read-through with zero side effects
# ---------------------------------------------------------------------------


def test_approved_chain_read_end_to_end_creates_no_execution_side_effect(client, db_session):
    group = _seed_event(db_session, "f" * 64)
    incident = _open_incident_via_api(client, group)
    _generate_full_chain(client, group)
    rec_id = db_session.scalar(
        select(AIResponseRecommendation.id).where(
            AIResponseRecommendation.alert_group_id == group.id
        )
    )
    assert client.post(
        f"/api/v1/response-recommendations/{rec_id}/approve",
        json={"reviewer": "analyst-01", "review_comment": "go"},
    ).status_code == 201
    before = {
        "counts": _ai_counts(db_session),
        "incident": (
            db_session.get(Incident, _uuid_of(incident["id"])).risk_score,
            db_session.get(Incident, _uuid_of(incident["id"])).status,
            db_session.get(Incident, _uuid_of(incident["id"])).severity,
        ),
    }

    # Read the complete chain back through every layer.
    body = client.get(CONTEXT_PATH.format(incident["id"])).json()
    assert body["response_recommendations"][0]["approval"]["status"] == "approved"
    get_incident_ai_context(db_session, _uuid_of(incident["id"]))

    db_session.expire_all()
    db_incident = db_session.get(Incident, _uuid_of(incident["id"]))
    assert _ai_counts(db_session) == before["counts"]  # no execution row type exists,
    # and no new recommendation/approval was fabricated by reading
    assert (
        db_incident.risk_score,
        db_incident.status,
        db_incident.severity,
    ) == before["incident"]
    # The approval queue stayed consistent: nothing pending for this rec.
    # (GET /approvals returns the pending queue as a plain JSON list.)
    queue = client.get("/api/v1/approvals").json()
    pending_ids = {item["id"] for item in queue}
    assert str(rec_id) not in pending_ids


# ---------------------------------------------------------------------------
# F. empty / partial AI pipelines are legal context states
# ---------------------------------------------------------------------------


def test_incident_without_any_ai_history_is_a_legal_empty_context(client, db_session):
    group = _seed_event(db_session, "0" * 64)
    incident = _open_incident_via_api(client, group)

    response = client.get(CONTEXT_PATH.format(incident["id"]))

    assert response.status_code == 200
    body = response.json()
    assert body["analyses"] == []
    assert body["risk_summaries"] == []
    assert body["response_recommendations"] == []


def test_analysis_only_pipeline_never_assumes_later_stages(client, db_session):
    """Production reality: a case may be viewed mid-pipeline — an event that
    was only explained (no summary, no recommendation) is a valid context."""
    group = _seed_event(db_session, "1" * 64)
    incident = _open_incident_via_api(client, group)
    assert client.post(f"/api/v1/events/{group.id}/ai-analysis").status_code == 201

    body = client.get(CONTEXT_PATH.format(incident["id"])).json()

    assert len(body["analyses"]) == 1
    assert body["risk_summaries"] == []
    assert body["response_recommendations"] == []
    # The service layer agrees — the API did not fabricate the gaps itself.
    context = get_incident_ai_context(db_session, _uuid_of(incident["id"]))
    assert len(context.analyses) == 1
    assert context.risk_summaries == context.response_recommendations == []
