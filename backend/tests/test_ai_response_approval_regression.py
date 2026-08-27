"""Step 13.4: cross-layer regression for the approval state machine.

13.1 (model) / 13.2 (service) / 13.3 (API) have their own suites; this
file pins the whole pipeline as one contract, all at the API boundary:

    Recommendation (no approval row) -> PENDING (derived)
    PENDING + approve  -> APPROVED   (one-shot INSERT)
    PENDING + reject   -> REJECTED   (one-shot INSERT)

There is no pending -> UPDATE -> approved path: "pending" never exists in
the database, decisions are INSERT-only, and a decided recommendation is
final. Six blocks:

1. full queue lifecycles (approve chain + reject chain), including the
   12.3 -> 13 hand-off: a recommendation generated through the real
   Step 12 API lands in the Step 13 queue
2. no re-judging: every second decision is 409 and the original row is
   field-for-field immutable (status / reviewer / reviewed_at / comment)
3. concurrency through the API: two racing decisions, exactly one wins
4. queue boundaries: decided items vanish, order stays created_at ASC
5. empty queue is a normal [] — never 404
6. the safety boundary across layers: a decision never executes anything —
   approving an escalate_to_incident advice creates no Incident, leaves
   EventRisk and the advice body untouched (the Step 13 modules import no
   orchestrator client; the behavioral assertions below pin the outcome)
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    Alert,
    AlertGroup,
    EventRisk,
    Incident,
)

QUEUE = "/api/v1/approvals"


def _seed_event(db_session: Session, score: int = 85) -> AlertGroup:
    """AlertGroup + EventRisk + one evidence alert, committed."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add_all(
        [
            group,
            EventRisk(
                alert_group=group,
                score=score,
                level="high",
                factors=[{"name": "severity", "score": 30, "reason": "High-severity alerts"}],
            ),
            Alert(
                source="scenario-simulator",
                event_type="ssh_failed_login",
                severity="high",
                source_ip="203.0.113.9",
                user_name="root",
                first_seen_at=now,
                last_seen_at=now,
                alert_group=group,
            ),
        ]
    )
    db_session.commit()
    return group


def _seed_recommendation(
    db_session: Session, minutes_ago: int = 0, actions: tuple[str, ...] = ("block_source_ip",)
) -> AIResponseRecommendation:
    """Committed event + one recommendation carrying the given actions."""
    group = _seed_event(db_session)
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": action, "target": "203.0.113.9", "rationale": "abuse"}
            for action in actions
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    if minutes_ago:
        record.created_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    db_session.commit()
    return record


def _decision_urls(record) -> dict[str, str]:
    base = f"/api/v1/response-recommendations/{record.id}"
    return {"approve": f"{base}/approve", "reject": f"{base}/reject"}


# ------------------------------------- Block 1: full queue lifecycles


def test_approve_lifecycle_queue_decision_detail(client, db_session):
    """Recommendation created through the REAL Step 12 API lands in the
    Step 13 queue; approve closes the auditable loop end to end:
    generate -> queue -> approve -> queue empty -> detail."""
    group = _seed_event(db_session, score=85)
    generated = client.post(f"/api/v1/events/{group.id}/response-recommendation")
    assert generated.status_code == 201
    recommendation_id = generated.json()["id"]

    # 1 pending entry, derived (no status field anywhere).
    queue = client.get(QUEUE)
    assert queue.status_code == 200
    assert [entry["id"] for entry in queue.json()] == [recommendation_id]
    assert "status" not in queue.json()[0]

    # Decide.
    decision = client.post(
        f"/api/v1/response-recommendations/{recommendation_id}/approve",
        json={"reviewer": "analyst-1", "review_comment": "confirmed by SOC"},
    )
    assert decision.status_code == 201
    approval = decision.json()
    assert approval["status"] == "approved"
    assert approval["recommendation_id"] == recommendation_id

    # Queue drained; the decision is readable across requests.
    assert client.get(QUEUE).json() == []
    detail = client.get(f"{QUEUE}/{approval['id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "approved"
    assert detail.json()["reviewer"] == "analyst-1"


def test_reject_lifecycle_queue_decision_detail(client, db_session):
    record = _seed_recommendation(db_session)
    urls = _decision_urls(record)
    assert [entry["id"] for entry in client.get(QUEUE).json()] == [str(record.id)]

    decision = client.post(
        urls["reject"], json={"reviewer": "analyst-2", "review_comment": "false positive"}
    )
    assert decision.status_code == 201
    approval = decision.json()
    assert approval["status"] == "rejected"

    assert client.get(QUEUE).json() == []
    detail = client.get(f"{QUEUE}/{approval['id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "rejected"
    assert detail.json()["review_comment"] == "false positive"


# --------------------------------------------- Block 2: no re-judging


@pytest.mark.parametrize(
    "first,second",
    [("approve", "approve"), ("approve", "reject"), ("reject", "approve"), ("reject", "reject")],
)
def test_second_decision_is_409_and_original_is_field_immutable(
    client, db_session, first, second
):
    """A decision is a one-shot final act: the retry is 409 and EVERY field
    of the original row survives untouched (no workflow-style edits)."""
    record = _seed_recommendation(db_session)
    urls = _decision_urls(record)

    first_response = client.post(
        urls[first], json={"reviewer": "analyst-1", "review_comment": "original note"}
    )
    assert first_response.status_code == 201
    original = db_session.query(AIResponseApproval).one()
    snapshot = {
        "id": original.id,
        "status": original.status,
        "reviewer": original.reviewer,
        "reviewed_at": original.reviewed_at,
        "review_comment": original.review_comment,
    }

    retry = client.post(
        urls[second], json={"reviewer": "analyst-2", "review_comment": "attempted overwrite"}
    )
    assert retry.status_code == 409
    assert retry.json()["detail"] == "Recommendation already reviewed"

    db_session.expire_all()
    after = db_session.query(AIResponseApproval).one()  # exactly ONE row
    assert after.id == snapshot["id"]
    assert after.status == snapshot["status"]
    assert after.reviewer == snapshot["reviewer"]
    assert after.reviewed_at == snapshot["reviewed_at"]  # clock not overwritten
    assert after.review_comment == snapshot["review_comment"]


# -------------------------------------------------- Block 3: concurrency


@pytest.mark.parametrize("winner,loser", [("approve", "reject"), ("reject", "approve")])
def test_racing_decisions_exactly_one_wins(client, db_session, winner, loser):
    """Two analysts act on the same queue item: one 201, the other 409,
    exactly one approval row, winner's verdict stands. (The true flush-time
    UNIQUE race branch is pinned at service level in 13.2; here the API
    contract of the resolved race is locked.)"""
    record = _seed_recommendation(db_session)
    urls = _decision_urls(record)

    first = client.post(urls[winner], json={"reviewer": "analyst-A"})
    second = client.post(urls[loser], json={"reviewer": "analyst-B"})

    assert first.status_code == 201
    assert second.status_code == 409

    approvals = db_session.query(AIResponseApproval).all()
    assert len(approvals) == 1
    assert approvals[0].status == {"approve": "approved", "reject": "rejected"}[winner]
    assert approvals[0].reviewer == "analyst-A"
    assert client.get(QUEUE).json() == []


# ------------------------------------------- Block 4: queue boundaries


def test_queue_shows_only_pending_in_frozen_order(client, db_session):
    """A(pending) B(approved) C(rejected) D(pending) -> queue is [A, D],
    ordered created_at ASC straight from the service (no API re-sort)."""
    a = _seed_recommendation(db_session, minutes_ago=30)
    b = _seed_recommendation(db_session, minutes_ago=20)
    c = _seed_recommendation(db_session, minutes_ago=10)
    d = _seed_recommendation(db_session)
    for record, path in ((b, "approve"), (c, "reject")):
        response = client.post(
            f"/api/v1/response-recommendations/{record.id}/{path}",
            json={"reviewer": "analyst-1"},
        )
        assert response.status_code == 201

    queue = client.get(QUEUE)
    assert queue.status_code == 200
    assert [entry["id"] for entry in queue.json()] == [str(a.id), str(d.id)]


# -------------------------------------------------- Block 5: empty queue


def test_fully_drained_queue_is_200_empty_list_not_404(client, db_session):
    """Queue empty is a normal operational state, not an error."""
    first = _seed_recommendation(db_session, minutes_ago=5)
    second = _seed_recommendation(db_session)
    for record, path in ((first, "approve"), (second, "reject")):
        assert client.post(
            f"/api/v1/response-recommendations/{record.id}/{path}",
            json={"reviewer": "analyst-1"},
        ).status_code == 201

    response = client.get(QUEUE)
    assert response.status_code == 200
    assert response.json() == []


# ------------------------------------- Block 6: safety boundary cross-layer


def test_approving_an_escalation_never_executes_anything(client, db_session):
    """The sharpest edge: a recommendation carrying escalate_to_incident +
    block_source_ip gets APPROVED — and still nothing executes. No Incident
    appears, EventRisk is untouched, the advice body is never rewritten."""
    record = _seed_recommendation(
        db_session, actions=("block_source_ip", "escalate_to_incident")
    )
    risk = db_session.query(EventRisk).one()
    before = {
        "score": risk.score,
        "level": risk.level,
        "recommendations": list(record.recommendations),
        "overall_rationale": record.overall_rationale,
    }

    decision = client.post(
        f"/api/v1/response-recommendations/{record.id}/approve",
        json={"reviewer": "analyst-1"},
    )
    assert decision.status_code == 201
    assert decision.json()["status"] == "approved"

    # Execution layer untouched.
    assert db_session.query(Incident).count() == 0
    assert risk.score == before["score"] and risk.level == before["level"]
    db_session.expire_all()
    fresh = db_session.get(AIResponseRecommendation, record.id)
    assert fresh.recommendations == before["recommendations"]
    assert fresh.overall_rationale == before["overall_rationale"]
    # The approval row is the ONLY new artifact of the decision.
    assert db_session.query(AIResponseApproval).count() == 1
