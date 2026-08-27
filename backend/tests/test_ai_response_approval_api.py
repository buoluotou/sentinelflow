"""Step 13.3: Approval-queue API tests.

HTTP contract over AIResponseApprovalService: the queue returns pending
RECOMMENDATIONS (derived absence, never a stored status), approve/reject
record one decision row each (201), the frozen error mapping holds
(404 Recommendation/Approval not found, 409 already reviewed) and the
advisory-only boundary survives at the API layer — a decision never
touches EventRisk, Incident or the recommendation body.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    EventRisk,
    Incident,
)

QUEUE = "/api/v1/approvals"


def _seed(db_session, minutes_ago: int = 0) -> AIResponseRecommendation:
    """Committed AlertGroup + EventRisk + one AI recommendation."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.add(
        EventRisk(
            alert_group=group,
            score=85,
            level="high",
            factors=[{"name": "severity", "score": 30, "reason": "High-severity alerts"}],
        )
    )
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.7", "rationale": "abuse"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    if minutes_ago:
        record.created_at = now - timedelta(minutes=minutes_ago)
    db_session.commit()
    return record


def _approve_url(record) -> str:
    return f"/api/v1/response-recommendations/{record.id}/approve"


def _reject_url(record) -> str:
    return f"/api/v1/response-recommendations/{record.id}/reject"


# ------------------------------------------------------------ approval queue


def test_queue_lists_pending_recommendations(client, db_session):
    record = _seed(db_session)
    response = client.get(QUEUE)

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list) and len(body) == 1
    entry = body[0]
    # The queue entry IS the recommendation plus event context — no
    # approval fields and no invented "status: pending" key.
    assert entry["id"] == str(record.id)
    assert entry["event_id"] == str(record.alert_group_id)
    assert entry["event_title"] == "SSH Brute Force on edge-gateway"
    assert entry["overall_rationale"] == "[mock] guidance"
    assert entry["recommendations"][0]["action"] == "block_source_ip"
    assert entry["confidence"] == pytest.approx(0.7)
    assert "status" not in entry and "approval" not in entry


def test_empty_queue_returns_empty_list(client):
    response = client.get(QUEUE)
    assert response.status_code == 200
    assert response.json() == []


def test_approved_recommendation_leaves_queue(client, db_session):
    record = _seed(db_session)
    assert client.post(
        _approve_url(record), json={"reviewer": "analyst-1"}
    ).status_code == 201

    assert client.get(QUEUE).json() == []


def test_rejected_recommendation_leaves_queue(client, db_session):
    record = _seed(db_session)
    assert client.post(
        _reject_url(record), json={"reviewer": "analyst-1"}
    ).status_code == 201

    assert client.get(QUEUE).json() == []


def test_queue_keeps_first_in_first_reviewed_order(client, db_session):
    """API never re-sorts: the frozen service order (created_at ASC) wins."""
    oldest = _seed(db_session, minutes_ago=10)
    middle = _seed(db_session, minutes_ago=5)
    newest = _seed(db_session)

    ids = [entry["id"] for entry in client.get(QUEUE).json()]
    assert ids == [str(oldest.id), str(middle.id), str(newest.id)]


# ---------------------------------------------------------- approval detail


def test_approval_detail_round_trips(client, db_session):
    record = _seed(db_session)
    created = client.post(
        _approve_url(record),
        json={"reviewer": "analyst-1", "review_comment": "confirmed by SOC"},
    )
    approval_id = created.json()["id"]

    response = client.get(f"{QUEUE}/{approval_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == approval_id
    assert body["recommendation_id"] == str(record.id)
    assert body["status"] == "approved"
    assert body["reviewer"] == "analyst-1"
    assert body["review_comment"] == "confirmed by SOC"


def test_approval_detail_unknown_id_is_404(client):
    response = client.get(f"{QUEUE}/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Approval not found"


def test_approval_detail_malformed_id_is_404(client):
    response = client.get(f"{QUEUE}/not-a-uuid")
    assert response.status_code == 404
    assert response.json()["detail"] == "Approval not found"


# --------------------------------------------------------------- decisions


def test_approve_creates_approved_decision(client, db_session):
    record = _seed(db_session)
    before = datetime.now(timezone.utc)

    response = client.post(
        _approve_url(record),
        json={"reviewer": "analyst-1", "review_comment": "Confirmed malicious activity."},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["recommendation_id"] == str(record.id)
    assert body["status"] == "approved"
    assert body["reviewer"] == "analyst-1"
    assert body["review_comment"] == "Confirmed malicious activity."
    # reviewed_at is server-stamped: present, parseable and at/after the
    # moment the request started (never a client-supplied backdate).
    reviewed = datetime.fromisoformat(body["reviewed_at"])
    if reviewed.tzinfo is not None:
        assert reviewed >= before
    else:  # SQLite round-trips naive UTC datetimes
        assert reviewed >= before.replace(tzinfo=None) - timedelta(seconds=1)

    # One row, decided — the API committed (nothing was rolled back).
    assert db_session.query(AIResponseApproval).count() == 1
    assert client.get(QUEUE).json() == []


def test_reject_creates_rejected_decision(client, db_session):
    record = _seed(db_session)
    response = client.post(
        _reject_url(record),
        json={"reviewer": "analyst-2", "review_comment": "Insufficient evidence."},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "rejected"
    assert body["reviewer"] == "analyst-2"
    assert body["review_comment"] == "Insufficient evidence."
    assert db_session.query(AIResponseApproval).count() == 1


def test_comment_optional_on_both_decisions(client, db_session):
    first = _seed(db_session, minutes_ago=2)
    second = _seed(db_session)

    ok = client.post(_approve_url(first), json={"reviewer": "analyst-1"})
    assert ok.status_code == 201 and ok.json()["review_comment"] is None
    ok = client.post(_reject_url(second), json={"reviewer": "analyst-1"})
    assert ok.status_code == 201 and ok.json()["review_comment"] is None


def test_reviewer_is_required(client, db_session):
    record = _seed(db_session)
    response = client.post(_approve_url(record), json={"review_comment": "x"})
    assert response.status_code == 422
    assert db_session.query(AIResponseApproval).count() == 0


def test_client_supplied_reviewed_at_is_rejected(client, db_session):
    """extra='forbid': the audit clock cannot be smuggled in — the request
    fails validation and nothing is persisted."""
    record = _seed(db_session)
    response = client.post(
        _approve_url(record),
        json={"reviewer": "analyst-1", "reviewed_at": "2020-01-01T00:00:00Z"},
    )
    assert response.status_code == 422
    assert db_session.query(AIResponseApproval).count() == 0
    assert len(client.get(QUEUE).json()) == 1


def test_decision_is_committed_and_readable_via_detail(client, db_session):
    """API owns commit + refresh: the decision survives a fresh lookup."""
    record = _seed(db_session)
    created = client.post(_approve_url(record), json={"reviewer": "analyst-1"})
    approval_id = created.json()["id"]

    fresh = client.get(f"{QUEUE}/{approval_id}")
    assert fresh.status_code == 200
    assert fresh.json()["status"] == "approved"


# ------------------------------------------------------------ error mapping


def test_unknown_recommendation_is_404(client, db_session):
    _seed(db_session)
    missing = uuid.uuid4()
    for path in ("approve", "reject"):
        response = client.post(
            f"/api/v1/response-recommendations/{missing}/{path}",
            json={"reviewer": "analyst-1"},
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Recommendation not found"
    assert db_session.query(AIResponseApproval).count() == 0


def test_malformed_recommendation_id_is_404(client):
    for path in ("approve", "reject"):
        response = client.post(
            f"/api/v1/response-recommendations/not-a-uuid/{path}",
            json={"reviewer": "analyst-1"},
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Recommendation not found"


@pytest.mark.parametrize(
    "first_decision,second_decision",
    [("approve", "approve"), ("approve", "reject"), ("reject", "approve")],
)
def test_second_decision_is_409_and_original_stands(
    client, db_session, first_decision, second_decision
):
    record = _seed(db_session)
    first_url = _approve_url(record) if first_decision == "approve" else _reject_url(record)
    second_url = _approve_url(record) if second_decision == "approve" else _reject_url(record)

    first = client.post(first_url, json={"reviewer": "analyst-1"})
    assert first.status_code == 201

    response = client.post(second_url, json={"reviewer": "analyst-2"})
    assert response.status_code == 409
    assert response.json()["detail"] == "Recommendation already reviewed"

    # The original decision is untouched — exactly one row, original reviewer.
    approvals = db_session.query(AIResponseApproval).all()
    assert len(approvals) == 1
    assert approvals[0].status == ("approved" if first_decision == "approve" else "rejected")
    assert approvals[0].reviewer == "analyst-1"


# ----------------------------------------------------------- safety boundary


@pytest.mark.parametrize("path", ["approve", "reject"])
def test_decision_executes_nothing_via_api(client, db_session, path):
    """Approve/Reject != Execute at the HTTP edge: EventRisk unchanged, no
    Incident created, the recommendation body never rewritten."""
    record = _seed(db_session)
    before = dict(record.recommendations[0])

    response = client.post(
        f"/api/v1/response-recommendations/{record.id}/{path}",
        json={"reviewer": "analyst-1"},
    )
    assert response.status_code == 201

    risk = db_session.query(EventRisk).one()
    assert risk.score == 85 and risk.level == "high"
    assert db_session.query(Incident).count() == 0
    db_session.expire_all()
    fresh = db_session.get(AIResponseRecommendation, record.id)
    assert fresh.recommendations[0] == before
    assert db_session.query(AIResponseApproval).count() == 1


def test_response_never_leaks_orm_or_execution_fields(client, db_session):
    """Schema discipline: the approval JSON carries exactly the frozen read
    fields — no ORM repr, no executed/attempts/payload style keys."""
    record = _seed(db_session)
    body = client.post(_approve_url(record), json={"reviewer": "analyst-1"}).json()

    assert set(body.keys()) == {
        "id",
        "recommendation_id",
        "status",
        "reviewer",
        "reviewed_at",
        "review_comment",
        "created_at",
        "updated_at",
    }
