"""Step 13.2: AIResponseApprovalService tests.

Recommendation -> pending (derived) -> approve()/reject() -> terminal
decision row. CI-stable: pure database semantics, no provider involved.
Covers the derived-pending semantics (absence, never a stored status),
one-shot INSERT finality, server-stamped reviewed_at, the flush-not-commit
discipline, the advisory-only boundary (approve/reject execute NOTHING) and
the typed conversion of the UNIQUE concurrency violation.
"""
import inspect
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
from app.services.ai import (
    AIEventNotFound,
    AIResponseAlreadyReviewed,
    AIResponseApprovalNotFound,
    AIResponseApprovalService,
)


def _seed(db_session, minutes_ago: int = 0, score: int = 85) -> AIResponseRecommendation:
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
            score=score,
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


def _service() -> AIResponseApprovalService:
    return AIResponseApprovalService()


# -------------------------------------------------- pending = derived absence


def test_unreviewed_recommendation_is_pending(db_session):
    record = _seed(db_session)
    pending = _service().get_pending_approvals(db_session)
    assert [r.id for r in pending] == [record.id]


def test_approved_recommendation_leaves_pending_queue(db_session):
    record = _seed(db_session)
    service = _service()
    service.approve(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    assert service.get_pending_approvals(db_session) == []


def test_rejected_recommendation_leaves_pending_queue(db_session):
    record = _seed(db_session)
    service = _service()
    service.reject(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    assert service.get_pending_approvals(db_session) == []


def test_pending_filters_mixed_queue(db_session):
    """Only unreviewed recommendations surface; decided ones never do."""
    kept = _seed(db_session, minutes_ago=5)
    approved = _seed(db_session, minutes_ago=4)
    rejected = _seed(db_session, minutes_ago=3)
    service = _service()
    service.approve(db_session, approved.id, reviewer="analyst-1")
    service.reject(db_session, rejected.id, reviewer="analyst-2")
    db_session.commit()

    pending = service.get_pending_approvals(db_session)
    assert [r.id for r in pending] == [kept.id]


def test_pending_ordered_first_in_first_reviewed(db_session):
    """Frozen ordering: created_at ASC — the oldest item tops the queue."""
    oldest = _seed(db_session, minutes_ago=10)
    middle = _seed(db_session, minutes_ago=5)
    newest = _seed(db_session)

    pending = _service().get_pending_approvals(db_session)
    assert [r.id for r in pending] == [oldest.id, middle.id, newest.id]


def test_pending_tie_broken_by_id_asc(db_session):
    """Same created_at falls back to id ASC — deterministic ordering."""
    anchor = datetime.now(timezone.utc) - timedelta(hours=1)
    first = _seed(db_session)
    second = _seed(db_session)
    first.created_at = anchor
    second.created_at = anchor
    db_session.commit()

    pending = _service().get_pending_approvals(db_session)
    assert [r.id for r in pending] == sorted([first.id, second.id])


# ------------------------------------------------------- one-shot decisions


def test_approve_inserts_approved_decision(db_session):
    record = _seed(db_session)
    approval = _service().approve(
        db_session, record.id, reviewer="analyst-1", review_comment="confirmed by SOC"
    )
    db_session.commit()

    db_session.expire_all()
    fresh = db_session.get(AIResponseApproval, approval.id)
    assert fresh.recommendation_id == record.id
    assert fresh.status == "approved"
    assert fresh.reviewer == "analyst-1"
    assert fresh.review_comment == "confirmed by SOC"


def test_reject_inserts_rejected_decision(db_session):
    record = _seed(db_session)
    approval = _service().reject(db_session, record.id, reviewer="analyst-2")
    db_session.commit()

    db_session.expire_all()
    fresh = db_session.get(AIResponseApproval, approval.id)
    assert fresh.recommendation_id == record.id
    assert fresh.status == "rejected"
    assert fresh.reviewer == "analyst-2"


def test_reviewer_stored_verbatim(db_session):
    """reviewer is the human decision-maker — never the AI or an action."""
    record = _seed(db_session)
    approval = _service().approve(db_session, record.id, reviewer="soc-shift-a")
    db_session.commit()
    assert approval.reviewer == "soc-shift-a"
    assert approval.reviewer not in ("mock", "block_source_ip")


def test_reviewed_at_stamped_by_server(db_session):
    record = _seed(db_session)
    before = datetime.now(timezone.utc)
    approval = _service().approve(db_session, record.id, reviewer="analyst-1")
    after = datetime.now(timezone.utc)
    db_session.commit()

    stamped = approval.reviewed_at
    if stamped.tzinfo is None:  # SQLite round-trips naive datetimes
        stamped = stamped.replace(tzinfo=timezone.utc)
    assert before <= stamped <= after


def test_service_signature_refuses_client_supplied_reviewed_at(db_session):
    """The audit clock is stamped inside the service — the signature has no
    reviewed_at parameter, so no caller (API included) can backdate it."""
    for method in (AIResponseApprovalService.approve, AIResponseApprovalService.reject):
        assert "reviewed_at" not in inspect.signature(method).parameters

    record = _seed(db_session)
    with pytest.raises(TypeError):
        _service().approve(
            db_session,
            record.id,
            reviewer="analyst-1",
            reviewed_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
    db_session.rollback()
    assert db_session.query(AIResponseApproval).count() == 0


@pytest.mark.parametrize(
    "comment", [None, "", "Confirmed malicious activity"]
)
def test_comment_variants_follow_schema_rules(db_session, comment):
    record = _seed(db_session)
    approval = _service().approve(
        db_session, record.id, reviewer="analyst-1", review_comment=comment
    )
    db_session.commit()
    assert approval.review_comment == comment


# --------------------------------------------------- flush, never commit


def test_approve_flushes_but_does_not_commit(db_session):
    record = _seed(db_session)
    approval = _service().approve(db_session, record.id, reviewer="analyst-1")
    assert approval.id is not None  # flushed (id assigned)

    db_session.rollback()
    assert db_session.query(AIResponseApproval).count() == 0


def test_reject_flushes_but_does_not_commit(db_session):
    record = _seed(db_session)
    _service().reject(db_session, record.id, reviewer="analyst-1")
    db_session.rollback()
    assert db_session.query(AIResponseApproval).count() == 0


# ------------------------------------------------------- safety boundaries


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_decision_executes_nothing(db_session, decision):
    """Approve != Execute (and Reject != Execute): the decision only adds
    one approval row — EventRisk is untouched, no Incident appears and the
    recommendation itself is never rewritten."""
    record = _seed(db_session, score=85)
    before = record.recommendations

    getattr(_service(), decision)(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    risk = db_session.query(EventRisk).one()
    assert risk.score == 85 and risk.level == "high"
    assert db_session.query(Incident).count() == 0
    db_session.expire_all()
    fresh = db_session.get(AIResponseRecommendation, record.id)
    assert fresh.recommendations == before  # advice is immutable advice
    assert db_session.query(AIResponseApproval).count() == 1


# ------------------------------------------- finality + concurrency defense


def test_second_approve_is_rejected_and_original_stands(db_session):
    record = _seed(db_session)
    service = _service()
    service.approve(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    with pytest.raises(AIResponseAlreadyReviewed):
        service.approve(db_session, record.id, reviewer="analyst-2")
    db_session.rollback()

    fresh = db_session.get(AIResponseRecommendation, record.id)
    assert fresh.approval.status == "approved"
    assert fresh.approval.reviewer == "analyst-1"
    assert db_session.query(AIResponseApproval).count() == 1


def test_reject_after_approve_is_rejected(db_session):
    record = _seed(db_session)
    service = _service()
    service.approve(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    with pytest.raises(AIResponseAlreadyReviewed):
        service.reject(db_session, record.id, reviewer="analyst-2")
    db_session.rollback()
    assert db_session.get(AIResponseRecommendation, record.id).approval.status == "approved"


def test_approve_after_reject_is_rejected(db_session):
    record = _seed(db_session)
    service = _service()
    service.reject(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    with pytest.raises(AIResponseAlreadyReviewed):
        service.approve(db_session, record.id, reviewer="analyst-2")
    db_session.rollback()
    assert db_session.get(AIResponseRecommendation, record.id).approval.status == "rejected"


def test_racing_insert_surfaces_as_typed_domain_error(db_session):
    """Concurrency last line of defense: an approval inserted behind the
    service's back (racing request) trips the UNIQUE constraint at flush —
    the service must translate the IntegrityError, never leak raw SQL."""
    record = _seed(db_session)
    # Unflushed duplicate: invisible to the pre-check, fatal at flush time.
    db_session.add(
        AIResponseApproval(
            recommendation_id=record.id,
            status="approved",
            reviewer="racing-analyst",
            reviewed_at=datetime.now(timezone.utc),
        )
    )

    with pytest.raises(AIResponseAlreadyReviewed, match="concurrently"):
        _service().approve(db_session, record.id, reviewer="analyst-1")
    db_session.rollback()

    assert _service().get_pending_approvals(db_session)[0].id == record.id


# ------------------------------------------------------------- error paths


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_unknown_recommendation_raises_not_found(db_session, decision):
    """No third lookup taxonomy: missing recommendation reuses AIEventNotFound."""
    with pytest.raises(AIEventNotFound):
        getattr(_service(), decision)(db_session, uuid.uuid4(), reviewer="analyst-1")
    assert db_session.query(AIResponseApproval).count() == 0


def test_get_approval_round_trips(db_session):
    record = _seed(db_session)
    approval = _service().approve(db_session, record.id, reviewer="analyst-1")
    db_session.commit()

    fresh = _service().get_approval(db_session, approval.id)
    assert fresh.status == "approved"
    assert fresh.recommendation_id == record.id


def test_get_approval_missing_raises_not_found(db_session):
    with pytest.raises(AIResponseApprovalNotFound):
        _service().get_approval(db_session, uuid.uuid4())
