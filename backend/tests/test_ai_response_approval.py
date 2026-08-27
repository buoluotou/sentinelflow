"""Step 13.1: Approval Queue protocol / data-model freeze tests.

Locks the frozen shape of AIResponseApproval before Service/API/UI land:

- vocabulary: pending / approved / rejected, with "pending" DERIVED (never
  persisted) and execution-layer words banned from the storage vocabulary
- at most ONE approval per recommendation (unique FK) and a decision is
  final (INSERT-only discipline, no state machine)
- storage guard: the CHECK constraint rejects anything but the terminal
  human decisions — even "pending"
- Approve != Execute: the model carries no reference to execution, EventRisk
  or Incident — a decision row is pure audit trail
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.models import (
    APPROVAL_DECISIONS,
    APPROVAL_STATUSES,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
)


def _seed_recommendation(db_session) -> AIResponseRecommendation:
    """One committed event + recommendation to hang a decision on."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint="c" * 64,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
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
    db_session.commit()
    return record


def _approve(db_session, record, **overrides) -> AIResponseApproval:
    defaults = dict(
        recommendation_id=record.id,
        status="approved",
        reviewer="analyst-1",
        reviewed_at=datetime.now(timezone.utc),
        review_comment="confirmed by SOC",
    )
    defaults.update(overrides)
    approval = AIResponseApproval(**defaults)
    db_session.add(approval)
    return approval


class TestApprovalVocabulary:
    def test_frozen_status_vocabulary(self):
        assert APPROVAL_STATUSES == frozenset({"pending", "approved", "rejected"})

    def test_persistable_decisions_exclude_pending(self):
        # pending is a DERIVED queue state (no approval row), never a stored one
        assert APPROVAL_DECISIONS == frozenset({"approved", "rejected"})
        assert APPROVAL_DECISIONS < APPROVAL_STATUSES
        assert "pending" not in APPROVAL_DECISIONS

    def test_execution_layer_words_are_banned(self):
        # Step 13 records decisions only — execution states belong to Step 14
        execution_words = {"executing", "executed", "failed", "rolled_back"}
        assert not (execution_words & APPROVAL_STATUSES)
        assert not (execution_words & APPROVAL_DECISIONS)


class TestApprovalModelShape:
    def test_table_shape(self):
        assert AIResponseApproval.__tablename__ == "ai_response_approvals"
        columns = {c.name for c in AIResponseApproval.__table__.columns}
        assert columns == {
            "id", "recommendation_id", "status", "reviewer", "reviewed_at",
            "review_comment", "created_at", "updated_at",
        }

    def test_recommendation_id_is_unique_one_to_one(self):
        uniques = [
            constraint.columns.keys()
            for constraint in AIResponseApproval.__table__.constraints
            if type(constraint).__name__ == "UniqueConstraint"
        ]
        assert ["recommendation_id"] in uniques

    def test_status_check_constraint_only_allows_terminal_decisions(self):
        checks = [
            constraint.sqltext.text
            for constraint in AIResponseApproval.__table__.constraints
            if type(constraint).__name__ == "CheckConstraint"
        ]
        assert any("approved" in c and "rejected" in c for c in checks)

    def test_reviewed_at_is_required_and_never_client_supplied(self):
        column = AIResponseApproval.__table__.columns["reviewed_at"]
        assert column.nullable is False
        # No DB default: the Service stamps the server clock at decision time,
        # so the audit trail cannot be backdated from the client.
        assert column.server_default is None and column.default is None

    def test_review_comment_is_optional(self):
        assert AIResponseApproval.__table__.columns["review_comment"].nullable is True

    def test_recommendation_fk_cascades(self):
        fk = next(
            constraint
            for constraint in AIResponseApproval.__table__.constraints
            if type(constraint).__name__ == "ForeignKeyConstraint"
        )
        assert fk.referred_table.name == "ai_response_recommendations"
        assert fk.ondelete == "CASCADE"

    def test_relationships_registered_both_sides(self):
        assert "approval" in AIResponseRecommendation.__mapper__.relationships
        assert AIResponseRecommendation.__mapper__.relationships["approval"].uselist is False
        assert "recommendation" in AIResponseApproval.__mapper__.relationships


class TestApprovalPersistence:
    def test_approved_decision_round_trips(self, db_session):
        record = _seed_recommendation(db_session)
        assert record.approval is None  # pending is derived: no row yet

        _approve(db_session, record)
        db_session.commit()

        db_session.expire_all()
        fresh = db_session.get(AIResponseRecommendation, record.id)
        assert fresh.approval is not None
        assert fresh.approval.status == "approved"
        assert fresh.approval.reviewer == "analyst-1"
        assert fresh.approval.review_comment == "confirmed by SOC"
        assert fresh.approval.reviewed_at is not None

    def test_rejected_decision_without_comment_round_trips(self, db_session):
        record = _seed_recommendation(db_session)
        _approve(db_session, record, status="rejected", review_comment=None)
        db_session.commit()

        db_session.expire_all()
        fresh = db_session.get(AIResponseRecommendation, record.id)
        assert fresh.approval.status == "rejected"
        assert fresh.approval.review_comment is None

    def test_second_decision_on_same_recommendation_is_rejected(self, db_session):
        record = _seed_recommendation(db_session)
        _approve(db_session, record)
        db_session.commit()

        _approve(db_session, record, status="rejected", reviewer="analyst-2")
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

        # The original decision stands untouched (no re-judging).
        fresh = db_session.get(AIResponseRecommendation, record.id)
        assert fresh.approval.status == "approved"
        assert fresh.approval.reviewer == "analyst-1"

    def test_two_recommendations_of_one_event_each_get_own_decision(self, db_session):
        # History semantics: a fresh recommendation means a fresh approval.
        record = _seed_recommendation(db_session)
        second = AIResponseRecommendation(
            alert_group=record.alert_group,
            provider="mock",
            model="mock-deterministic",
            overall_rationale="[mock] second run",
            recommendations=[],
            confidence=0.4,
        )
        db_session.add(second)
        db_session.flush()

        _approve(db_session, record, status="approved")
        _approve(db_session, second, status="rejected", reviewer="analyst-2")
        db_session.commit()

        assert record.approval.status == "approved"
        assert second.approval.status == "rejected"

    @pytest.mark.parametrize("illegal_status", ["pending", "executing", "executed", ""])
    def test_storage_rejects_anything_but_terminal_decisions(self, db_session, illegal_status):
        record = _seed_recommendation(db_session)
        _approve(db_session, record, status=illegal_status)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.get(AIResponseRecommendation, record.id).approval is None


class TestApprovalMigration:
    def test_migration_0008_links_0007(self):
        # migrations/ is an Alembic script dir, not an importable package
        # (no __init__.py): exec the file directly, as alembic itself does.
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "versions"
            / "0008_add_ai_response_approvals.py"
        )
        namespace: dict = {}
        exec(path.read_text(encoding="utf-8"), namespace)
        assert namespace["revision"] == "0008"
        assert namespace["down_revision"] == "0007"
        assert callable(namespace["upgrade"])
        assert callable(namespace["downgrade"])
