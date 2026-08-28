"""Phase 3.1.1: execution_log data-model freeze tests.

Locks the frozen shape of ExecutionLog before Migration/Service/API land
(design doc docs/design/phase3-response-execution.md):

- vocabulary: 5 execute decisions + 3 compensate decisions, with the legal
  decision x direction combinations enforced by a DB CHECK
- append-only audit fact: no updated_at, created_at is server-stamped
- idempotency + identity: three partial unique indexes (constraints 1/2/3)
  hold in SQLite AND PostgreSQL (last line of defense, D14)
- action / target are a server-side snapshot, detail is JSON audit payload
- relationship to AIResponseApproval registered both sides

Model tests ONLY — no Service, no API, no Executor (3.1.1 gate).
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import (
    APPROVAL_DECISIONS,
    COMPENSATE_DECISIONS,
    EXECUTE_DECISIONS,
    EXECUTION_DECISIONS,
    EXECUTION_DIRECTIONS,
    EXECUTION_LEGAL_COMBINATIONS,
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
)


def _seed_approved(db_session) -> AIResponseApproval:
    """One committed event + recommendation + approved decision."""
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
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status="approved",
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _row(db_session, approval, **overrides) -> ExecutionLog:
    """One execute-direction requested row; overrides drive every attack."""
    defaults = dict(
        execution_id=uuid.uuid4(),
        approval_id=approval.id,
        decision="requested",
        direction="execute",
        action="block_source_ip",
        target="203.0.113.7",
        operator="ops-1",
        detail={"note": "intent accepted"},
    )
    defaults.update(overrides)
    row = ExecutionLog(**defaults)
    db_session.add(row)
    return row


def _partial_where(table, index_name) -> str:
    index = next(index for index in table.indexes if index.name == index_name)
    return index.dialect_options["sqlite"]["where"].text


class TestExecutionVocabulary:
    def test_execute_decisions_frozen(self):
        assert EXECUTE_DECISIONS == frozenset(
            {"requested", "guard_rejected", "dispatched", "succeeded", "failed"}
        )

    def test_compensate_decisions_frozen(self):
        assert COMPENSATE_DECISIONS == frozenset(
            {"compensation_requested", "compensation_succeeded", "compensation_failed"}
        )

    def test_full_vocabulary_is_disjoint_union(self):
        assert EXECUTION_DECISIONS == EXECUTE_DECISIONS | COMPENSATE_DECISIONS
        assert not (EXECUTE_DECISIONS & COMPENSATE_DECISIONS)
        assert len(EXECUTION_DECISIONS) == 8

    def test_directions_frozen(self):
        assert EXECUTION_DIRECTIONS == frozenset({"execute", "compensate"})

    def test_legal_combinations_are_exactly_eight_pairs(self):
        assert len(EXECUTION_LEGAL_COMBINATIONS) == 8
        assert all(
            (decision, "execute") in EXECUTION_LEGAL_COMBINATIONS
            for decision in EXECUTE_DECISIONS
        )
        assert all(
            (decision, "compensate") in EXECUTION_LEGAL_COMBINATIONS
            for decision in COMPENSATE_DECISIONS
        )
        assert ("requested", "compensate") not in EXECUTION_LEGAL_COMBINATIONS
        assert ("compensation_requested", "execute") not in EXECUTION_LEGAL_COMBINATIONS

    def test_approval_layer_words_banned_from_execution_vocabulary(self):
        # Execution audit facts never reuse the approval queue vocabulary.
        assert not (APPROVAL_DECISIONS & EXECUTION_DECISIONS)
        assert "pending" not in EXECUTION_DECISIONS


class TestExecutionLogModelShape:
    def test_table_name(self):
        assert ExecutionLog.__tablename__ == "execution_log"

    def test_table_shape_frozen_eleven_columns(self):
        columns = {c.name for c in ExecutionLog.__table__.columns}
        assert columns == {
            "id", "execution_id", "approval_id", "decision", "direction",
            "action", "target", "compensates_execution_id", "operator",
            "detail", "created_at",
        }
        # Append-only rows never update — no updated_at by design.
        assert "updated_at" not in columns

    def test_check_constraint_guards_decision_direction(self):
        checks = [
            constraint
            for constraint in ExecutionLog.__table__.constraints
            if type(constraint).__name__ == "CheckConstraint"
        ]
        assert len(checks) == 1
        sqltext = checks[0].sqltext.text
        assert checks[0].name == "ck_execution_log_decision_direction"
        assert "direction = 'execute'" in sqltext
        assert "direction = 'compensate'" in sqltext
        assert "'requested'" in sqltext
        assert "'compensation_requested'" in sqltext

    def test_partial_unique_1_execution_id_requested(self):
        table = ExecutionLog.__table__
        index = next(i for i in table.indexes if i.name == "ux_execution_log_execution_id_requested")
        assert index.unique is True
        assert _partial_where(table, "ux_execution_log_execution_id_requested") == (
            "decision = 'requested'"
        )

    def test_partial_unique_2_approval_lifecycle_slot(self):
        # requested is the lifecycle slot-holder: every chain holds exactly
        # one, so one approval can never start a second forward execution.
        table = ExecutionLog.__table__
        index = next(i for i in table.indexes if i.name == "ux_execution_log_approval_id_execute")
        assert index.unique is True
        assert _partial_where(table, "ux_execution_log_approval_id_execute") == (
            "direction = 'execute' AND decision = 'requested'"
        )

    def test_partial_unique_3_one_compensation_per_original(self):
        table = ExecutionLog.__table__
        index = next(i for i in table.indexes if i.name == "ux_execution_log_compensates_requested")
        assert index.unique is True
        assert _partial_where(table, "ux_execution_log_compensates_requested") == (
            "decision = 'compensation_requested'"
        )

    def test_approval_fk_protects_audit_on_delete(self):
        # Append-only audit must never disappear with a deleted approval:
        # NO ACTION, not CASCADE (migration-review 2026-08-28; the project
        # has no approval deletion path, so this is the frozen semantics).
        fk = next(
            constraint
            for constraint in ExecutionLog.__table__.constraints
            if type(constraint).__name__ == "ForeignKeyConstraint"
        )
        assert fk.referred_table.name == "ai_response_approvals"
        assert fk.ondelete == "NO ACTION"

    def test_nullable_semantics(self):
        columns = ExecutionLog.__table__.columns
        required = [
            "id", "execution_id", "approval_id", "decision", "direction",
            "action", "target", "operator", "detail", "created_at",
        ]
        for name in required:
            assert columns[name].nullable is False, name
        # Only the compensation back-link may be NULL (execute rows).
        assert columns["compensates_execution_id"].nullable is True

    def test_created_at_is_server_stamped_only(self):
        column = ExecutionLog.__table__.columns["created_at"]
        assert column.server_default is not None  # CURRENT_TIMESTAMP
        assert column.default is None  # never accepted from the client

    def test_relationships_registered_both_sides(self):
        assert "approval" in ExecutionLog.__mapper__.relationships
        assert "executions" in AIResponseApproval.__mapper__.relationships
        # One approval -> many audit rows (chain + compensation).
        assert AIResponseApproval.__mapper__.relationships["executions"].uselist is True


class TestDecisionDirectionCheck:
    @pytest.mark.parametrize("decision", sorted(EXECUTE_DECISIONS))
    def test_legal_execute_rows_persist(self, db_session, decision):
        approval = _seed_approved(db_session)
        _row(db_session, approval, decision=decision)
        db_session.commit()
        assert db_session.query(ExecutionLog).count() == 1

    @pytest.mark.parametrize("decision", sorted(COMPENSATE_DECISIONS))
    def test_legal_compensate_rows_persist(self, db_session, decision):
        approval = _seed_approved(db_session)
        _row(
            db_session,
            approval,
            decision=decision,
            direction="compensate",
            compensates_execution_id=uuid.uuid4(),
        )
        db_session.commit()
        row = db_session.query(ExecutionLog).one()
        assert row.direction == "compensate"
        assert row.compensates_execution_id is not None

    @pytest.mark.parametrize(
        "decision,direction",
        [
            ("requested", "compensate"),
            ("dispatched", "compensate"),
            ("succeeded", "compensate"),
            ("compensation_requested", "execute"),
            ("compensation_succeeded", "execute"),
            ("compensation_failed", "execute"),
        ],
    )
    def test_cross_direction_rows_rejected_by_check(self, db_session, decision, direction):
        approval = _seed_approved(db_session)
        _row(db_session, approval, decision=decision, direction=direction)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.query(ExecutionLog).count() == 0

    @pytest.mark.parametrize("illegal_decision", ["pending", "approved", ""])
    def test_foreign_vocabulary_rejected_by_check(self, db_session, illegal_decision):
        approval = _seed_approved(db_session)
        _row(db_session, approval, decision=illegal_decision)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.query(ExecutionLog).count() == 0


class TestPartialUniqueEnforcement:
    def test_duplicate_requested_same_execution_id_rejected(self, db_session):
        # Constraint 1 — idempotency key (D14 last line of defense).
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        _row(db_session, approval, execution_id=execution_id)
        db_session.commit()

        second_approval = _seed_approved(db_session)
        _row(db_session, second_approval, execution_id=execution_id)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.query(ExecutionLog).count() == 1

    def test_full_chain_appends_under_one_execution_id(self, db_session):
        # Chain rows share execution_id AND approval_id; only the single
        # requested row sits in the partial unique indexes, so the chain
        # requested -> dispatched -> failed appends cleanly.
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        _row(db_session, approval, execution_id=execution_id)
        _row(db_session, approval, execution_id=execution_id, decision="dispatched",
             detail={"adapter": "mock"})
        _row(db_session, approval, execution_id=execution_id, decision="failed",
             detail={"classification": "adapter_error"})
        db_session.commit()
        assert db_session.query(ExecutionLog).count() == 3

    def test_second_forward_execution_of_same_approval_rejected(self, db_session):
        # Constraint 2 — lifecycle uniqueness: even after terminal failed,
        # a fresh requested row for the same approval must be blocked.
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        _row(db_session, approval, execution_id=execution_id)
        _row(db_session, approval, execution_id=execution_id, decision="dispatched")
        _row(db_session, approval, execution_id=execution_id, decision="failed")
        db_session.commit()

        _row(db_session, approval, execution_id=uuid.uuid4())  # retry attempt
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.query(ExecutionLog).count() == 3

    def test_compensation_rows_do_not_occupy_forward_slot(self, db_session):
        # Compensation inherits approval_id (D11) but reads direction =
        # compensate, so the lifecycle index must not fire on it.
        approval = _seed_approved(db_session)
        execution_id = uuid.uuid4()
        _row(db_session, approval, execution_id=execution_id)
        _row(db_session, approval, execution_id=execution_id, decision="dispatched")
        _row(db_session, approval, execution_id=execution_id, decision="succeeded")
        _row(
            db_session,
            approval,
            execution_id=uuid.uuid4(),
            decision="compensation_requested",
            direction="compensate",
            compensates_execution_id=execution_id,
        )
        db_session.commit()
        assert db_session.query(ExecutionLog).count() == 4

    def test_second_compensation_of_same_original_rejected(self, db_session):
        # Constraint 3 — one original execution -> at most one compensation
        # request; the compensation_succeeded append still fits.
        approval = _seed_approved(db_session)
        original_id = uuid.uuid4()
        _row(db_session, approval, execution_id=original_id)
        _row(db_session, approval, execution_id=original_id, decision="failed")

        compensation_id = uuid.uuid4()
        _row(db_session, approval, execution_id=compensation_id,
             decision="compensation_requested", direction="compensate",
             compensates_execution_id=original_id)
        db_session.commit()

        _row(db_session, approval, execution_id=compensation_id,
             decision="compensation_succeeded", direction="compensate",
             compensates_execution_id=original_id)
        db_session.commit()
        assert db_session.query(ExecutionLog).count() == 4

        _row(db_session, approval, execution_id=uuid.uuid4(),
             decision="compensation_requested", direction="compensate",
             compensates_execution_id=original_id)  # duplicate compensation
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
        assert db_session.query(ExecutionLog).count() == 4


class TestSnapshotAndDetail:
    def test_action_target_snapshot_round_trips(self, db_session):
        approval = _seed_approved(db_session)
        _row(db_session, approval, action="isolate_host", target="host-42.internal")
        db_session.commit()
        db_session.expire_all()
        row = db_session.query(ExecutionLog).one()
        assert row.action == "isolate_host"
        assert row.target == "host-42.internal"

    def test_detail_json_round_trips_nested(self, db_session):
        approval = _seed_approved(db_session)
        detail = {
            "guard": {"result": "pass"},
            "dispatch": {"adapter": "mock", "echo": {"action": "block_source_ip"}},
            "raw_response": {"status": "ok", "items": [1, 2]},
        }
        _row(db_session, approval, detail=detail)
        db_session.commit()
        db_session.expire_all()
        assert db_session.query(ExecutionLog).one().detail == detail

    def test_detail_defaults_to_empty_object(self, db_session):
        approval = _seed_approved(db_session)
        # Built by hand so the detail attribute is truly never assigned.
        db_session.add(ExecutionLog(
            execution_id=uuid.uuid4(),
            approval_id=approval.id,
            decision="requested",
            direction="execute",
            action="block_source_ip",
            target="203.0.113.7",
            operator="ops-1",
        ))
        db_session.commit()
        assert db_session.query(ExecutionLog).one().detail == {}


class TestTimestampAndRelationship:
    def test_created_at_stamped_by_server(self, db_session):
        approval = _seed_approved(db_session)
        row = _row(db_session, approval)
        db_session.commit()
        assert row.created_at is not None

    def test_approval_relationship_both_directions(self, db_session):
        approval = _seed_approved(db_session)
        row = _row(db_session, approval)
        db_session.commit()
        db_session.expire_all()

        fresh_row = db_session.query(ExecutionLog).one()
        assert fresh_row.approval.id == approval.id
        fresh_approval = db_session.get(AIResponseApproval, approval.id)
        assert [r.id for r in fresh_approval.executions] == [row.id]
