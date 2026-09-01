"""Phase 3.1.6: Execute / Compensation Service tests — the first layer
that produces REAL execution facts.

Locks the complete chain offline at pure Service level:

    Approval + snapshot + State Machine + Guard + Executor -> execution_log

Coverage map (acceptance gate):
- Execute success / guard rejection / adapter failure x3 / protocol
  violation — full decision chains asserted row by row
- Untrusted inputs: action/target only from the server snapshot;
  execution_id is identity only — replays with different facts are 409
- 404/409 boundaries: missing approval leaves ZERO rows; conflicts raise
  typed exceptions; Service pre-check AND DB partial indexes map to the
  same family (D14)
- Compensation: fresh execution_id, server-inherited approval/action/
  target, at most one compensation per original (constraint 3)
- Guard rejection boundaries: 404 no row vs requested->guard_rejected
- Risk / Incident / Recommendation / Approval immutability
- Transaction discipline: add+flush only, NEVER commit (API owns it)

No API, no Token, no frontend, no external systems.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    EventRisk,
    ExecutionLog,
    Incident,
)
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.guard import ApprovalNotFound, EXECUTABLE_ACTIONS
from app.services.executions.mock import MockExecutor
from app.services.executions.service import (
    COMPENSATABLE_STATES,
    ApprovalAlreadyExecuted,
    CompensationOfCompensation,
    ExecutionAlreadyCompensated,
    ExecutionConflictError,
    ExecutionIdAlreadyBound,
    ExecutionNotFound,
    ExecutionResult,
    ExecutionServiceError,
    OriginalExecutionNotTerminal,
    compensate_response,
    execute_response,
)


# --------------------------------------------------------------------------
# Seeding helpers
# --------------------------------------------------------------------------
def seed_approved(db_session, *, status="approved", recommendations=None):
    """alert_group -> recommendation -> approval chain; returns approval."""
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
        recommendations=recommendations
        or [{"action": "block_source_ip", "target": "203.0.113.10", "rationale": "abuse"}],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status=status,
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.flush()
    return approval


def execute_ok(db_session, approval=None, executor=None, **overrides):
    """One successful forward execution (requested->dispatched->succeeded)."""
    approval = approval or seed_approved(db_session)
    kwargs = dict(
        approval_id=approval.id,
        execution_id=uuid.uuid4(),
        operator="ops-1",
        executor=executor or MockExecutor(),
    )
    kwargs.update(overrides)
    return execute_response(db_session, **kwargs)


def rows_for(db_session, execution_id):
    return list(
        db_session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


def all_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


class NoCapabilityExecutor:
    """Supports nothing — drives G4 capability misses."""

    name = "incapable"

    def supports(self, action):
        return False

    def supports_compensation(self, action):
        return False


class ExecuteOnlyExecutor(ResponseExecutor):
    """Supports execute of every executable action but NO compensation."""

    def __init__(self):
        self._inner = MockExecutor()

    @property
    def name(self):
        return "execute-only"

    def supports(self, action):
        return action in EXECUTABLE_ACTIONS

    def supports_compensation(self, action):
        return False

    def execute(self, dispatch):
        return self._inner.execute(dispatch)

    def compensate(self, dispatch):
        raise AssertionError("compensate must never be reached")


class BadOutcomeExecutor(ResponseExecutor):
    """Answers the forbidden word `dispatched` — the platform parse must
    judge it as protocol_violation (D8/D9)."""

    @property
    def name(self):
        return "bad-outcome"

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return True

    def execute(self, dispatch):
        return {"status": "dispatched"}

    def compensate(self, dispatch):
        return {"status": "dispatched"}


# --------------------------------------------------------------------------
# Forward execution — happy path
# --------------------------------------------------------------------------
class TestExecuteSuccessChain:
    def test_full_chain_requested_dispatched_succeeded(self, db_session):
        approval = seed_approved(db_session)
        execution_id = uuid.uuid4()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=execution_id,
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert result.chain == ("requested", "dispatched", "succeeded")
        assert result.final_decision == "succeeded"
        assert result.direction == "execute"
        rows = rows_for(db_session, execution_id)
        assert [row.decision for row in rows] == list(result.chain)

    def test_action_and_target_come_from_the_server_snapshot(self, db_session):
        approval = seed_approved(
            db_session,
            recommendations=[
                {"action": "isolate_host", "target": "WS-042", "rationale": "c2"}
            ],
        )
        result = execute_ok(db_session, approval)
        assert all(row.action == "isolate_host" for row in result.rows)
        assert all(row.target == "WS-042" for row in result.rows)

    def test_requested_row_is_first_and_carries_identity(self, db_session):
        approval = seed_approved(db_session)
        execution_id = uuid.uuid4()
        execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=execution_id,
            operator="ops-7",
            executor=MockExecutor(),
        )
        rows = rows_for(db_session, execution_id)
        assert rows[0].decision == "requested"  # constraint 10 invariant
        assert all(row.execution_id == execution_id for row in rows)
        assert all(row.approval_id == approval.id for row in rows)
        assert all(row.operator == "ops-7" for row in rows)
        assert all(row.compensates_execution_id is None for row in rows)

    def test_terminal_row_carries_dry_run_detail_and_raw_response(self, db_session):
        result = execute_ok(db_session)
        terminal = result.rows[-1]
        assert terminal.detail["dry_run"]["executor"] == "mock"
        assert terminal.detail["dry_run"]["operation"] == "execute"
        assert terminal.detail["raw_response"] == {"mock": "ok", "operation": "execute"}

    def test_result_is_a_frozen_dataclass(self, db_session):
        result = execute_ok(db_session)
        assert isinstance(result, ExecutionResult)
        with pytest.raises(Exception):
            result.final_decision = "tampered"


# --------------------------------------------------------------------------
# Guard rejection — requested -> guard_rejected (D13, same transaction)
# --------------------------------------------------------------------------
class TestGuardRejectionChains:
    def test_rejected_approval_status(self, db_session):
        approval = seed_approved(db_session, status="rejected")
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert result.chain == ("requested", "guard_rejected")
        rejected = result.rows[-1]
        assert rejected.detail["code"] == "approval_not_approved"
        assert rejected.detail["reason"]

    def test_broken_snapshot_is_recorded_as_recommendation_missing(self, db_session):
        approval = seed_approved(db_session)
        approval.recommendation.recommendations = []
        db_session.flush()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert result.chain == ("requested", "guard_rejected")
        assert result.rows[-1].detail["code"] == "recommendation_missing"

    def test_advisory_action_in_snapshot_is_not_executable(self, db_session):
        approval = seed_approved(
            db_session,
            recommendations=[
                {"action": "monitor_only", "target": "edge-gw", "rationale": "watch"}
            ],
        )
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert result.chain == ("requested", "guard_rejected")
        assert result.rows[-1].detail["code"] == "action_not_executable"

    def test_g4_capability_miss_is_a_business_rejection(self, db_session):
        approval = seed_approved(db_session)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=NoCapabilityExecutor(),
        )
        assert result.chain == ("requested", "guard_rejected")
        assert result.rows[-1].detail["code"] == "executor_unsupported"

    def test_guard_rejection_keeps_the_snapshot_facts_on_both_rows(self, db_session):
        approval = seed_approved(db_session, status="rejected")
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert all(row.action == "block_source_ip" for row in result.rows)
        assert all(row.target == "203.0.113.10" for row in result.rows)


# --------------------------------------------------------------------------
# Adapter failure — dispatched -> failed (never guard_rejected)
# --------------------------------------------------------------------------
class TestAdapterFailure:
    @pytest.mark.parametrize(
        "classification", ["adapter_unavailable", "timeout", "adapter_error"]
    )
    def test_adapter_failure_chain(self, db_session, classification):
        approval = seed_approved(db_session)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(fail_with=classification),
        )
        assert result.chain == ("requested", "dispatched", "failed")
        failed = result.rows[-1]
        assert failed.detail["classification"] == classification
        assert failed.decision != "guard_rejected"  # the executor HAD accepted

    def test_bad_adapter_result_is_judged_protocol_violation(self, db_session):
        approval = seed_approved(db_session)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=BadOutcomeExecutor(),
        )
        assert result.chain == ("requested", "dispatched", "failed")
        failed = result.rows[-1]
        assert failed.detail["classification"] == "protocol_violation"
        assert "dispatched" in failed.detail["violation"]
        assert failed.detail["raw_response"] is None


# --------------------------------------------------------------------------
# 404 / 409 boundaries — the four untrusted inputs
# --------------------------------------------------------------------------
class TestNotFoundBoundary:
    def test_missing_approval_leaves_zero_rows(self, db_session):
        with pytest.raises(ApprovalNotFound):
            execute_response(
                db_session,
                approval_id=uuid.uuid4(),
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=MockExecutor(),
            )
        assert all_rows(db_session) == []

    def test_not_found_exception_stays_in_the_guard_family(self):
        from app.services.executions.guard import ExecutionGuardError

        assert issubclass(ApprovalNotFound, ExecutionGuardError)


class TestLifecycleConflicts:
    def test_reexecute_after_succeeded_is_409(self, db_session):
        approval = seed_approved(db_session)
        first = execute_ok(db_session, approval)
        db_session.commit()
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=MockExecutor(),
            )
        assert exc_info.value.derived_state == "succeeded"
        # The first chain stays exactly as it was — no new rows.
        assert len(rows_for(db_session, first.execution_id)) == 3
        assert len(all_rows(db_session)) == 3

    def test_reexecute_after_failed_is_409_recovery_is_compensation(self, db_session):
        approval = seed_approved(db_session)
        execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(fail_with="timeout"),
        )
        db_session.commit()
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=MockExecutor(),
            )
        assert exc_info.value.derived_state == "failed"

    def test_same_execution_id_different_approval_is_409(self, db_session):
        """Attack: execution_id = A with approval X, then A with Y."""
        approval_x = seed_approved(db_session)
        approval_y = seed_approved(db_session)
        execution_id = uuid.uuid4()
        first = execute_response(
            db_session,
            approval_id=approval_x.id,
            execution_id=execution_id,
            operator="ops-1",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(ExecutionIdAlreadyBound):
            execute_response(
                db_session,
                approval_id=approval_y.id,
                execution_id=execution_id,
                operator="attacker",
                executor=MockExecutor(),
            )
        # The first execution's facts stand, untouched.
        rows = rows_for(db_session, execution_id)
        assert [row.decision for row in rows] == list(first.chain)
        assert all(row.approval_id == approval_x.id for row in rows)
        assert len(all_rows(db_session)) == 3

    def test_identical_replay_is_still_409(self, db_session):
        """execution_id is identity, not an upsert key. The approval slot
        fires first (frozen G3 order), so the typed conflict is
        ApprovalAlreadyExecuted — either way a 409, never an overwrite."""
        approval = seed_approved(db_session)
        execution_id = uuid.uuid4()
        execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=execution_id,
            operator="ops-1",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(ApprovalAlreadyExecuted) as exc_info:
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=execution_id,
                operator="ops-1",
                executor=MockExecutor(),
            )
        assert exc_info.value.derived_state == "succeeded"
        assert len(all_rows(db_session)) == 3

    def test_db_last_line_same_approval_new_execution_id(self, db_session):
        """Race simulation: the Service pre-check misses nothing here, but
        the partial unique index is proven independently by seeding a
        requested row that occupies the approval slot."""
        approval = seed_approved(db_session)
        squatter = ExecutionLog(
            execution_id=uuid.uuid4(),
            approval_id=approval.id,
            decision="requested",
            direction="execute",
            action="block_source_ip",
            target="203.0.113.10",
            operator="ops-0",
            detail={},
        )
        db_session.add(squatter)
        db_session.flush()
        # Pre-check line: the service sees the occupied slot BEFORE insert.
        with pytest.raises(ApprovalAlreadyExecuted):
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=MockExecutor(),
            )

    def test_db_last_line_index_conflicts_translate_to_typed_409(self, db_session):
        """The D14 translation path, proven with real flush collisions on
        EACH partial unique index (in production these fire when a
        concurrent request wins between the pre-check and the flush):
        the typed conflict class matches the pre-check's, and the
        transaction rolls back cleanly."""
        from app.services.executions.service import _translate_integrity_error

        approval = seed_approved(db_session)
        other_approval = seed_approved(db_session)

        def colliding(**overrides):
            payload = dict(
                execution_id=uuid.uuid4(),
                approval_id=approval.id,
                decision="requested",
                direction="execute",
                action="block_source_ip",
                target="203.0.113.10",
                operator="ops-0",
                detail={},
            )
            payload.update(overrides)
            return ExecutionLog(**payload)

        def flush_and_translate():
            try:
                db_session.flush()
            except IntegrityError as exc:
                _translate_integrity_error(exc, db_session)
            else:
                raise AssertionError("expected an IntegrityError at flush")

        # 1) execution_id index — same execution_id, different approval.
        shared_execution_id = uuid.uuid4()
        db_session.add(colliding(execution_id=shared_execution_id))
        db_session.flush()
        db_session.add(
            colliding(execution_id=shared_execution_id, approval_id=other_approval.id)
        )
        with pytest.raises(ExecutionIdAlreadyBound):
            flush_and_translate()

        # 2) approval placeholder index — same approval, fresh execution_id.
        db_session.add(colliding())
        db_session.flush()
        db_session.add(colliding())
        with pytest.raises(ApprovalAlreadyExecuted):
            flush_and_translate()

        # 3) compensates index — same original, second compensation_requested.
        original_id = uuid.uuid4()
        db_session.add(
            colliding(
                decision="compensation_requested",
                direction="compensate",
                compensates_execution_id=original_id,
            )
        )
        db_session.flush()
        db_session.add(
            colliding(
                decision="compensation_requested",
                direction="compensate",
                approval_id=other_approval.id,
                compensates_execution_id=original_id,
            )
        )
        with pytest.raises(ExecutionAlreadyCompensated):
            flush_and_translate()

        # Every collision rolled its whole transaction back — clean slate.
        assert all_rows(db_session) == []

    def test_conflict_family_maps_to_409(self):
        """Forward conflicts stay in the 3.1.4 Guard family, compensation
        conflicts in the Service family — every 409 class carries the
        SAME http_status attribute the API will map (D14)."""
        for conflict in (
            ApprovalAlreadyExecuted,
            ExecutionIdAlreadyBound,
            ExecutionAlreadyCompensated,
            OriginalExecutionNotTerminal,
            CompensationOfCompensation,
        ):
            assert conflict.http_status == 409
        for subclass in (
            ExecutionAlreadyCompensated,
            OriginalExecutionNotTerminal,
            CompensationOfCompensation,
        ):
            assert issubclass(subclass, ExecutionConflictError)
        assert ExecutionNotFound.http_status == 404
        assert issubclass(ExecutionNotFound, ExecutionServiceError)


class TestTargetSmugglingImpossible:
    def test_request_surface_carries_no_action_or_target(self, db_session):
        """execute_response's signature accepts ONLY execution_id /
        approval_id / operator (+ the 3.1.7 audit-metadata comment) —
        there is no parameter through which a client could hand in
        action or target. 3.3.2.4 adds exactly ONE parameter, ``policy``:
        the server-side ExecutionPolicy (built from .env -> Settings,
        never a client fact) — the request surface itself is unchanged."""
        import inspect

        signature = inspect.signature(execute_response)
        assert set(signature.parameters) == {
            "session",
            "approval_id",
            "execution_id",
            "operator",
            "executor",
            "comment",
            "policy",
        }

    def test_replayed_facts_cannot_overwrite_the_snapshot(self, db_session):
        approval = seed_approved(db_session)
        execution_id = uuid.uuid4()
        execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=execution_id,
            operator="ops-1",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(ApprovalAlreadyExecuted):
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=execution_id,
                operator="attacker",
                executor=MockExecutor(),
            )
        rows = rows_for(db_session, execution_id)
        assert all(row.target == "203.0.113.10" for row in rows)


# --------------------------------------------------------------------------
# Compensation
# --------------------------------------------------------------------------
class TestCompensation:
    def test_compensate_succeeded_original(self, db_session):
        approval = seed_approved(db_session)
        original = execute_ok(db_session, approval)
        db_session.commit()
        compensation_id = uuid.uuid4()
        result = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=compensation_id,
            operator="ops-2",
            executor=MockExecutor(),
        )
        assert result.chain == ("compensation_requested", "compensation_succeeded")
        assert result.execution_id == compensation_id
        rows = result.rows
        # Server-side inheritance: approval / action / target copied from
        # the original execution — never from the client.
        assert all(row.approval_id == approval.id for row in rows)
        assert all(row.action == "block_source_ip" for row in rows)
        assert all(row.target == "203.0.113.10" for row in rows)
        assert all(row.compensates_execution_id == original.execution_id for row in rows)
        assert all(row.direction == "compensate" for row in rows)
        # The original chain is untouched.
        assert [row.decision for row in rows_for(db_session, original.execution_id)] == [
            "requested",
            "dispatched",
            "succeeded",
        ]

    def test_compensate_failed_original(self, db_session):
        approval = seed_approved(db_session)
        original = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(fail_with="adapter_error"),
        )
        db_session.commit()
        result = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=MockExecutor(),
        )
        assert result.chain == ("compensation_requested", "compensation_succeeded")

    def test_compensation_adapter_failure(self, db_session):
        original = execute_ok(db_session)
        db_session.commit()
        result = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=MockExecutor(fail_with="timeout"),
        )
        assert result.chain == ("compensation_requested", "compensation_failed")
        assert result.rows[-1].detail["classification"] == "timeout"

    def test_compensation_capability_miss_ends_as_compensation_failed(self, db_session):
        """The compensate vocabulary has no guard_rejected word (CHECK):
        a G4 capability miss terminates as compensation_failed with the
        rejection code in its detail."""
        original = execute_ok(db_session)
        db_session.commit()
        result = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=ExecuteOnlyExecutor(),
        )
        assert result.chain == ("compensation_requested", "compensation_failed")
        assert result.rows[-1].detail["classification"] == "capability_missing"
        assert result.rows[-1].detail["code"] == "executor_unsupported"

    def test_compensation_bad_outcome_is_protocol_violation(self, db_session):
        original = execute_ok(db_session)
        db_session.commit()
        result = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=BadOutcomeExecutor(),
        )
        assert result.chain == ("compensation_requested", "compensation_failed")
        assert result.rows[-1].detail["classification"] == "protocol_violation"

    def test_compensatable_states_frozen(self):
        assert COMPENSATABLE_STATES == frozenset({"succeeded", "failed"})


class TestCompensationUnavailable:
    def test_phantom_original_is_404_with_no_rows(self, db_session):
        with pytest.raises(ExecutionNotFound):
            compensate_response(
                db_session,
                compensates_execution_id=uuid.uuid4(),
                execution_id=uuid.uuid4(),
                operator="ops-2",
                executor=MockExecutor(),
            )
        assert all_rows(db_session) == []

    def test_non_terminal_dispatched_original_refused(self, db_session):
        """A hand-built chain stuck at `dispatched` has nothing settled to
        undo — compensation refuses with the derived state attached."""
        approval = seed_approved(db_session)
        stuck_id = uuid.uuid4()
        # Hand-built chain: explicit increasing server stamps, exactly as
        # the Service would produce (derive needs ordered timestamps).
        stamp = datetime.now(timezone.utc)
        for offset, decision in enumerate(("requested", "dispatched")):
            db_session.add(
                ExecutionLog(
                    execution_id=stuck_id,
                    approval_id=approval.id,
                    decision=decision,
                    direction="execute",
                    action="block_source_ip",
                    target="203.0.113.10",
                    operator="ops-1",
                    detail={},
                    created_at=stamp + timedelta(microseconds=offset + 1),
                )
            )
        db_session.commit()
        with pytest.raises(OriginalExecutionNotTerminal) as exc_info:
            compensate_response(
                db_session,
                compensates_execution_id=stuck_id,
                execution_id=uuid.uuid4(),
                operator="ops-2",
                executor=MockExecutor(),
            )
        assert exc_info.value.derived_state == "dispatched"
        assert len(all_rows(db_session)) == 2

    def test_non_terminal_requested_original_refused(self, db_session):
        approval = seed_approved(db_session, status="rejected")
        rejected = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(OriginalExecutionNotTerminal) as exc_info:
            compensate_response(
                db_session,
                compensates_execution_id=rejected.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-2",
                executor=MockExecutor(),
            )
        assert exc_info.value.derived_state == "guard_rejected"
        assert len(all_rows(db_session)) == 2  # no compensation rows

    def test_compensation_of_compensation_refused(self, db_session):
        original = execute_ok(db_session)
        db_session.commit()
        compensation = compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(CompensationOfCompensation):
            compensate_response(
                db_session,
                compensates_execution_id=compensation.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-3",
                executor=MockExecutor(),
            )


class TestDuplicateCompensation:
    def test_second_compensation_is_409(self, db_session):
        original = execute_ok(db_session)
        db_session.commit()
        compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=MockExecutor(),
        )
        db_session.commit()
        with pytest.raises(ExecutionAlreadyCompensated):
            compensate_response(
                db_session,
                compensates_execution_id=original.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-3",
                executor=MockExecutor(),
            )
        # Exactly one compensation chain exists.
        compensation_rows = [
            row for row in all_rows(db_session) if row.direction == "compensate"
        ]
        assert len(compensation_rows) == 2

    def test_db_last_line_compensation_index_conflict(self, db_session):
        """Constraint 3 proven at the index level: a second
        compensation_requested row for the same original is rejected by
        the partial unique index itself."""
        original = execute_ok(db_session)
        db_session.commit()
        db_session.add(
            ExecutionLog(
                execution_id=uuid.uuid4(),
                approval_id=original.approval_id,
                decision="compensation_requested",
                direction="compensate",
                action="block_source_ip",
                target="203.0.113.10",
                operator="ops-2",
                detail={},
                compensates_execution_id=original.execution_id,
            )
        )
        db_session.flush()
        db_session.add(
            ExecutionLog(
                execution_id=uuid.uuid4(),
                approval_id=original.approval_id,
                decision="compensation_requested",
                direction="compensate",
                action="block_source_ip",
                target="203.0.113.10",
                operator="ops-3",
                detail={},
                compensates_execution_id=original.execution_id,
            )
        )
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()


# --------------------------------------------------------------------------
# Immutability + transaction discipline
# --------------------------------------------------------------------------
class TestWorldImmutability:
    def test_execution_and_compensation_touch_nothing_else(self, db_session):
        approval = seed_approved(db_session)
        group = approval.recommendation.alert_group
        risk = EventRisk(alert_group_id=group.id, score=80, level="high", factors={})
        incident = Incident(
            alert_group_id=group.id,
            title="SSH Brute Force on edge-gateway",
            severity="high",
            risk_score=80,
            status="open",
        )
        db_session.add_all([risk, incident])
        db_session.commit()

        before = {
            "risk_score": risk.score,
            "risk_level": risk.level,
            "incident_status": incident.status,
            "incident_severity": incident.severity,
            "incident_risk_score": incident.risk_score,
            "recommendation_payload": list(approval.recommendation.recommendations),
            "approval_status": approval.status,
            "approval_reviewer": approval.reviewer,
        }

        original = execute_ok(db_session, approval)
        db_session.commit()
        compensate_response(
            db_session,
            compensates_execution_id=original.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-2",
            executor=MockExecutor(fail_with="timeout"),
        )
        db_session.commit()

        db_session.refresh(risk)
        db_session.refresh(incident)
        db_session.refresh(approval)
        db_session.refresh(approval.recommendation)
        assert risk.score == before["risk_score"]
        assert risk.level == before["risk_level"]
        assert incident.status == before["incident_status"]
        assert incident.severity == before["incident_severity"]
        assert incident.risk_score == before["incident_risk_score"]
        assert approval.recommendation.recommendations == before["recommendation_payload"]
        assert approval.status == before["approval_status"]
        assert approval.reviewer == before["approval_reviewer"]


class TestTransactionDiscipline:
    def test_service_never_commits_uncommitted_rows_vanish_on_rollback(self, db_session):
        execute_ok(db_session)
        assert len(all_rows(db_session)) == 3
        db_session.rollback()
        assert all_rows(db_session) == []

    def test_committed_chains_persist_across_sessions(self, db_session):
        result = execute_ok(db_session)
        db_session.commit()
        fresh = type(db_session)(bind=db_session.get_bind())
        try:
            rows = list(
                fresh.scalars(
                    select(ExecutionLog).where(
                        ExecutionLog.execution_id == result.execution_id
                    )
                )
            )
            assert [row.decision for row in rows] == [
                "requested",
                "dispatched",
                "succeeded",
            ]
        finally:
            fresh.close()

    def test_service_module_has_no_token_or_commit_surface(self):
        """Token is an HTTP-layer concern; commit is the API's boundary."""
        import inspect

        import app.services.executions.service as service_module

        source = inspect.getsource(service_module)
        lowered = source.lower()
        assert "bearer" not in lowered
        assert "token" not in lowered
        assert ".commit()" not in source
