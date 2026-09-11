"""/ C-1 — durable compensation integration (the reverse of test_dispatch_durable_integration).

WHAT THIS PROVES. The compensation path now has the SAME durable protection as
forward dispatch: the immutable reverse binding commits on its OWN transaction
BEFORE the external ``executor.compensate()`` call, a duplicate compensation for
the same ORIGINAL execution is refused at that independent commit (before the
wire call), a persistence failure or an ambiguous commit makes ZERO external
calls, and the terminal compensation row REFERENCES the recorded
``compensation_attempt_id``. Recovery reads classify committed attempts
read-only (TERMINAL_AUDIT_PRESENT / DISPATCH_STATUS_UNKNOWN) and never fabricate
an external-effect confirmation.

LAYERS (mirroring the forward suite):
- ``TestCompensationBinding`` — the typed binding build/parse/whitelist.
- ``TestDurableCompensationStore`` — the REAL store on a FILE-backed engine
(an independent commit needs a second connection, so the in-memory StaticPool
harness cannot drive it — same rule as the forward store tests).
- ``TestCompensationServiceWiring`` — service sequencing on the in-memory
harness with the FakeStore seam (record-before-wire ordering, fail-closed
gate, duplicate refusal, single external call).
- ``TestCompensationRecoveryReads`` — the read-only recovery classification.

PostgreSQL concurrency lives in ``test_compensation_durable_postgres.py``
(``-m external``, dedicated throwaway DB).
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import CompensationAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.compensation_binding import (
    COMPENSATION_BINDING_SCHEMA,
    COMPENSATION_REFERENCE_KEY,
    build_compensation_binding,
    parse_compensation_binding,
)
from app.services.executions.durable_compensation import (
    CompensationRecoveryDisposition,
    DurableCompensationAttemptStore,
    classify_compensation_recovery,
    find_unreconciled_compensations,
)
from app.services.executions.mock import MockExecutor
from app.services.executions.service import (
    DurableStoreRequired,
    ExecutionAlreadyCompensated,
    compensate_response,
    execute_response,
)
from tests.test_dispatch_durable_integration import (
    CountingExecutor,
    FakeStore,
    _Events,
)
from tests.test_execution_service import seed_approved


def _binding(
    *,
    execution_id=None,
    original_execution_id=None,
    original_dispatch_attempt_id=None,
    approval_id=None,
    action="block_source_ip",
    target="203.0.113.9",
    operator="ops-1",
    reason="undo",
    original_outcome_state="succeeded",
    contributor_facts=None,
):
    now = datetime.now(timezone.utc)
    return build_compensation_binding(
        execution_id=execution_id or uuid.uuid4(),
        original_execution_id=original_execution_id or uuid.uuid4(),
        original_dispatch_attempt_id=original_dispatch_attempt_id,
        approval_id=approval_id or uuid.uuid4(),
        adapter="mock",
        action=action,
        target=target,
        operator=operator,
        reason=reason,
        original_outcome_state=original_outcome_state,
        prepared_at=now,
        dispatch_started_at=now,
        contributor_facts=contributor_facts,
    )


def _forward(db_session, *, executor, dispatch_store=None, action="block_source_ip"):
    approval = seed_approved(
        db_session,
        recommendations=[{"action": action, "target": "203.0.113.9",
                          "rationale": "test"}],
    )
    forward = execute_response(
        db_session,
        approval_id=approval.id,
        execution_id=uuid.uuid4(),
        operator="ops-1",
        executor=executor,
        dispatch_attempt_store=dispatch_store if dispatch_store is not None else FakeStore(),
    )
    assert forward.final_decision == "succeeded"
    return forward


def _compensate(db_session, forward, *, executor, store=None):
    return compensate_response(
        db_session,
        compensates_execution_id=forward.execution_id,
        execution_id=uuid.uuid4(),
        operator="ops-1",
        executor=executor,
        compensation_attempt_store=store,
    )


#
# 1. The typed binding (unit)
#
class TestCompensationBinding:
    def test_roundtrip_via_detail(self):
        execution_id = uuid.uuid4()
        original = uuid.uuid4()
        forward_attempt = uuid.uuid4()
        approval_id = uuid.uuid4()
        binding = _binding(
            execution_id=execution_id,
            original_execution_id=original,
            original_dispatch_attempt_id=forward_attempt,
            approval_id=approval_id,
            contributor_facts={
                "endpoint": "https://lab.example.internal",
                "version_evidence_ref": "shuffle-0.0.1",
                "version_assertion_kind": "config-declaration",
                "target_instance": None,
                "target_tenant": None,
            },
        )
        detail = binding.to_detail()
        assert detail["schema"] == COMPENSATION_BINDING_SCHEMA
        parsed = parse_compensation_binding(detail)
        assert parsed is not None
        assert parsed.compensation_attempt_id == binding.compensation_attempt_id
        assert parsed.execution_id == str(execution_id)
        assert parsed.original_execution_id == str(original)
        assert parsed.original_dispatch_attempt_id == str(forward_attempt)
        assert parsed.approval_id == str(approval_id)
        assert parsed.reverse_action == "block_source_ip"
        assert parsed.endpoint == "https://lab.example.internal"
        assert parsed.prepared_instant() is not None
        assert parsed.started_at() is not None

    def test_parse_fails_closed_on_corrupt_detail(self):
        good = _binding().to_detail()
        assert parse_compensation_binding(None) is None
        assert parse_compensation_binding([1, 2]) is None
        assert parse_compensation_binding({}) is None
        assert parse_compensation_binding({**good, "schema": "other.v9"}) is None
        missing = dict(good)
        missing.pop("original_execution_id")
        assert parse_compensation_binding(missing) is None

    def test_contributor_whitelist_blocks_arbitrary_keys(self):
        binding = _binding(
            contributor_facts={
                "endpoint": "https://lab.example.internal",
                "smuggled_secret": "must-never-surface",
                "execution_id": "overridden",
            }
        )
        detail = binding.to_detail()
        assert "smuggled_secret" not in detail
        assert detail["execution_id"] == binding.execution_id  # platform fact intact


#
# 2. The REAL store on a FILE-backed engine (independent connection)
#
@pytest.fixture()
def file_engine(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'compensation-durable.db'}"
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


class TestDurableCompensationStore:
    def test_commit_survives_caller_rollback(self, file_engine):
        store = DurableCompensationAttemptStore(file_engine)
        binding = _binding()
        caller = Session(file_engine)
        try:
            caller.execute(text("SELECT 1"))
            store.record(binding)  # independent commit
        finally:
            caller.rollback()
            caller.close()
        with Session(file_engine) as fresh:
            row = fresh.query(CompensationAttempt).one()
            assert str(row.compensation_attempt_id) == binding.compensation_attempt_id
            assert str(row.original_execution_id) == binding.original_execution_id
            assert row.adapter == "mock"
            assert row.reverse_action == "block_source_ip"
            assert row.operator == "ops-1"
            assert row.original_outcome_state == "succeeded"
            parsed = parse_compensation_binding(row.detail)
            assert parsed is not None
            assert parsed.compensation_attempt_id == binding.compensation_attempt_id

    def test_duplicate_original_execution_is_refused_at_the_commit(self, file_engine):
        store = DurableCompensationAttemptStore(file_engine)
        original = uuid.uuid4()
        store.record(_binding(original_execution_id=original))
        with pytest.raises(IntegrityError):
            # a DIFFERENT compensation execution targeting the SAME original
            store.record(_binding(original_execution_id=original))
        with Session(file_engine) as fresh:
            assert fresh.query(CompensationAttempt).count() == 1

    def test_duplicate_compensation_execution_is_refused_at_the_commit(self, file_engine):
        store = DurableCompensationAttemptStore(file_engine)
        execution_id = uuid.uuid4()
        store.record(_binding(execution_id=execution_id))
        with pytest.raises(IntegrityError):
            store.record(_binding(execution_id=execution_id))
        with Session(file_engine) as fresh:
            assert fresh.query(CompensationAttempt).count() == 1


#
# 3. Service wiring (in-memory harness + FakeStore seam)
#
class TestCompensationServiceWiring:
    def test_store_records_before_the_external_reverse_request(self, db_session):
        events = _Events()
        executor = CountingExecutor(events=events)
        forward = _forward(db_session, executor=executor,
                           dispatch_store=FakeStore(events=events))
        events.clear()  # keep the ordering assertion scoped to the reverse chain
        store = FakeStore(events=events)
        result = _compensate(db_session, forward, executor=executor, store=store)
        assert result.chain == (
            "compensation_requested",
            "compensation_succeeded",
        )
        assert len(store.recorded) == 1
        # THE pre-compensation guarantee: the durable record precedes the wire call.
        assert events.index("record") < events.index("compensate")
        assert executor.compensate_calls == 1

    def test_binding_carries_the_original_forward_attempt_reference(self, db_session):
        fstore = FakeStore()
        forward = _forward(db_session, executor=MockExecutor(), dispatch_store=fstore)
        store = FakeStore()
        _compensate(db_session, forward, executor=MockExecutor(), store=store)
        assert len(fstore.recorded) == 1
        assert len(store.recorded) == 1
        assert (
            store.recorded[0].original_dispatch_attempt_id
            == fstore.recorded[0].attempt_id
        )
        assert (
            store.recorded[0].original_execution_id == str(forward.execution_id)
        )

    def test_persistence_failure_never_calls_the_reverse_adapter(self, db_session):
        events = _Events()
        executor = CountingExecutor(events=events)
        forward = _forward(db_session, executor=executor)
        events.clear()
        store = FakeStore(events=events, raise_exc=SQLAlchemyError("connection lost"))
        with pytest.raises(SQLAlchemyError):
            _compensate(db_session, forward, executor=executor, store=store)
        assert executor.compensate_calls == 0
        assert "compensate" not in events

    def test_duplicate_original_execution_refuses_the_external_reverse_request(
        self, db_session
    ):
        dup = IntegrityError(
            "INSERT INTO compensation_attempt ...",
            {},
            Exception(
                "UNIQUE constraint failed: compensation_attempt.original_execution_id"
            ),
        )
        events = _Events()
        executor = CountingExecutor(events=events)
        forward = _forward(db_session, executor=executor)
        events.clear()
        store = FakeStore(events=events, raise_exc=dup)
        with pytest.raises(ExecutionAlreadyCompensated):
            _compensate(db_session, forward, executor=executor, store=store)
        # the durable reservation refused first -> the adapter NEVER ran.
        assert executor.compensate_calls == 0
        assert "compensate" not in events

    def test_terminal_row_references_the_recorded_attempt_id(self, db_session):
        forward = _forward(db_session, executor=MockExecutor())
        store = FakeStore()
        result = _compensate(db_session, forward, executor=MockExecutor(), store=store)
        assert len(store.recorded) == 1
        terminal = result.rows[-1]
        assert terminal.decision == "compensation_succeeded"
        assert (
            terminal.detail[COMPENSATION_REFERENCE_KEY]
            == store.recorded[0].compensation_attempt_id
        )

    def test_store_none_keeps_the_demo_path_and_records_no_durable_row(self, db_session):
        # Regression guard: the offline mock + store=None path stays available
        # (Demo Mode compensation) and writes NO durable row; the terminal still
        # carries the binding reference (the binding is minted regardless).
        forward = _forward(db_session, executor=MockExecutor())
        result = _compensate(db_session, forward, executor=MockExecutor(), store=None)
        assert result.final_decision == "compensation_succeeded"
        assert COMPENSATION_REFERENCE_KEY in result.rows[-1].detail
        assert db_session.query(CompensationAttempt).count() == 0

    def test_recognized_adapter_without_a_durable_store_is_refused_before_dispatch(
        self, db_session
    ):
        # / C-1 FAIL-CLOSED GATE: a
        # RECOGNIZED real external adapter presented with store=None MUST be
        # refused BEFORE the external reverse request. The adapter is NEVER
        # invoked.
        events = _Events()
        executor = CountingExecutor(events=events, name="shuffle")
        forward = _forward(db_session, executor=executor, dispatch_store=FakeStore())
        events.clear()
        with pytest.raises(DurableStoreRequired):
            _compensate(db_session, forward, executor=executor, store=None)
        assert executor.compensate_calls == 0
        assert "compensate" not in events

    def test_recognized_adapter_with_a_durable_store_proceeds(self, db_session):
        events = _Events()
        executor = CountingExecutor(events=events, name="shuffle")
        forward = _forward(db_session, executor=executor, dispatch_store=FakeStore())
        events.clear()
        store = FakeStore(events=events)
        result = _compensate(db_session, forward, executor=executor, store=store)
        assert result.final_decision == "compensation_succeeded"
        assert executor.compensate_calls == 1
        assert events.index("record") < events.index("compensate")

    def test_capability_miss_records_no_durable_attempt(self, db_session):
        # escalate_to_incident has no machine reversal: the chain ends as
        # compensation_failed (capability_missing) BEFORE the durable gate —
        # no external call ever fires, so no durable attempt is required or
        # recorded.
        executor = CountingExecutor()
        forward = _forward(
            db_session, executor=executor, action="escalate_to_incident"
        )
        store = FakeStore()
        result = _compensate(
            db_session, forward, executor=executor, store=store
        )
        assert result.final_decision == "compensation_failed"
        assert result.rows[-1].detail["classification"] == "capability_missing"
        assert len(store.recorded) == 0
        assert executor.compensate_calls == 0

    def test_ambiguous_store_commit_never_retries_the_external_action(
        self, db_session
    ):
        # COMMIT-UNCERTAINTY: the durable commit outcome is AMBIGUOUS. The
        # Service MUST NOT auto-retry the reverse action: it propagates the
        # uncertainty, makes ZERO external calls, and asks the store exactly
        # ONCE.
        events = _Events()
        executor = CountingExecutor(events=events)
        forward = _forward(db_session, executor=executor)
        events.clear()
        ambiguous = SQLAlchemyError("connection lost during commit — outcome unknown")
        store = FakeStore(events=events, raise_exc=ambiguous)
        with pytest.raises(SQLAlchemyError):
            _compensate(db_session, forward, executor=executor, store=store)
        assert executor.compensate_calls == 0
        assert events.count("record") == 1
        assert "compensate" not in events

    def test_a_single_compensation_makes_exactly_one_external_call(self, db_session):
        forward = _forward(db_session, executor=CountingExecutor())
        # a compensation-side adapter failure is TERMINAL — no retry / re-compensation
        executor = CountingExecutor(fail_with="timeout")
        store = FakeStore()
        result = _compensate(db_session, forward, executor=executor, store=store)
        assert result.final_decision == "compensation_failed"
        assert executor.compensate_calls == 1
        assert len(store.recorded) == 1


#
# 4. Recovery reads (read-only classification)
#
def _attempt_row(**kw):
    now = datetime.now(timezone.utc)
    defaults = dict(
        compensation_attempt_id=uuid.uuid4(),
        execution_id=uuid.uuid4(),
        original_execution_id=uuid.uuid4(),
        original_dispatch_attempt_id=None,
        approval_id=uuid.uuid4(),
        adapter="mock",
        reverse_action="block_source_ip",
        target="203.0.113.9",
        endpoint=None,
        operator="ops-1",
        reason=None,
        original_outcome_state="succeeded",
        prepared_at=now,
        dispatch_started_at=now,
        detail={},
    )
    defaults.update(kw)
    return CompensationAttempt(**defaults)


def _terminal_row(attempt, decision, *, execution_id=None, approval_id=None,
                  reference=None):
    return ExecutionLog(
        execution_id=execution_id if execution_id is not None else attempt.execution_id,
        approval_id=approval_id if approval_id is not None else attempt.approval_id,
        decision=decision,
        direction="compensate",
        action=attempt.reverse_action,
        target=attempt.target,
        operator="ops-1",
        detail={
            COMPENSATION_REFERENCE_KEY: (
                reference if reference is not None
                else str(attempt.compensation_attempt_id)
            )
        },
        compensates_execution_id=attempt.original_execution_id,
    )


class TestCompensationRecoveryReads:
    def test_orphan_attempt_is_unknown_and_unreconciled(self, db_session):
        attempt = _attempt_row()
        db_session.add(attempt)
        db_session.flush()
        unreconciled = find_unreconciled_compensations(db_session)
        assert [str(a.compensation_attempt_id) for a in unreconciled] == [
            str(attempt.compensation_attempt_id)
        ]
        classified = classify_compensation_recovery(db_session)
        assert len(classified) == 1
        assert (
            classified[0].disposition
            == CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        assert classified[0].audit_decision is None

    def test_agreeing_terminal_is_audit_present_never_external_confirmation(
        self, db_session
    ):
        attempt = _attempt_row()
        db_session.add(attempt)
        db_session.add(_terminal_row(attempt, "compensation_succeeded"))
        db_session.flush()
        assert find_unreconciled_compensations(db_session) == []
        classified = classify_compensation_recovery(db_session)
        assert len(classified) == 1
        assert (
            classified[0].disposition
            == CompensationRecoveryDisposition.TERMINAL_AUDIT_PRESENT
        )
        assert classified[0].audit_decision == "compensation_succeeded"
        # NEVER external-effect confirmation — that state lives only in the
        # Outcome layer's authoritative proof path.
        assert (
            classified[0].disposition
            != CompensationRecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
        )

    def test_failed_terminal_is_an_audit_fact_never_confirmed_failure(self, db_session):
        attempt = _attempt_row()
        db_session.add(attempt)
        db_session.add(_terminal_row(attempt, "compensation_failed"))
        db_session.flush()
        classified = classify_compensation_recovery(db_session)
        assert classified[0].audit_decision == "compensation_failed"
        # an audit ``compensation_failed`` is NOT a confirmed external failure;
        # the disposition stays the audit classification.
        assert (
            classified[0].disposition
            == CompensationRecoveryDisposition.TERMINAL_AUDIT_PRESENT
        )

    def test_cross_execution_terminal_does_not_settle_the_attempt(self, db_session):
        attempt = _attempt_row()
        db_session.add(attempt)
        # a terminal that merely REFERENCES this attempt id but lives in a
        # DIFFERENT execution cannot settle it.
        db_session.add(
            _terminal_row(attempt, "compensation_succeeded", execution_id=uuid.uuid4())
        )
        db_session.flush()
        unreconciled = find_unreconciled_compensations(db_session)
        assert len(unreconciled) == 1
        classified = classify_compensation_recovery(db_session)
        assert (
            classified[0].disposition
            == CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )

    def test_wrong_attempt_reference_does_not_settle_the_attempt(self, db_session):
        attempt = _attempt_row()
        db_session.add(attempt)
        db_session.add(
            _terminal_row(attempt, "compensation_succeeded", reference=str(uuid.uuid4()))
        )
        db_session.flush()
        classified = classify_compensation_recovery(db_session)
        assert (
            classified[0].disposition
            == CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
