"""M4-F §1/§2 — service + endpoint integration for the durable pre-dispatch
attempt store (TDD Cycle 2).

Cycle 1 (``test_dispatch_attempt_durability.py``) proved the STORE commits
durably on an INDEPENDENT connection (file-backed SQLite). This cycle proves the
SERVICE wiring around it:

- ``store.record()`` runs BEFORE ``executor.execute()`` — the pre-dispatch
  guarantee: the committed intent + target binding exists before the wire call
- a pre-dispatch commit failure means ZERO external calls — the adapter is NEVER
  invoked on an intent that did not durably persist
- a duplicate ``execution_id`` at the durable commit maps to the SAME typed 409
  (D14) the pre-check raises, caught BEFORE the adapter runs
- M4-G §1: a duplicate ``approval_id`` at the durable commit (two execution_ids
  racing ONE approval) maps to ``ApprovalAlreadyExecuted`` — the SAME typed 409
  the G3 pre-check raises — caught BEFORE the adapter runs, closing the race the
  pre-check alone cannot (both requests read an empty prior_approval_rows)
- the terminal row REFERENCES the recorded ``attempt_id`` (never re-writes it)
- ``store=None`` is byte-identical to the pre-M4-F path (no regression)
- exactly ONE external call per dispatch — no automatic retry / re-dispatch
  (constraint 5)

SQLite honesty (constraint 2): these control-flow proofs use a FAKE store on the
in-memory ``db_session`` — a REAL independent-connection store cannot interleave
with the caller's open write transaction under SQLite's single-writer lock (the
caller flushes ``requested`` before dispatch). The TRUE interleaved durability
(the caller's transaction overlapping the store's independent commit, then a
crash / rollback) is PostgreSQL-MVCC semantics and is covered by an
``external``-marked test that stays DESELECTED — never faked green on SQLite.
"""
import uuid

import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.services.executions.base import ResponseExecutor
from app.services.executions.binding import TERMINAL_REFERENCE_KEY
from app.services.executions.mock import MockExecutor
from app.services.executions.service import (
    ApprovalAlreadyExecuted,
    ExecutionIdAlreadyBound,
    execute_response,
)
from tests.test_execution_service import seed_approved


class _Events(list):
    """Ordered call log shared by the fake store and the counting executor."""


class FakeStore:
    """Stand-in durable store: logs the binding + call order, optionally raising a
    configured error to simulate a pre-dispatch commit failure. Touches NO
    database, so it runs on the in-memory harness without the SQLite
    single-writer artifact."""

    def __init__(self, events=None, raise_exc=None):
        self.recorded = []
        self._events = events
        self._raise = raise_exc

    def record(self, binding):
        if self._events is not None:
            self._events.append("record")
        if self._raise is not None:
            raise self._raise
        self.recorded.append(binding)


class CountingExecutor(ResponseExecutor):
    """Wraps ``MockExecutor``; counts ``execute()`` calls and logs the order."""

    def __init__(self, events=None, fail_with=None):
        self._inner = MockExecutor(fail_with=fail_with)
        self.calls = 0
        self._events = events

    @property
    def name(self):
        return "mock"

    def supports(self, action):
        return self._inner.supports(action)

    def supports_compensation(self, action):
        return self._inner.supports_compensation(action)

    def execute(self, dispatch):
        self.calls += 1
        if self._events is not None:
            self._events.append("execute")
        return self._inner.execute(dispatch)

    def compensate(self, dispatch):
        return self._inner.compensate(dispatch)


class TestDurableDispatchWiring:
    def test_store_records_the_binding_before_the_external_request(self, db_session):
        approval = seed_approved(db_session)
        events = _Events()
        store = FakeStore(events=events)
        executor = CountingExecutor(events=events)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            dispatch_attempt_store=store,
        )
        assert result.chain == ("requested", "dispatched", "succeeded")
        assert len(store.recorded) == 1
        # THE pre-dispatch guarantee: the durable record precedes the wire call.
        assert "record" in events and "execute" in events
        assert events.index("record") < events.index("execute")
        assert executor.calls == 1

    def test_pre_dispatch_duplicate_commit_refuses_the_external_request(self, db_session):
        approval = seed_approved(db_session)
        events = _Events()
        dup = IntegrityError(
            "INSERT INTO dispatch_attempt ...",
            {},
            Exception("UNIQUE constraint failed: dispatch_attempt.execution_id"),
        )
        store = FakeStore(events=events, raise_exc=dup)
        executor = CountingExecutor(events=events)
        with pytest.raises(ExecutionIdAlreadyBound):
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                dispatch_attempt_store=store,
            )
        # persistence failed first -> the adapter NEVER ran (D14, ahead of the wire)
        assert executor.calls == 0
        assert "execute" not in events

    def test_pre_dispatch_duplicate_approval_refuses_the_external_request(self, db_session):
        # M4-G §1: TWO different execution_ids racing ONE approval_id. Both pass
        # the G3 lifecycle pre-check (each reads an empty prior_approval_rows) and
        # both would fire the adapter; the durable approval-slot reservation is the
        # line that stops the SECOND, at its own independent commit, translating the
        # unique-index IntegrityError into the SAME typed 409 the pre-check raises
        # (ApprovalAlreadyExecuted) BEFORE the wire call. execution_log's partial
        # approval index bites only at caller-commit, AFTER the external request —
        # too late — which is exactly the M4-F review finding this closes.
        approval = seed_approved(db_session)
        events = _Events()
        dup = IntegrityError(
            "INSERT INTO dispatch_attempt ...",
            {},
            Exception("UNIQUE constraint failed: dispatch_attempt.approval_id"),
        )
        store = FakeStore(events=events, raise_exc=dup)
        executor = CountingExecutor(events=events)
        with pytest.raises(ApprovalAlreadyExecuted):
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                dispatch_attempt_store=store,
            )
        # the approval-slot reservation refused first -> the adapter NEVER ran.
        assert executor.calls == 0
        assert "execute" not in events

    def test_pre_dispatch_commit_failure_never_calls_the_adapter(self, db_session):
        approval = seed_approved(db_session)
        events = _Events()
        store = FakeStore(events=events, raise_exc=SQLAlchemyError("connection lost"))
        executor = CountingExecutor(events=events)
        with pytest.raises(SQLAlchemyError):
            execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                dispatch_attempt_store=store,
            )
        assert executor.calls == 0

    def test_terminal_row_references_the_recorded_attempt_id(self, db_session):
        approval = seed_approved(db_session)
        store = FakeStore()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=CountingExecutor(),
            dispatch_attempt_store=store,
        )
        assert len(store.recorded) == 1
        recorded = store.recorded[0]
        terminal = result.rows[-1]
        assert terminal.decision == "succeeded"
        assert terminal.detail[TERMINAL_REFERENCE_KEY] == recorded.attempt_id

    def test_store_none_is_the_unchanged_pre_m4f_path(self, db_session):
        # Regression guard: the default (no store) path is byte-identical to
        # pre-M4-F, so the 2810 existing tests are untouched by the wiring.
        approval = seed_approved(db_session)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert result.chain == ("requested", "dispatched", "succeeded")

    def test_a_single_dispatch_makes_exactly_one_external_call(self, db_session):
        approval = seed_approved(db_session)
        executor = CountingExecutor(fail_with="timeout")
        store = FakeStore()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            dispatch_attempt_store=store,
        )
        # an adapter failure is TERMINAL — no automatic retry / re-dispatch
        assert result.final_decision == "failed"
        assert executor.calls == 1
        assert len(store.recorded) == 1
