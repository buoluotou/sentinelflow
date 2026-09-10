"""M4-F §1/§2 — durable pre-dispatch attempt store: REAL independent-connection
durability proofs (TDD Cycle 1, store unit level).

The M4 review finding was "flush 不等于持久提交": M4-A persisted the binding with
``session.flush()`` inside the caller's transaction, so a caller rollback /
terminal-write failure / process crash AFTER the external request fired could
erase it. These tests prove the FIX at the store unit level using a FILE-backed
SQLite engine and INDEPENDENT ``Session``/connection objects — NOT the in-memory
``StaticPool`` ``db_session`` fixture, whose single shared connection would make a
"commit" visible to the same session and therefore FAKE durability (exactly the
trap the reviewer called out: do not pass off same-session flush visibility as
durable).

Cycle 2 (service-level crash/rollback injection, restart recovery, concurrency,
no-second-external-call) builds on this. Scope here: store durability ONLY. No
API, no external system, no frontend.

SQLite note (constraint 2): a file-backed SQLite proves COMMIT visibility across
independent connections and rollback survival, but it CANNOT certify PostgreSQL
row-lock / serialisation semantics — those stay explicitly unverified here and are
tracked separately, never claimed green from a SQLite run.
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.database import Base
from app.models import DispatchAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.binding import (
    TERMINAL_REFERENCE_KEY,
    build_dispatch_binding,
)
from app.services.executions.durable_dispatch import (
    AttemptRecovery,
    DurableDispatchAttemptStore,
    RecoveryDisposition,
    classify_attempt_recovery,
    find_unreconciled_attempts,
)


@pytest.fixture()
def durable_engine(tmp_path):
    """A FILE-backed SQLite engine with a real (non-shared) pool, so an
    independent ``Session`` truly reads only COMMITTED rows — the durability
    semantics the in-memory ``StaticPool`` fixture cannot provide."""
    db_path = tmp_path / "durable_dispatch.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


def _independent_session(engine) -> Session:
    """A brand-new ``Session`` (its own connection) — reads committed data only."""
    return Session(engine)


def _binding(**overrides):
    """A deterministic pre-dispatch binding from server-side facts."""
    facts = dict(
        execution_id=uuid.uuid4(),
        approval_id=uuid.uuid4(),
        adapter="thehive",
        action="create_case",
        target="203.0.113.10",
        approval_status="approved",
        dispatch_started_at=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
        contributor_facts={
            "endpoint": "https://thehive.lab.internal",
            "version_evidence_ref": "config:THEHIVE_EXPECTED_VERSION",
            "version_assertion_kind": "config-declaration",
            "target_instance": None,
            "target_tenant": None,
        },
    )
    facts.update(overrides)
    return build_dispatch_binding(**facts)


class TestDurableStoreCommit:
    def test_record_is_visible_on_an_independent_connection(self, durable_engine):
        """CORE durability: after ``record()``, a NEW Session/connection (not the
        writer's) sees the committed attempt. A same-session flush would NOT be
        visible here — this is the exact distinction the reviewer demanded."""
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        assert rows[0].attempt_id == uuid.UUID(binding.attempt_id)
        assert rows[0].execution_id == uuid.UUID(binding.execution_id)

    def test_record_projects_the_full_binding(self, durable_engine):
        """The committed row carries the immutable target identity + the exact
        binding projection in ``detail``."""
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.adapter == binding.adapter
        assert row.action == binding.action
        assert row.target == binding.target
        assert row.approval_id == uuid.UUID(binding.approval_id)
        # SQLite drops tzinfo on read; normalise to UTC to compare the instant.
        assert row.dispatch_started_at.replace(tzinfo=timezone.utc) == binding.started_at()
        # detail preserves the exact binding projection (JSON round-trip).
        assert row.detail["schema"] == binding.schema
        assert row.detail["attempt_id"] == binding.attempt_id
        assert row.detail["dispatch_started_at"] == binding.dispatch_started_at
        assert row.detail["endpoint"] == "https://thehive.lab.internal"
        assert row.detail["version_assertion_kind"] == "config-declaration"
        assert row.detail["target_instance"] is None
        assert row.detail["target_tenant"] is None

    def test_record_never_stores_a_secret(self, durable_engine, monkeypatch):
        """A secret value that leaks into a binding field is masked by the
        ``redact_detail`` gate at the store's single write point (constraint 3 —
        the endpoint is a secret-free base URL, never a credential carrier)."""
        sentinel = "SUPER_SECRET_LEAKED_KEY_0123456789"
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", sentinel)
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding(
            contributor_facts={
                "endpoint": f"https://thehive.lab.internal/{sentinel}",
                "version_evidence_ref": "config:THEHIVE_EXPECTED_VERSION",
                "version_assertion_kind": "config-declaration",
                "target_instance": None,
                "target_tenant": None,
            }
        )
        store.record(binding)

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        row = rows[0]
        assert sentinel not in row.detail["endpoint"]
        assert "***" in row.detail["endpoint"]
        assert sentinel not in row.target

    def test_record_refuses_a_duplicate_execution_id(self, durable_engine):
        """ONE durable attempt per execution_id: a second ``record()`` for the same
        execution_id (a duplicate/concurrent replay) raises ``IntegrityError``
        BEFORE any external request, and the FIRST committed attempt SURVIVES."""
        store = DurableDispatchAttemptStore(durable_engine)
        execution_id = uuid.uuid4()
        first = _binding(execution_id=execution_id)
        store.record(first)

        second = _binding(execution_id=execution_id)  # a different attempt_id
        assert second.attempt_id != first.attempt_id
        with pytest.raises(IntegrityError):
            store.record(second)

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        assert rows[0].attempt_id == uuid.UUID(first.attempt_id)

    def test_record_refuses_a_second_attempt_for_the_same_approval(self, durable_engine):
        """M4-G §1: ONE execute dispatch attempt per approval_id. Two DIFFERENT
        execution_ids sharing the SAME approval_id is the concurrent same-approval
        race the M4-F review flagged — the durable reservation must refuse the
        SECOND at its independent commit (IntegrityError) BEFORE any external
        request, and the FIRST committed attempt must SURVIVE. Without an approval
        slot reservation both would commit and both would fire the adapter, the
        execution_log approval index only biting at caller-commit AFTER the wire
        call (D14's last line arriving too late)."""
        store = DurableDispatchAttemptStore(durable_engine)
        approval_id = uuid.uuid4()
        first = _binding(approval_id=approval_id)
        store.record(first)

        second = _binding(approval_id=approval_id)  # a different execution_id/attempt
        assert second.execution_id != first.execution_id
        assert second.attempt_id != first.attempt_id
        with pytest.raises(IntegrityError):
            store.record(second)

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        assert rows[0].attempt_id == uuid.UUID(first.attempt_id)
        assert rows[0].approval_id == approval_id

    def test_committed_attempt_survives_an_unrelated_rollback(self, durable_engine):
        """The reviewer's exact scenario: the attempt is committed on its OWN
        transaction, so a LATER rollback on a DIFFERENT session (the caller's
        business transaction) does NOT erase it."""
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)

        # A caller-style session that aborts its whole transaction.
        caller = _independent_session(durable_engine)
        try:
            caller.rollback()
        finally:
            caller.close()

        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        assert rows[0].attempt_id == uuid.UUID(binding.attempt_id)


def _seed_execution_row(
    engine, execution_id, approval_id, decision, direction="execute", attempt_id=None
):
    """Commit ONE execution_log row on the SAME execution_id — what the caller's
    business transaction writes. FK enforcement is OFF on this file-backed engine,
    so no approval row is needed; the CHECK + partial-unique-index DDL IS enforced,
    and a legal execute decision lands cleanly (a non-``requested`` row falls outside
    the ``requested``-only partial indexes).

    M4-G §3: when ``attempt_id`` is supplied the row REFERENCES it under
    ``TERMINAL_REFERENCE_KEY`` exactly as the REAL service does (the terminal
    ``detail["dispatch_attempt_id"] = binding.attempt_id``). Recovery correlates BY
    attempt_id, so a terminal that does not reference the attempt no longer settles it."""
    detail = {} if attempt_id is None else {TERMINAL_REFERENCE_KEY: str(attempt_id)}
    with Session(engine) as session:
        session.add(
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval_id,
                decision=decision,
                direction=direction,
                action="create_case",
                target="203.0.113.10",
                operator="ops-1",
                detail=detail,
            )
        )
        session.commit()


def _seed_terminal(engine, execution_id, approval_id, decision="succeeded", attempt_id=None):
    """Commit a TERMINAL (``succeeded``/``failed``) execution_log row — the outcome
    the caller writes AFTER the external request returns. M4-G §3: it SETTLES an
    attempt ONLY when it REFERENCES that attempt's immutable id (``attempt_id``),
    mirroring the real service; a terminal with no / a wrong reference leaves the
    attempt unreconciled (correlation is BY attempt_id, never by execution_id alone)."""
    _seed_execution_row(
        engine, execution_id, approval_id, decision, attempt_id=attempt_id
    )


class TestUnreconciledRecovery:
    """M4-F §1/§2 recovery: a committed attempt with NO committed terminal row is a
    MANUAL reconciliation candidate — surfaced, never auto-retried (constraint 5).
    The store is the ONLY writer here, so the file-backed SQLite single-writer lock
    is not contended (the caller's overlapping write transaction is the PostgreSQL
    ``external`` case, tracked separately)."""

    def test_committed_attempt_without_a_terminal_row_is_unreconciled(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)

        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]

    def test_committed_attempt_with_a_terminal_row_is_reconciled(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            attempt_id=binding.attempt_id,
        )

        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert unreconciled == []

    def test_recovery_selects_only_the_attempts_missing_a_terminal(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        settled = _binding()
        pending = _binding()
        store.record(settled)
        store.record(pending)
        # the settled attempt's terminal landed as a FAILED outcome — still a
        # terminal, so it is NOT unreconciled (an emitted-and-failed attempt is
        # settled; only "no reliable terminal" needs a human).
        _seed_terminal(
            durable_engine,
            uuid.UUID(settled.execution_id),
            uuid.UUID(settled.approval_id),
            decision="failed",
            attempt_id=settled.attempt_id,
        )

        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(pending.attempt_id)]


class TestEmittedThenAbandoned:
    """The M4 review's EXACT demanded scenario (constraint 1): "外部副作用发生后，
    数据库事务回滚仍保留绑定". The external request fires (the caller logs
    ``dispatched`` and the wire call goes out), THEN the caller's whole business
    transaction aborts — a process crash, a lost response, a terminal-write failure
    or an explicit rollback. Because the durable attempt was committed on its OWN
    transaction BEFORE the request, it SURVIVES the abort and recovery flags it as a
    MANUAL reconciliation candidate. It is NEVER auto-retried (constraint 5).

    SQLite honesty (constraint 2): the abort is modelled SEQUENTIALLY (the store
    commits + closes, THEN the caller opens + aborts), which file-backed SQLite
    proves exactly. TRUE interleaving — the caller holding an OPEN write transaction
    WHILE the store commits on a second connection, then a crash — is
    PostgreSQL-MVCC semantics under SQLite's single-writer lock and is covered by an
    ``external``-marked test that stays DESELECTED, never faked green here.
    """

    def test_attempt_survives_a_caller_rollback_after_the_external_request(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        # 1. the durable pre-dispatch commit lands BEFORE the external request.
        store.record(binding)
        # 2. the external request goes out: the caller appends + flushes ``dispatched``
        #    inside its business transaction, then the process crashes / the caller
        #    rolls the WHOLE transaction back before any terminal commits.
        caller = _independent_session(durable_engine)
        try:
            caller.add(
                ExecutionLog(
                    execution_id=uuid.UUID(binding.execution_id),
                    approval_id=uuid.UUID(binding.approval_id),
                    decision="dispatched",
                    direction="execute",
                    action="create_case",
                    target="203.0.113.10",
                    operator="ops-1",
                    detail={},
                )
            )
            caller.flush()
            caller.rollback()
        finally:
            caller.close()
        # 3. the committed attempt SURVIVES the caller's rollback (independent txn),
        #    and 4. recovery flags it: no terminal row -> MANUAL reconciliation.
        with _independent_session(durable_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
            assert len(rows) == 1
            assert rows[0].attempt_id == uuid.UUID(binding.attempt_id)
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]

    def test_committed_dispatched_row_without_a_terminal_is_still_unreconciled(self, durable_engine):
        # A committed ``dispatched`` row is NOT a terminal: the request went out and
        # the log committed, but the terminal (succeeded/failed) never landed (a lost
        # response). Recovery MUST still flag it — only a terminal settles an attempt,
        # so this discriminates the ``decision IN (terminals)`` filter from a naive
        # "any execution_log row reconciles" reading.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_execution_row(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="dispatched",
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]


class TestAttemptIdCorrelation:
    """M4-G §3: a terminal SETTLES an attempt ONLY by REFERENCING its immutable
    ``attempt_id`` — NEVER by ``execution_id`` alone. A terminal for a DIFFERENT /
    wrong attempt on the SAME execution_id (a stale or mis-attributed terminal) must
    NOT mask the pending attempt (§4 requirement 7: a wrong-attempt_id terminal
    cannot cover an unreconciled attempt)."""

    def test_terminal_for_a_wrong_attempt_id_does_not_settle_the_attempt(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        # A terminal on the SAME execution_id but referencing a DIFFERENT attempt_id
        # (never this attempt's). Under the OLD execution_id-only correlation it would
        # wrongly settle; §3 requires the attempt_id reference, so it stays pending.
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            attempt_id=uuid.uuid4(),  # a WRONG / unrelated attempt id
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]

    def test_terminal_without_an_attempt_id_reference_does_not_settle(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        # A terminal carrying NO dispatch_attempt_id reference (detail={}) on the same
        # execution_id: execution_id alone is NOT proof THIS attempt settled.
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            attempt_id=None,
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]


class TestRecoveryClassification:
    """M4-G §3: the READ-ONLY three-state recovery classification. A TERMINAL AUDIT
    (a terminal references the attempt) is KEPT DISTINCT from DISPATCH_STATUS_UNKNOWN
    (no terminal references it) and from EXTERNAL_EFFECT_CONFIRMED (an Outcome-layer
    state the recovery read NEVER produces). A FAILED terminal is an AUDIT fact about
    what the service recorded, NEVER ``confirmed_failure`` about the external world."""

    def test_classify_separates_terminal_audit_from_dispatch_unknown(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        settled = _binding()
        pending = _binding()
        store.record(settled)
        store.record(pending)
        _seed_terminal(
            durable_engine,
            uuid.UUID(settled.execution_id),
            uuid.UUID(settled.approval_id),
            attempt_id=settled.attempt_id,
        )
        with _independent_session(durable_engine) as session:
            classified = {r.attempt_id: r for r in classify_attempt_recovery(session)}
        assert isinstance(classified[uuid.UUID(settled.attempt_id)], AttemptRecovery)
        assert classified[uuid.UUID(settled.attempt_id)].disposition is (
            RecoveryDisposition.TERMINAL_AUDIT_PRESENT
        )
        assert classified[uuid.UUID(settled.attempt_id)].audit_decision == "succeeded"
        assert classified[uuid.UUID(pending.attempt_id)].disposition is (
            RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        assert classified[uuid.UUID(pending.attempt_id)].audit_decision is None

    def test_failed_terminal_is_audit_present_never_confirmed_failure(self, durable_engine):
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="failed",
            attempt_id=binding.attempt_id,
        )
        with _independent_session(durable_engine) as session:
            record = classify_attempt_recovery(session)[0]
        # A failed terminal is a TERMINAL AUDIT fact — the dispatch was RECORDED as
        # failed — but the EXTERNAL effect is NOT confirmed to have failed (the action
        # may have landed before the timeout / lost response). NEVER confirmed_failure.
        assert record.disposition is RecoveryDisposition.TERMINAL_AUDIT_PRESENT
        assert record.audit_decision == "failed"
        assert record.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED

    def test_recovery_never_produces_external_effect_confirmed(self, durable_engine):
        # No durable attempt, terminal audit, or external JSON can authorize
        # EXTERNAL_EFFECT_CONFIRMED here: confirmed_success / confirmed_failure live
        # ONLY in the Outcome layer via the authoritative reconcile / trusted-reader
        # proof path (verify_creation_effect), never in the recovery read.
        store = DurableDispatchAttemptStore(durable_engine)
        settled = _binding()
        pending = _binding()
        store.record(settled)
        store.record(pending)
        _seed_terminal(
            durable_engine,
            uuid.UUID(settled.execution_id),
            uuid.UUID(settled.approval_id),
            attempt_id=settled.attempt_id,
        )
        with _independent_session(durable_engine) as session:
            records = classify_attempt_recovery(session)
        assert RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED not in {
            r.disposition for r in records
        }

    def test_recovery_identity_comes_from_the_immutable_attempt_not_config(
        self, durable_engine, monkeypatch
    ):
        # The recovery identity (adapter / action / target) is the durable attempt's
        # IMMUTABLE snapshot, NEVER back-filled from the CURRENT config: changing the
        # adapter base URL after the attempt committed must not alter the record.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", "https://changed.example")
        with _independent_session(durable_engine) as session:
            record = classify_attempt_recovery(session)[0]
        assert record.adapter == "thehive"
        assert record.action == "create_case"
        assert record.target == "203.0.113.10"

    def test_classification_is_read_only_no_new_rows(self, durable_engine):
        # The recovery classifier is a PURE read: it appends ZERO dispatch_attempt /
        # execution_log rows and never re-dispatches, retries or compensates.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        with _independent_session(durable_engine) as session:
            attempts_before = len(session.scalars(select(DispatchAttempt)).all())
            logs_before = len(session.scalars(select(ExecutionLog)).all())
            classify_attempt_recovery(session)
            find_unreconciled_attempts(session)
            attempts_after = len(session.scalars(select(DispatchAttempt)).all())
            logs_after = len(session.scalars(select(ExecutionLog)).all())
        assert attempts_after == attempts_before == 1
        assert logs_after == logs_before == 0


class TestImmutableFactCorrelation:
    """M4-GR: a terminal SETTLES an attempt ONLY when ALL THREE immutable durable facts
    agree — ``execution_id`` AND the referenced ``attempt_id`` AND (because a committed
    ``execution_log`` row ALWAYS carries a non-null ``approval_id``) ``approval_id``.

    M4-G correlated on ``attempt_id`` ALONE, so a terminal belonging to a DIFFERENT
    execution that merely referenced this attempt's ``attempt_id`` could wrongly erase a
    still-pending attempt from the recovery view (Final Review finding: "有跨 execution
    误关联缺口"). Recovery exists precisely to survive crashed / corrupted / mis-ordered /
    cross-linked history, so ANY missing, malformed, cross-execution, cross-approval or
    wrong-attempt_id reference is fail-closed -> DISPATCH_STATUS_UNKNOWN, never a settle.
    The correlation is by the attempt's IMMUTABLE facts only — NEVER back-filled from the
    current config or another log."""

    def test_cross_execution_terminal_referencing_the_attempt_does_not_settle(
        self, durable_engine
    ):
        # The reviewer's EXACT scenario: a durable attempt on execution A / attempt X, and
        # a 'failed' terminal that BELONGS TO a different execution B (its own approval) yet
        # references X's attempt_id. attempt_id alone must NOT settle — execution_id must
        # ALSO agree — so the pending attempt X stays unreconciled and DISPATCH_STATUS_UNKNOWN.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        foreign_execution_id = uuid.uuid4()  # execution B
        foreign_approval_id = uuid.uuid4()  # approval B
        assert foreign_execution_id != uuid.UUID(binding.execution_id)
        _seed_terminal(
            durable_engine,
            foreign_execution_id,           # a DIFFERENT execution ...
            foreign_approval_id,            # ... a DIFFERENT approval ...
            decision="failed",
            attempt_id=binding.attempt_id,  # ... but it references THIS attempt X
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        # the attempt is STILL pending — the cross-execution reference is inert.
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]
        assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        assert rec.audit_decision is None
        # and it is NEVER promoted to a confirmed external effect.
        assert rec.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED

    def test_same_execution_wrong_approval_id_does_not_settle(self, durable_engine):
        # execution_id AND attempt_id agree, but the terminal carries a DIFFERENT
        # approval_id -> a cross-approval mis-reference -> fail-closed UNKNOWN.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        wrong_approval_id = uuid.uuid4()
        assert wrong_approval_id != uuid.UUID(binding.approval_id)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),  # the SAME execution
            wrong_approval_id,                # a WRONG approval
            decision="succeeded",
            attempt_id=binding.attempt_id,    # the correct attempt_id
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]
        assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        assert rec.audit_decision is None

    def test_same_execution_wrong_attempt_id_does_not_settle(self, durable_engine):
        # execution_id AND approval_id agree, but the terminal references a DIFFERENT
        # attempt_id -> a wrong-attempt mis-reference -> fail-closed UNKNOWN (the
        # classification view; the unreconciled view is TestAttemptIdCorrelation's).
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="succeeded",
            attempt_id=uuid.uuid4(),  # a WRONG / unrelated attempt id
        )
        with _independent_session(durable_engine) as session:
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        assert rec.audit_decision is None

    def test_malformed_attempt_id_reference_does_not_settle(self, durable_engine):
        # A terminal whose attempt_id reference is NOT a valid UUID settles NOTHING
        # (fail-closed), even though it sits on the SAME execution_id + approval_id.
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="succeeded",
            attempt_id="not-a-valid-uuid",  # malformed reference
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        assert [a.attempt_id for a in unreconciled] == [uuid.UUID(binding.attempt_id)]
        assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        assert rec.audit_decision is None

    def test_all_three_immutable_facts_agree_settles_the_attempt(self, durable_engine):
        # POSITIVE control: execution_id + approval_id + attempt_id ALL agree -> the
        # terminal settles the attempt as TERMINAL_AUDIT_PRESENT (a succeeded audit).
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="succeeded",
            attempt_id=binding.attempt_id,
        )
        with _independent_session(durable_engine) as session:
            unreconciled = find_unreconciled_attempts(session)
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        assert unreconciled == []
        assert rec.disposition is RecoveryDisposition.TERMINAL_AUDIT_PRESENT
        assert rec.audit_decision == "succeeded"

    def test_failed_with_all_facts_agreeing_is_audit_present_not_confirmed(
        self, durable_engine
    ):
        # A CORRECTLY correlated 'failed' terminal (all three facts agree) is STILL only a
        # TERMINAL_AUDIT_PRESENT audit fact — NEVER confirmed_failure / EXTERNAL_EFFECT_
        # CONFIRMED (the external action may have landed before the failure was recorded).
        store = DurableDispatchAttemptStore(durable_engine)
        binding = _binding()
        store.record(binding)
        _seed_terminal(
            durable_engine,
            uuid.UUID(binding.execution_id),
            uuid.UUID(binding.approval_id),
            decision="failed",
            attempt_id=binding.attempt_id,
        )
        with _independent_session(durable_engine) as session:
            rec = {r.attempt_id: r for r in classify_attempt_recovery(session)}[
                uuid.UUID(binding.attempt_id)
            ]
        assert rec.disposition is RecoveryDisposition.TERMINAL_AUDIT_PRESENT
        assert rec.audit_decision == "failed"
        assert rec.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
