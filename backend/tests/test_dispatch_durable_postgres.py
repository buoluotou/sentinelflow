"""PostgreSQL-specific durable-dispatch integration.

WHY THIS FILE EXISTS: "如使用 SQLite 无法可靠模拟生产锁或
崩溃语义，必须补充 PostgreSQL 专项集成测试或明确保持对应能力未验证。不能以 SQLite
全绿宣称 PostgreSQL 事务与并发已认证。"

The store-level durability (independent-connection commit, rollback survival, recovery)
and the service/endpoint control flow are proven on FILE-backed SQLite in
``test_dispatch_attempt_durability.py`` / ``test_dispatch_durable_integration.py`` /
``test_dispatch_endpoint_durability.py``. But a set of capabilities CANNOT be certified
on SQLite — its lock is DATABASE-level (an open write on ANY table blocks a write on ANY
other: "database is locked"), it SERIALISES writers (so a unique-index race is only
provable deterministically, never as a real parallel race), and file-backed SQLite runs
with FOREIGN KEYS OFF (so ``execution_log.approval_id`` is unenforced). PostgreSQL MVCC +
its unique indexes + enforced FKs are the production semantics.

SCENARIO MATRIX:

req 1  SAME approval_id, DIFFERENT execution_id concurrent reservation — the approval-slot unique index (``ux_dispatch_attempt_approval_id``) adjudicates a
TRUE parallel race to EXACTLY ONE winner BEFORE any external call.
-> TestPostgresApprovalSlotRace
req 2  SAME execution_id concurrent replay — ``ux_dispatch_attempt_execution_id``
commits EXACTLY ONE; the loser raises IntegrityError (-> typed 409, ZERO
external calls). -> TestPostgresDurableInterleaving
req 3  caller's OPEN (uncommitted) write transaction vs the store's INDEPENDENT
commit on a SECOND connection — MVCC lets them overlap; the independent commit
SURVIVES the caller's rollback. -> TestPostgresDurableInterleaving
req 4  commit SUCCEEDED but the client confirmation was LOST — the read-only recovery
check FINDS the durable attempt and KEEPS the uncertainty (never auto-retries).
-> TestPostgresCommitConfirmationLost
req 5  terminal-write failure / caller rollback / process interruption — the committed
attempt SURVIVES, the caller's rows vanish, recovery flags the orphan.
-> TestPostgresTerminalFailureSurvival
req 6  orphan-attempt recovery AFTER a restart (engine disposed, fresh engine reopened)
— durability lives in the DATABASE, not the process. -> TestPostgresRestartRecovery
req 7  a WRONG-attempt_id terminal on the SAME execution_id does NOT mask the pending
attempt (recovery correlates by attempt_id, never execution_id alone).
-> TestPostgresAttemptIdCorrelation
req 8  a FAILED dispatch is NEVER ``confirmed_failure`` — a ``failed`` terminal that
REFERENCES the attempt is a TERMINAL_AUDIT_PRESENT audit fact, never
EXTERNAL_EFFECT_CONFIRMED, and fabricates NO Outcome row.
-> TestPostgresAttemptIdCorrelation
req 9  ZERO automatic second external call — a naive retry on the SAME approval after a
lost confirmation is REJECTED by the approval-slot index BEFORE the adapter.
-> TestPostgresCommitConfirmationLost

STATUS — **PostgreSQL UNVERIFIED**. This module is ``@pytest.mark.external`` (conftest
DESELECTS it unless ``-m external``) AND guarded by a dedicated-DB env var, so a normal
``pytest`` run NEVER touches a database and this SKIPS rather than faking a result. Until
it is RUN against a real PostgreSQL, EVERY scenario above stays UNVERIFIED — it is NOT
certified by the green SQLite run, and this suite MUST NOT be cited as proof that real
PostgreSQL concurrency/transaction semantics pass.

SAFETY: ``SENTINELFLOW_PG_TEST_URL`` MUST point at a DEDICATED throwaway
PostgreSQL; NEVER a production/shared database. The suite issues ``Base.metadata
.create_all`` (idempotent — ``checkfirst``; NEVER ``drop_all``) and each test removes ONLY
the rows IT created via ``_cleanup`` (targeted, FK-safe DELETEs scoped to the test's own
ids) — NEVER a blanket truncate / destructive wipe. Tests are order-independent and
repeatable: assertions are SCOPED to each test's own execution_ids / approval_id.
"""
import os
import threading
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    DispatchAttempt,
    ExecutionLog,
    ExecutionOutcome,
)
from app.services.executions.binding import (
    TERMINAL_REFERENCE_KEY,
    build_dispatch_binding,
)
from app.services.executions.durable_dispatch import (
    DurableDispatchAttemptStore,
    RecoveryDisposition,
    classify_attempt_recovery,
    find_unreconciled_attempts,
)

# The dedicated-DB env var. Unset -> SKIP (LAB BLOCKED), never a fabricated pass.
PG_URL_ENV = "SENTINELFLOW_PG_TEST_URL"


def _pg_engine():
    """A REAL PostgreSQL engine on the DEDICATED throwaway DB, or SKIP (LAB BLOCKED).

Module-level so every test class shares ONE guard + ``create_all``. ``create_all``
is idempotent (``checkfirst=True``) and NEVER drops — the throwaway schema is
provisioned once; each test cleans up ONLY its own rows (``_cleanup``).
"""
    url = os.environ.get(PG_URL_ENV, "")
    if not url:
        pytest.skip(
            "LAB BLOCKED: no dedicated PostgreSQL configured "
            f"({PG_URL_ENV} unset) — the true MVCC interleaving, concurrent "
            "approval-slot race, commit-confirmation-loss, restart recovery and "
            "FK-enforced attempt_id correlation stay explicitly UNVERIFIED "
            "(M4-G §4: SQLite's single-writer lock + FK-off cannot certify them)."
        )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return engine


def _pg_binding(execution_id=None, approval_id=None):
    """A deterministic pre-dispatch binding (server-side facts only).

``approval_id`` is injectable so can race the SAME approval across DIFFERENT
execution_ids (req 1 — the D14 approval-slot unique index) and reuse a REAL seeded
approval where an ExecutionLog FK demands it (reqs 5/7/8).
"""
    return build_dispatch_binding(
        execution_id=execution_id or uuid.uuid4(),
        approval_id=approval_id or uuid.uuid4(),
        adapter="thehive",
        action="create_case",
        target="203.0.113.10",
        approval_status="approved",
        dispatch_started_at=datetime.now(timezone.utc),
        contributor_facts={
            "endpoint": "https://thehive.lab.internal",
            "version_evidence_ref": "config:THEHIVE_EXPECTED_VERSION",
            "version_assertion_kind": "config-declaration",
            "target_instance": None,
            "target_tenant": None,
        },
    )


def _attempt_row(binding):
    """A raw ``DispatchAttempt`` from a binding (the caller's open-write analog)."""
    return DispatchAttempt(
        attempt_id=uuid.UUID(binding.attempt_id),
        execution_id=uuid.UUID(binding.execution_id),
        approval_id=uuid.UUID(binding.approval_id),
        adapter=binding.adapter,
        action=binding.action,
        target=binding.target,
        dispatch_started_at=binding.started_at(),
        detail={},
    )


def _seed_approval_chain(engine):
    """Seed + COMMIT a REAL ``alert_group -> recommendation -> approval`` chain; return
``(approval_id, group_id)``.

PostgreSQL ENFORCES ``execution_log.approval_id`` as a FK to ``ai_response_approvals``
(checked at flush), so any scenario that writes/flushes an ExecutionLog row (reqs
5/7/8) MUST first have a real approval. file-backed SQLite runs FK-OFF, which is why
the SQLite suite never needed this — a PostgreSQL-only precondition. ``group_id`` is
returned so ``_cleanup`` can remove the chain (alert_group CASCADEs to recommendation
-> approval). Ids are captured BEFORE commit (avoid post-commit attribute expiry).
"""
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        group = AlertGroup(
            fingerprint=uuid.uuid4().hex,
            title="SSH Brute Force on edge-gateway",
            category="authentication",
            severity="high",
            first_seen=now,
            last_seen=now,
        )
        session.add(group)
        session.flush()
        record = AIResponseRecommendation(
            alert_group=group,
            provider="mock",
            model="mock-deterministic",
            overall_rationale="[mock] guidance",
            recommendations=[
                {"action": "block_source_ip", "target": "203.0.113.10", "rationale": "abuse"}
            ],
            confidence=0.7,
        )
        session.add(record)
        session.flush()
        approval = AIResponseApproval(
            recommendation_id=record.id,
            status="approved",
            reviewer="analyst-1",
            reviewed_at=now,
        )
        session.add(approval)
        session.flush()
        approval_id, group_id = approval.id, group.id
        session.commit()
    return approval_id, group_id


def _pg_terminal_row(engine, binding, approval_id, decision, attempt_id=None):
    """Append + COMMIT a terminal ``execution_log`` row (``succeeded`` / ``failed``) that
REFERENCES ``attempt_id`` via ``TERMINAL_REFERENCE_KEY`` (``None`` -> no reference).

Mirrors the real service's terminal write (``service.py``:
``detail[TERMINAL_REFERENCE_KEY] = binding.attempt_id``). ``approval_id`` MUST be a
REAL seeded approval (PostgreSQL FK); a terminal decision falls OUTSIDE every
execution_log partial unique index (those bite only ``requested`` /
``compensation_requested``), so terminals never collide.
"""
    detail = {} if attempt_id is None else {TERMINAL_REFERENCE_KEY: str(attempt_id)}
    with Session(engine) as session:
        session.add(
            ExecutionLog(
                execution_id=uuid.UUID(binding.execution_id),
                approval_id=approval_id,
                decision=decision,
                direction="execute",
                action=binding.action,
                target=binding.target,
                operator="ops-1",
                detail=detail,
            )
        )
        session.commit()


def _cleanup(engine, *, execution_ids=(), approval_group_ids=()):
    """TARGETED, FK-safe deletion of ONLY the rows a test created.

NEVER ``drop_all`` / truncate / blanket delete — the throwaway DB stays reusable and
the wipe is scoped to this test's own ids. Order
respects the FK graph: ``execution_log`` (NO ACTION -> approvals) and the FK-free
``dispatch_attempt`` / ``execution_outcome`` FIRST (by execution_id), THEN the approval
chain via ``alert_group`` (CASCADEs to recommendation -> approval). Deleting the group
before the execution_log rows would trip the NO-ACTION FK, hence the order.
"""
    exec_ids = [uuid.UUID(str(e)) for e in execution_ids]
    with Session(engine) as session:
        if exec_ids:
            session.execute(
                delete(ExecutionLog).where(ExecutionLog.execution_id.in_(exec_ids))
            )
            session.execute(
                delete(ExecutionOutcome).where(ExecutionOutcome.execution_id.in_(exec_ids))
            )
            session.execute(
                delete(DispatchAttempt).where(DispatchAttempt.execution_id.in_(exec_ids))
            )
        for group_id in approval_group_ids:
            session.execute(delete(AlertGroup).where(AlertGroup.id == uuid.UUID(str(group_id))))
        session.commit()


@pytest.mark.external
class TestPostgresDurableInterleaving:
    """reqs 3 + 2 — TRUE MVCC interleaving + concurrent replay on a REAL PostgreSQL: the
two capabilities file-backed SQLite CANNOT certify (see the module docstring)."""

    def test_open_caller_write_transaction_does_not_block_the_independent_commit(self):
        """req 3 — the caller holds an OPEN write transaction WHILE the store commits the
attempt on a SECOND connection, then the caller rolls its WHOLE transaction back.
PostgreSQL MVCC: the independent commit SUCCEEDS and SURVIVES; the rolled-back
caller row vanishes. (On SQLite this raises "database is locked" — the exact reason
the capability is UNVERIFIABLE there.)"""
        engine = _pg_engine()
        caller_binding = _pg_binding()  # execution_id A — the caller's open write
        store_binding = _pg_binding()  # execution_id B — the durable pre-dispatch
        caller_exec = uuid.UUID(caller_binding.execution_id)
        store_exec = uuid.UUID(store_binding.execution_id)
        try:
            store = DurableDispatchAttemptStore(engine)
            caller = Session(engine)
            try:
                caller.add(_attempt_row(caller_binding))
                caller.flush()  # OPEN, UNCOMMITTED write transaction (holds a lock)
                # WHILE the caller's transaction is still open, commit B independently.
                store.record(store_binding)
                # The caller then aborts its WHOLE transaction (crash / rollback).
                caller.rollback()
            finally:
                caller.close()
            # B (independently committed) SURVIVES; A (rolled back) is gone; B has no
            # terminal -> recovery flags it as a MANUAL reconciliation candidate. Assertions
            # are SCOPED to A/B so the test is order-independent on a reused throwaway DB.
            with Session(engine) as reader:
                rows = reader.scalars(
                    select(DispatchAttempt).where(
                        DispatchAttempt.execution_id.in_([caller_exec, store_exec])
                    )
                ).all()
                assert [r.execution_id for r in rows] == [store_exec]
                flagged = {a.execution_id for a in find_unreconciled_attempts(reader)}
                assert store_exec in flagged  # B: committed, no terminal -> UNKNOWN
                assert caller_exec not in flagged  # A: rolled back -> never existed
        finally:
            _cleanup(engine, execution_ids=[caller_exec, store_exec])
            engine.dispose()

    def test_concurrent_replay_commits_exactly_one_attempt(self):
        """req 2 — two threads race ``store.record()`` on the SAME execution_id: the unique
index commits EXACTLY ONE and the loser raises ``IntegrityError`` (which the Service
maps to the typed 409 with ZERO external calls — proven deterministically in
``test_dispatch_durable_integration.py``). This is the TRUE parallel race SQLite
serialises away."""
        engine = _pg_engine()
        execution_id = uuid.uuid4()
        try:
            store = DurableDispatchAttemptStore(engine)
            outcomes: list[str] = []
            lock = threading.Lock()

            def _race():
                binding = _pg_binding(execution_id=execution_id)  # SAME execution_id
                try:
                    store.record(binding)
                    verdict = "committed"
                except IntegrityError:
                    verdict = "conflict"
                with lock:
                    outcomes.append(verdict)

            threads = [threading.Thread(target=_race) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            assert sorted(outcomes) == ["committed", "conflict"]
            with Session(engine) as reader:
                rows = reader.scalars(
                    select(DispatchAttempt).where(
                        DispatchAttempt.execution_id == execution_id
                    )
                ).all()
            # EXACTLY ONE durable attempt -> at most ONE external request proceeds.
            assert len(rows) == 1
            assert rows[0].execution_id == execution_id
        finally:
            _cleanup(engine, execution_ids=[execution_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresApprovalSlotRace:
    """req 1 — the approval-slot unique index (``ux_dispatch_attempt_approval_id``)
under TRUE PostgreSQL concurrency: SAME approval_id, DIFFERENT execution_ids.

SQLite serialises writers, so this race is only provable there deterministically
(sequential duplicate); PostgreSQL MVCC makes it a REAL parallel race the unique index
must adjudicate to EXACTLY ONE winner BEFORE any external call. This is the durable
reservation the review found missing — the execution_log partial approval index
only bites at caller-commit AFTER the wire call, so the reservation lives HERE."""

    def test_same_approval_different_execution_commits_exactly_one(self):
        engine = _pg_engine()
        approval_id = uuid.uuid4()  # the ONE contended approval slot
        created_exec: list[uuid.UUID] = []  # the DIFFERENT execution_ids the racers mint
        try:
            store = DurableDispatchAttemptStore(engine)
            outcomes: list[str] = []
            lock = threading.Lock()

            def _race():
                execution_id = uuid.uuid4()  # DIFFERENT execution_id per racer
                binding = _pg_binding(execution_id=execution_id, approval_id=approval_id)
                try:
                    store.record(binding)
                    verdict = "committed"
                except IntegrityError:
                    verdict = "conflict"
                with lock:
                    outcomes.append(verdict)
                    created_exec.append(execution_id)

            threads = [threading.Thread(target=_race) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            # EXACTLY ONE racer wins the approval slot; the loser is refused BEFORE any
            # external request (-> the Service's typed 409, ZERO second outbound call).
            assert sorted(outcomes) == ["committed", "conflict"]
            with Session(engine) as reader:
                rows = reader.scalars(
                    select(DispatchAttempt).where(
                        DispatchAttempt.approval_id == approval_id
                    )
                ).all()
            assert len(rows) == 1  # ONE durable attempt per approval -> at most ONE dispatch
            assert rows[0].approval_id == approval_id
            assert rows[0].execution_id in created_exec
        finally:
            _cleanup(engine, execution_ids=created_exec)
            engine.dispose()


@pytest.mark.external
class TestPostgresCommitConfirmationLost:
    """reqs 4 + 9 — commit SUCCEEDED but the client confirmation was LOST.

The durable attempt is committed; the caller, unsure whether the external effect
landed, MUST NOT auto-retry with a fresh execution_id / approval reservation. The
READ-ONLY recovery check FINDS the committed attempt and KEEPS the uncertainty
(DISPATCH_STATUS_UNKNOWN, never a fabricated terminal); a naive retry on the SAME
approval is REJECTED by the approval-slot index BEFORE any second external call
(req 9: ZERO automatic second external call)."""

    def test_lost_confirmation_is_recovered_and_naive_retry_is_rejected(self):
        engine = _pg_engine()
        binding = _pg_binding()
        execution_id = uuid.UUID(binding.execution_id)
        approval_id = uuid.UUID(binding.approval_id)
        retry_execution_id = uuid.uuid4()  # the naive retry's fresh execution_id
        try:
            store = DurableDispatchAttemptStore(engine)
            store.record(binding)  # COMMITTED ... but the client ack is "lost"

            # Read-only recovery FINDS the durable attempt and KEEPS the uncertainty —
            # no terminal references it -> DISPATCH_STATUS_UNKNOWN (NEVER an auto-retry,
            # NEVER a fabricated succeeded/confirmed row).
            with Session(engine) as reader:
                unreconciled = find_unreconciled_attempts(reader)
                assert execution_id in {a.execution_id for a in unreconciled}
                classified = {r.attempt_id: r for r in classify_attempt_recovery(reader)}
                rec = classified[uuid.UUID(binding.attempt_id)]
                assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                assert rec.audit_decision is None
                assert rec.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED

            # A NAIVE retry (SAME approval, NEW execution_id) is REJECTED by the
            # approval-slot unique index BEFORE the external adapter is reached -> ZERO
            # automatic second external call (req 9).
            retry_binding = _pg_binding(
                execution_id=retry_execution_id, approval_id=approval_id
            )
            with pytest.raises(IntegrityError):
                store.record(retry_binding)

            with Session(engine) as reader:
                rows = reader.scalars(
                    select(DispatchAttempt).where(
                        DispatchAttempt.approval_id == approval_id
                    )
                ).all()
            # STILL exactly ONE attempt for the approval -> no second dispatch happened.
            assert len(rows) == 1
            assert rows[0].execution_id == execution_id
        finally:
            _cleanup(engine, execution_ids=[execution_id, retry_execution_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresTerminalFailureSurvival:
    """req 5 — terminal-write failure / caller rollback / process interruption.

The store committed the attempt on its OWN connection BEFORE the external call; the
caller's business transaction (which would carry the ``dispatched`` -> terminal rows)
then ROLLS BACK. PostgreSQL MVCC: the committed attempt SURVIVES, the caller's rows
vanish, and recovery flags the orphan (no terminal references its attempt_id). Needs a
REAL seeded approval because the caller FLUSHES an ExecutionLog row (PG FK)."""

    def test_attempt_survives_caller_rollback_and_is_flagged(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        caller = Session(engine)
        try:
            DurableDispatchAttemptStore(engine).record(binding)  # committed independently
            # The caller appends + FLUSHES its 'dispatched' row (FK-checked against the real
            # approval), then the terminal write FAILS / the process is interrupted -> the
            # WHOLE caller transaction aborts.
            caller.add(
                ExecutionLog(
                    execution_id=execution_id,
                    approval_id=approval_id,
                    decision="dispatched",
                    direction="execute",
                    action=binding.action,
                    target=binding.target,
                    operator="ops-1",
                    detail={TERMINAL_REFERENCE_KEY: binding.attempt_id},
                )
            )
            caller.flush()
            caller.rollback()  # the terminal never commits
        finally:
            caller.close()
        try:
            with Session(engine) as reader:
                # The durable attempt SURVIVED the caller rollback ...
                attempts = reader.scalars(
                    select(DispatchAttempt).where(
                        DispatchAttempt.execution_id == execution_id
                    )
                ).all()
                assert [a.attempt_id for a in attempts] == [uuid.UUID(binding.attempt_id)]
                # ... but NO caller row survived (the flushed 'dispatched' vanished).
                logs = reader.scalars(
                    select(ExecutionLog).where(ExecutionLog.execution_id == execution_id)
                ).all()
                assert logs == []
                # > recovery flags the orphan as a MANUAL, read-only candidate.
                assert execution_id in {
                    a.execution_id for a in find_unreconciled_attempts(reader)
                }
        finally:
            _cleanup(engine, execution_ids=[execution_id], approval_group_ids=[group_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresRestartRecovery:
    """req 6 — orphan-attempt recovery AFTER a restart.

The attempt is committed, then the engine is DISPOSED (the process-restart analog: every
connection dropped) and a FRESH engine is reopened on the SAME dedicated DB. The durable
attempt SURVIVES the restart and recovery STILL flags it — proving durability lives in the
DATABASE, not the process/connection. The recovery identity facts come from the IMMUTABLE
durable attempt, never back-filled from the current config."""

    def test_orphan_attempt_survives_restart_and_is_recovered(self):
        engine = _pg_engine()
        binding = _pg_binding()
        execution_id = uuid.UUID(binding.execution_id)
        try:
            DurableDispatchAttemptStore(engine).record(binding)
        finally:
            engine.dispose()  # "process restart" — drop every connection

        restarted = _pg_engine()  # a FRESH engine on the SAME dedicated DB
        try:
            with Session(restarted) as reader:
                assert execution_id in {
                    a.execution_id for a in find_unreconciled_attempts(reader)
                }
                classified = {r.attempt_id: r for r in classify_attempt_recovery(reader)}
                rec = classified[uuid.UUID(binding.attempt_id)]
                assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                # Identity facts are the durable attempt's IMMUTABLE snapshot, not config.
                assert (rec.adapter, rec.action, rec.target) == (
                    "thehive",
                    "create_case",
                    "203.0.113.10",
                )
        finally:
            _cleanup(restarted, execution_ids=[execution_id])
            restarted.dispose()


@pytest.mark.external
class TestPostgresAttemptIdCorrelation:
    """reqs 7 + 8 — recovery correlates by attempt_id, NOT execution_id, on a REAL
PostgreSQL (FK-enforced ``execution_log``).

req 7: a terminal carrying a WRONG attempt_id on the SAME execution_id does NOT settle /
mask the still-pending attempt. req 8: a ``failed`` terminal that DOES reference the
attempt is a TERMINAL_AUDIT_PRESENT audit fact — NEVER ``confirmed_failure`` /
EXTERNAL_EFFECT_CONFIRMED — and fabricates NO Outcome row (a failed dispatch may still
have landed externally; only the authoritative Outcome path can confirm an effect)."""

    def test_wrong_attempt_id_terminal_does_not_mask_the_pending_attempt(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        try:
            DurableDispatchAttemptStore(engine).record(binding)
            # A terminal on the SAME execution_id but a DIFFERENT (wrong) attempt_id.
            _pg_terminal_row(
                engine, binding, approval_id, "succeeded", attempt_id=uuid.uuid4()
            )
            with Session(engine) as reader:
                # The real attempt is STILL pending — the wrong-attempt terminal is inert.
                assert execution_id in {
                    a.execution_id for a in find_unreconciled_attempts(reader)
                }
                classified = {r.attempt_id: r for r in classify_attempt_recovery(reader)}
                rec = classified[uuid.UUID(binding.attempt_id)]
                assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                assert rec.audit_decision is None
        finally:
            _cleanup(engine, execution_ids=[execution_id], approval_group_ids=[group_id])
            engine.dispose()

    def test_failed_terminal_is_audit_present_never_confirmed_failure(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        try:
            DurableDispatchAttemptStore(engine).record(binding)
            # A 'failed' terminal that CORRECTLY references the attempt_id.
            _pg_terminal_row(
                engine, binding, approval_id, "failed", attempt_id=binding.attempt_id
            )
            with Session(engine) as reader:
                # Settled BY attempt_id -> no longer unreconciled.
                assert execution_id not in {
                    a.execution_id for a in find_unreconciled_attempts(reader)
                }
                classified = {r.attempt_id: r for r in classify_attempt_recovery(reader)}
                rec = classified[uuid.UUID(binding.attempt_id)]
                # TERMINAL_AUDIT_PRESENT with a 'failed' AUDIT — NEVER confirmed_failure.
                assert rec.disposition is RecoveryDisposition.TERMINAL_AUDIT_PRESENT
                assert rec.audit_decision == "failed"
                assert rec.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
                # A failed dispatch fabricates NO external-effect Outcome row (the recovery
                # read is append-only-inert; only the authoritative reconcile path writes).
                outcomes = reader.scalars(
                    select(ExecutionOutcome).where(
                        ExecutionOutcome.execution_id == execution_id
                    )
                ).all()
                assert outcomes == []
        finally:
            _cleanup(engine, execution_ids=[execution_id], approval_group_ids=[group_id])
            engine.dispose()

    def test_cross_execution_terminal_referencing_the_attempt_does_not_settle(self):
        # (req 7 extension): a terminal belonging to a DIFFERENT execution B (its own
        # REAL seeded approval — execution_log.approval_id is FK-enforced on PostgreSQL) that
        # merely REFERENCES attempt X's attempt_id must NOT settle attempt X (execution A /
        # approval A). attempt_id alone is NOT enough — the immutable execution_id AND
        # approval_id must ALSO agree, else a corrupted / mis-ordered / cross-linked terminal
        # from another execution could erase a still-pending attempt from the recovery view.
        # This is the SQLite ``TestImmutableFactCorrelation`` scenario re-proved under
        # PostgreSQL MVCC + enforced FKs.
        engine = _pg_engine()
        approval_a, group_a = _seed_approval_chain(engine)
        approval_b, group_b = _seed_approval_chain(engine)
        binding_a = _pg_binding(approval_id=approval_a)  # execution A / attempt X
        binding_b = _pg_binding(approval_id=approval_b)  # execution B — a DIFFERENT chain
        exec_a = uuid.UUID(binding_a.execution_id)
        exec_b = uuid.UUID(binding_b.execution_id)
        try:
            DurableDispatchAttemptStore(engine).record(binding_a)  # the real pending attempt X
            # A 'failed' terminal on execution B / approval B that WRONGLY references attempt X.
            _pg_terminal_row(
                engine, binding_b, approval_b, "failed", attempt_id=binding_a.attempt_id
            )
            with Session(engine) as reader:
                # attempt X is STILL unreconciled — the cross-execution reference is inert.
                assert exec_a in {
                    a.execution_id for a in find_unreconciled_attempts(reader)
                }
                classified = {r.attempt_id: r for r in classify_attempt_recovery(reader)}
                rec = classified[uuid.UUID(binding_a.attempt_id)]
                assert rec.disposition is RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                assert rec.audit_decision is None
                # and it is NEVER promoted to a confirmed external effect.
                assert rec.disposition is not RecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
        finally:
            _cleanup(
                engine,
                execution_ids=[exec_a, exec_b],
                approval_group_ids=[group_a, group_b],
            )
            engine.dispose()
