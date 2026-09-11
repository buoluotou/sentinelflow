"""PostgreSQL-specific durable-compensation integration.

WHY THIS FILE EXISTS. SQLite's lock is DATABASE-level (an open write on ANY
table blocks a write on ANY other: "database is locked"), it SERIALISES
writers (so a unique-index race is never a real parallel race), and file-backed
SQLite runs with FOREIGN KEYS OFF. PostgreSQL MVCC + its unique indexes +
enforced FKs are the production semantics — so the C-1 capabilities are
certified HERE or stay explicitly UNVERIFIED:

req A  SAME original_execution_id concurrent compensation — the C-1
reservation (``ux_compensation_attempt_original_execution_id``)
adjudicates a TRUE parallel race to EXACTLY ONE winner BEFORE any
external reverse call. -> TestPostgresCompensationReservation
req B  SAME compensation execution_id concurrent replay —
``ux_compensation_attempt_execution_id`` commits EXACTLY ONE; the
loser raises IntegrityError (-> typed 409, ZERO external calls).
-> TestPostgresCompensationInterleaving
req C  caller's OPEN (uncommitted) write transaction vs the store's
INDEPENDENT commit on a SECOND connection — MVCC lets them overlap;
the independent commit SURVIVES the caller's rollback.
-> TestPostgresCompensationInterleaving
req D  commit SUCCEEDED but the client confirmation was LOST — the read-only
recovery check FINDS the durable attempt, KEEPS the uncertainty
(never auto-retries), and a naive re-compensation on the SAME
original is REJECTED before the adapter.
-> TestPostgresCompensationCommitConfirmationLost
req E  terminal-write failure / caller rollback — the committed compensation
attempt SURVIVES, the caller's rows vanish, recovery flags the orphan;
a committed agreeing terminal SETTLES it (audit only).
-> TestPostgresCompensationTerminalSurvival
req F  orphan recovery AFTER a restart (engine disposed, fresh engine
reopened) — durability lives in the DATABASE, not the process.
-> TestPostgresCompensationRestartRecovery
req G  a wrong-attempt-reference / cross-execution terminal does NOT settle a
pending compensation attempt (correlation by all immutable facts).
-> TestPostgresCompensationCorrelation

STATUS — **PostgreSQL UNVERIFIED** until this module runs against a real
PostgreSQL. It is ``@pytest.mark.external`` (conftest DESELECTS it unless
``-m external``) AND guarded by the dedicated-DB env var, so a normal ``pytest``
run NEVER touches a database and this SKIPS rather than faking a result.

SAFETY: ``SENTINELFLOW_PG_TEST_URL`` MUST point at a DEDICATED throwaway
PostgreSQL; NEVER a production/shared database. ``create_all`` is idempotent
(``checkfirst``; NEVER ``drop_all``); ``_cleanup`` removes ONLY the rows a test
created (targeted, FK-safe DELETEs scoped to the test's own ids).
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
    CompensationAttempt,
    ExecutionLog,
)
from app.services.executions.compensation_binding import (
    COMPENSATION_REFERENCE_KEY,
    build_compensation_binding,
)
from app.services.executions.durable_compensation import (
    CompensationRecoveryDisposition,
    DurableCompensationAttemptStore,
    classify_compensation_recovery,
    find_unreconciled_compensations,
)

# The dedicated-DB env var. Unset -> SKIP (LAB BLOCKED), never a fabricated pass.
PG_URL_ENV = "SENTINELFLOW_PG_TEST_URL"


def _pg_engine():
    """A REAL PostgreSQL engine on the DEDICATED throwaway DB, or SKIP.

Module-level so every test class shares ONE guard + ``create_all``.
``create_all`` is idempotent (``checkfirst=True``) and NEVER drops; each
test cleans up ONLY its own rows (``_cleanup``).
"""
    url = os.environ.get(PG_URL_ENV, "")
    if not url:
        pytest.skip(
            "LAB BLOCKED: no dedicated PostgreSQL configured "
            f"({PG_URL_ENV} unset) — the true C-1 MVCC interleaving, concurrent "
            "one-compensation-per-original reservation race, commit-confirmation "
            "loss and restart recovery stay explicitly UNVERIFIED."
        )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return engine


def _pg_comp_binding(
    execution_id=None,
    original_execution_id=None,
    approval_id=None,
    original_dispatch_attempt_id=None,
):
    """A deterministic pre-compensation binding (server-side facts only).

``original_execution_id`` is injectable so the suite can race the SAME
original execution across DIFFERENT compensation execution_ids (the C-1
reservation); ``approval_id`` is injectable so terminal rows can use a REAL
seeded approval (the PostgreSQL FK on ``execution_log.approval_id``).
"""
    now = datetime.now(timezone.utc)
    return build_compensation_binding(
        execution_id=execution_id or uuid.uuid4(),
        original_execution_id=original_execution_id or uuid.uuid4(),
        original_dispatch_attempt_id=original_dispatch_attempt_id,
        approval_id=approval_id or uuid.uuid4(),
        adapter="shuffle",
        action="block_source_ip",
        target="203.0.113.10",
        operator="ops-1",
        reason="lab compensation",
        original_outcome_state="succeeded",
        prepared_at=now,
        dispatch_started_at=now,
        contributor_facts={
            "endpoint": "https://shuffle.lab.internal",
            "version_evidence_ref": "config:SHUFFLE_EXPECTED_VERSION",
            "version_assertion_kind": "config-declaration",
            "target_instance": None,
            "target_tenant": None,
        },
    )


def _comp_row(binding):
    """A raw ``CompensationAttempt`` from a binding (the caller's open-write analog)."""
    return CompensationAttempt(
        compensation_attempt_id=uuid.UUID(binding.compensation_attempt_id),
        execution_id=uuid.UUID(binding.execution_id),
        original_execution_id=uuid.UUID(binding.original_execution_id),
        original_dispatch_attempt_id=None,
        approval_id=uuid.UUID(binding.approval_id),
        adapter=binding.adapter,
        reverse_action=binding.reverse_action,
        target=binding.target,
        endpoint=binding.endpoint,
        operator=binding.operator,
        reason=binding.reason,
        original_outcome_state=binding.original_outcome_state,
        prepared_at=binding.prepared_instant(),
        dispatch_started_at=binding.started_at(),
        detail={},
    )


def _seed_approval_chain(engine):
    """Seed + COMMIT a REAL ``alert_group -> recommendation -> approval`` chain;
return ``(approval_id, group_id)``.

PostgreSQL ENFORCES ``execution_log.approval_id`` as a FK (checked at
flush), so any scenario that writes/flushes a terminal ExecutionLog row
MUST first have a real approval. ``group_id`` is returned so ``_cleanup``
can remove the chain (alert_group CASCADEs to recommendation -> approval).
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


def _comp_terminal_row(engine, binding, approval_id, decision, reference=None):
    """Append + COMMIT a terminal compensation ``execution_log`` row
(``compensation_succeeded`` / ``compensation_failed``) that REFERENCES the
attempt via ``COMPENSATION_REFERENCE_KEY`` (``None`` -> the attempt's own id;
a different value -> a wrong reference).

Mirrors the real service's terminal write
(``detail[COMPENSATION_REFERENCE_KEY] = binding.compensation_attempt_id``).
``approval_id`` MUST be a REAL seeded approval (PostgreSQL FK).
"""
    ref = reference if reference is not None else binding.compensation_attempt_id
    with Session(engine) as session:
        session.add(
            ExecutionLog(
                execution_id=uuid.UUID(binding.execution_id),
                approval_id=approval_id,
                decision=decision,
                direction="compensate",
                action=binding.reverse_action,
                target=binding.target,
                operator="ops-1",
                detail={COMPENSATION_REFERENCE_KEY: str(ref)},
                compensates_execution_id=uuid.UUID(binding.original_execution_id),
            )
        )
        session.commit()


def _cleanup(engine, *, execution_ids=(), approval_group_ids=()):
    """TARGETED, FK-safe deletion of ONLY the rows a test created.

NEVER ``drop_all`` / truncate / blanket delete. Order respects the FK graph:
``execution_log`` (NO ACTION -> approvals) and the FK-free
``compensation_attempt`` FIRST (by execution_id), THEN the approval chain
via ``alert_group``.
"""
    exec_ids = [uuid.UUID(str(e)) for e in execution_ids]
    with Session(engine) as session:
        if exec_ids:
            session.execute(
                delete(ExecutionLog).where(ExecutionLog.execution_id.in_(exec_ids))
            )
            session.execute(
                delete(CompensationAttempt).where(
                    CompensationAttempt.execution_id.in_(exec_ids)
                )
            )
        for group_id in approval_group_ids:
            session.execute(
                delete(AlertGroup).where(AlertGroup.id == uuid.UUID(str(group_id)))
            )
        session.commit()


@pytest.mark.external
class TestPostgresCompensationInterleaving:
    """reqs B + C — TRUE MVCC interleaving + concurrent replay for the reverse path."""

    def test_open_caller_write_transaction_does_not_block_the_independent_commit(self):
        """req C — the caller holds an OPEN write transaction WHILE the store commits
the compensation attempt on a SECOND connection, then the caller rolls its
WHOLE transaction back. PostgreSQL MVCC: the independent commit SUCCEEDS and
SURVIVES; the rolled-back caller row vanishes."""
        engine = _pg_engine()
        caller_binding = _pg_comp_binding()  # execution_id A — the caller's open write
        store_binding = _pg_comp_binding()  # execution_id B — the durable reverse
        caller_exec = uuid.UUID(caller_binding.execution_id)
        store_exec = uuid.UUID(store_binding.execution_id)
        try:
            store = DurableCompensationAttemptStore(engine)
            caller = Session(engine)
            try:
                caller.add(_comp_row(caller_binding))
                caller.flush()  # OPEN, UNCOMMITTED write transaction
                store.record(store_binding)  # WHILE the caller's write is open
                caller.rollback()  # crash / rollback of the WHOLE caller transaction
            finally:
                caller.close()
            with Session(engine) as reader:
                rows = reader.scalars(
                    select(CompensationAttempt).where(
                        CompensationAttempt.execution_id.in_([caller_exec, store_exec])
                    )
                ).all()
                assert [r.execution_id for r in rows] == [store_exec]
                flagged = {
                    a.execution_id for a in find_unreconciled_compensations(reader)
                }
                assert store_exec in flagged  # B: committed, no terminal -> UNKNOWN
                assert caller_exec not in flagged  # A: rolled back -> never existed
        finally:
            _cleanup(engine, execution_ids=[caller_exec, store_exec])
            engine.dispose()

    def test_concurrent_replay_commits_exactly_one_attempt(self):
        """req B — two threads race ``store.record()`` on the SAME compensation
execution_id: the unique index commits EXACTLY ONE; the loser raises
IntegrityError (-> typed 409, ZERO external reverse calls)."""
        engine = _pg_engine()
        execution_id = uuid.uuid4()
        try:
            store = DurableCompensationAttemptStore(engine)
            outcomes: list[str] = []
            lock = threading.Lock()

            def _race():
                binding = _pg_comp_binding(execution_id=execution_id)  # SAME execution_id
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
                    select(CompensationAttempt).where(
                        CompensationAttempt.execution_id == execution_id
                    )
                ).all()
            # EXACTLY ONE durable attempt -> at most ONE external reverse request.
            assert len(rows) == 1
            assert rows[0].execution_id == execution_id
        finally:
            _cleanup(engine, execution_ids=[execution_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresCompensationReservation:
    """req A — the C-1 reservation under TRUE PostgreSQL concurrency: SAME
original_execution_id, DIFFERENT compensation execution_ids. The unique
index must adjudicate to EXACTLY ONE winner BEFORE any external call — the
durable refill of "at most one compensation per original" that the
execution_log partial index only enforces at caller-commit (AFTER the wire
call)."""

    def test_same_original_execution_commits_exactly_one_compensation(self):
        engine = _pg_engine()
        original_execution_id = uuid.uuid4()  # the ONE compensated original
        created_exec: list[uuid.UUID] = []
        try:
            store = DurableCompensationAttemptStore(engine)
            outcomes: list[str] = []
            lock = threading.Lock()

            def _race():
                execution_id = uuid.uuid4()  # DIFFERENT compensation execution per racer
                binding = _pg_comp_binding(
                    execution_id=execution_id,
                    original_execution_id=original_execution_id,
                )
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

            assert sorted(outcomes) == ["committed", "conflict"]
            with Session(engine) as reader:
                rows = reader.scalars(
                    select(CompensationAttempt).where(
                        CompensationAttempt.original_execution_id
                        == original_execution_id
                    )
                ).all()
            assert len(rows) == 1  # ONE durable compensation per original
            assert rows[0].original_execution_id == original_execution_id
            assert rows[0].execution_id in created_exec
        finally:
            _cleanup(engine, execution_ids=created_exec)
            engine.dispose()


@pytest.mark.external
class TestPostgresCompensationCommitConfirmationLost:
    """req D — commit SUCCEEDED but the client confirmation was LOST.

Recovery FINDS the committed attempt and KEEPS the uncertainty
(DISPATCH_STATUS_UNKNOWN, never a fabricated terminal); a naive
re-compensation on the SAME original (new compensation execution_id) is
REJECTED by the reservation BEFORE any second external reverse call."""

    def test_lost_confirmation_is_recovered_and_naive_retry_is_rejected(self):
        engine = _pg_engine()
        binding = _pg_comp_binding()
        execution_id = uuid.UUID(binding.execution_id)
        retry_execution_id = uuid.uuid4()
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)  # COMMITTED ... but the client ack is "lost"

            with Session(engine) as reader:
                unreconciled = find_unreconciled_compensations(reader)
                assert execution_id in {a.execution_id for a in unreconciled}
                classified = {
                    r.compensation_attempt_id: r
                    for r in classify_compensation_recovery(reader)
                }
                rec = classified[uuid.UUID(binding.compensation_attempt_id)]
                assert (
                    rec.disposition
                    is CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                )
                assert rec.audit_decision is None
                assert (
                    rec.disposition
                    is not CompensationRecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
                )

            # A NAIVE retry (SAME original, NEW compensation execution_id) is
            # REJECTED by the reservation BEFORE the adapter is reached -> ZERO
            # automatic second reverse call.
            retry_binding = _pg_comp_binding(
                execution_id=retry_execution_id,
                original_execution_id=uuid.UUID(binding.original_execution_id),
            )
            with pytest.raises(IntegrityError):
                store.record(retry_binding)

            with Session(engine) as reader:
                rows = reader.scalars(
                    select(CompensationAttempt).where(
                        CompensationAttempt.original_execution_id
                        == uuid.UUID(binding.original_execution_id)
                    )
                ).all()
            assert len(rows) == 1
            assert rows[0].execution_id == execution_id
        finally:
            _cleanup(engine, execution_ids=[execution_id, retry_execution_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresCompensationTerminalSurvival:
    """req E — terminal-write failure / caller rollback survival + the positive
control (a committed agreeing terminal SETTLES the attempt as an AUDIT)."""

    def test_attempt_survives_caller_rollback_and_is_flagged(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_comp_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)  # durable pre-compensation commit
            caller = Session(engine)
            try:
                # the caller's terminal write lands in the caller's transaction ...
                caller.add(
                    ExecutionLog(
                        execution_id=execution_id,
                        approval_id=approval_id,
                        decision="compensation_succeeded",
                        direction="compensate",
                        action=binding.reverse_action,
                        target=binding.target,
                        operator="ops-1",
                        detail={
                            COMPENSATION_REFERENCE_KEY: binding.compensation_attempt_id
                        },
                        compensates_execution_id=uuid.UUID(
                            binding.original_execution_id
                        ),
                    )
                )
                caller.flush()
                caller.rollback()  # ... then the terminal write NEVER commits
            finally:
                caller.close()
            with Session(engine) as reader:
                # the durable attempt SURVIVED; no committed terminal -> UNKNOWN
                flagged = {
                    a.execution_id for a in find_unreconciled_compensations(reader)
                }
                assert execution_id in flagged
        finally:
            _cleanup(
                engine,
                execution_ids=[execution_id],
                approval_group_ids=[group_id],
            )
            engine.dispose()

    def test_committed_agreeing_terminal_settles_as_audit_only(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_comp_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)
            _comp_terminal_row(
                engine, binding, approval_id, "compensation_succeeded"
            )
            with Session(engine) as reader:
                assert find_unreconciled_compensations(reader) == []
                classified = {
                    r.compensation_attempt_id: r
                    for r in classify_compensation_recovery(reader)
                }
                rec = classified[uuid.UUID(binding.compensation_attempt_id)]
                assert (
                    rec.disposition
                    is CompensationRecoveryDisposition.TERMINAL_AUDIT_PRESENT
                )
                assert rec.audit_decision == "compensation_succeeded"
                # NEVER an external-effect confirmation (Outcome layer only).
                assert (
                    rec.disposition
                    is not CompensationRecoveryDisposition.EXTERNAL_EFFECT_CONFIRMED
                )
        finally:
            _cleanup(
                engine,
                execution_ids=[execution_id],
                approval_group_ids=[group_id],
            )
            engine.dispose()


@pytest.mark.external
class TestPostgresCompensationRestartRecovery:
    """req F — durability lives in the DATABASE, not the process: dispose the
engine, reopen a fresh one, and the committed compensation attempt is still
there and still unreconciled."""

    def test_orphan_attempt_survives_restart_and_is_recovered(self):
        engine = _pg_engine()
        binding = _pg_comp_binding()
        execution_id = uuid.UUID(binding.execution_id)
        pg_url = engine.url  # the URL OBJECT (carries the credentials) for the reopen
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)
            engine.dispose()  # process "restart"
            fresh = create_engine(pg_url)
            try:
                with Session(fresh) as reader:
                    flagged = {
                        a.execution_id
                        for a in find_unreconciled_compensations(reader)
                    }
                    assert execution_id in flagged
                    classified = {
                        r.compensation_attempt_id: r
                        for r in classify_compensation_recovery(reader)
                    }
                    rec = classified[uuid.UUID(binding.compensation_attempt_id)]
                    assert (
                        rec.disposition
                        is CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
                    )
            finally:
                fresh.dispose()
        finally:
            engine = create_engine(pg_url)
            _cleanup(engine, execution_ids=[execution_id])
            engine.dispose()


@pytest.mark.external
class TestPostgresCompensationCorrelation:
    """req G — a WRONG-attempt-reference / cross-execution terminal does NOT
settle the pending compensation attempt (correlation requires ALL immutable
facts to agree)."""

    def test_wrong_reference_does_not_mask_the_pending_attempt(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_comp_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)
            # a terminal that REFERENCES a DIFFERENT compensation_attempt_id
            _comp_terminal_row(
                engine,
                binding,
                approval_id,
                "compensation_succeeded",
                reference=str(uuid.uuid4()),
            )
            with Session(engine) as reader:
                flagged = {
                    a.execution_id for a in find_unreconciled_compensations(reader)
                }
                assert execution_id in flagged
        finally:
            _cleanup(
                engine,
                execution_ids=[execution_id],
                approval_group_ids=[group_id],
            )
            engine.dispose()

    def test_cross_execution_terminal_does_not_settle(self):
        engine = _pg_engine()
        approval_id, group_id = _seed_approval_chain(engine)
        binding = _pg_comp_binding(approval_id=approval_id)
        execution_id = uuid.UUID(binding.execution_id)
        foreign = _pg_comp_binding(approval_id=approval_id)
        foreign_execution_id = uuid.UUID(foreign.execution_id)
        try:
            store = DurableCompensationAttemptStore(engine)
            store.record(binding)
            # a terminal in a DIFFERENT execution that merely references this
            # attempt's id cannot settle it.
            with Session(engine) as session:
                session.add(
                    ExecutionLog(
                        execution_id=foreign_execution_id,
                        approval_id=approval_id,
                        decision="compensation_succeeded",
                        direction="compensate",
                        action=binding.reverse_action,
                        target=binding.target,
                        operator="ops-1",
                        detail={
                            COMPENSATION_REFERENCE_KEY: binding.compensation_attempt_id
                        },
                        compensates_execution_id=uuid.UUID(
                            foreign.original_execution_id
                        ),
                    )
                )
                session.commit()
            with Session(engine) as reader:
                flagged = {
                    a.execution_id for a in find_unreconciled_compensations(reader)
                }
                assert execution_id in flagged
        finally:
            _cleanup(
                engine,
                execution_ids=[execution_id, foreign_execution_id],
                approval_group_ids=[group_id],
            )
            engine.dispose()
