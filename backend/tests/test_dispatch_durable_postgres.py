"""M4-F §2 — PostgreSQL-specific durable-dispatch integration (TRUE interleaving).

WHY THIS FILE EXISTS (constraint 2, verbatim): "如使用 SQLite 无法可靠模拟生产锁或
崩溃语义，必须补充 PostgreSQL 专项集成测试或明确保持对应能力未验证。不能以 SQLite
全绿宣称 PostgreSQL 事务与并发已认证。"

The store-level durability (independent-connection commit, rollback survival,
recovery) and the service/endpoint control flow are proven on FILE-backed SQLite in
``test_dispatch_attempt_durability.py`` / ``test_dispatch_durable_integration.py`` /
``test_dispatch_endpoint_durability.py``. But TWO capabilities CANNOT be certified on
SQLite and are therefore explicitly UNVERIFIED there:

1. TRUE caller/store INTERLEAVING — the caller holds an OPEN (uncommitted) write
   transaction WHILE the store commits the attempt on a SECOND connection. SQLite's
   lock is DATABASE-level: an open write on ANY table blocks a write on ANY other
   ("database is locked"), so the two connections can never overlap. PostgreSQL MVCC
   lets them proceed independently — the production semantics.
2. TRUE CONCURRENT REPLAY — two threads race ``store.record()`` on the SAME
   execution_id. SQLite serialises writers, so the unique-index contention is only
   provable deterministically (sequential duplicate), never as a real parallel race.

This module exercises BOTH against a REAL PostgreSQL. It is ``@pytest.mark.external``
(conftest DESELECTS it unless ``-m external``) AND guarded by a dedicated-DB env var,
so a normal ``pytest`` run NEVER touches a database and this SKIPS rather than faking
a result. It is the honest "PostgreSQL 专项集成测试" that keeps the SQLite suite from
over-claiming: until it is RUN against a real PostgreSQL, capabilities 1 and 2 stay
UNVERIFIED — they are NOT certified by the green SQLite run.

SAFETY: ``SENTINELFLOW_PG_TEST_URL`` MUST point at a DEDICATED throwaway PostgreSQL
(the test issues ``Base.metadata.create_all``); never a production/shared database.
"""
import os
import threading
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import DispatchAttempt
from app.services.executions.binding import build_dispatch_binding
from app.services.executions.durable_dispatch import (
    DurableDispatchAttemptStore,
    find_unreconciled_attempts,
)

#: The dedicated-DB env var. Unset -> SKIP (LAB BLOCKED), never a fabricated pass.
PG_URL_ENV = "SENTINELFLOW_PG_TEST_URL"


def _pg_binding(execution_id=None):
    """A deterministic pre-dispatch binding (server-side facts only)."""
    return build_dispatch_binding(
        execution_id=execution_id or uuid.uuid4(),
        approval_id=uuid.uuid4(),
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


@pytest.mark.external
class TestPostgresDurableInterleaving:
    """TRUE MVCC interleaving + concurrent replay on a REAL PostgreSQL — the two
    capabilities file-backed SQLite CANNOT certify (see the module docstring)."""

    @staticmethod
    def _engine():
        url = os.environ.get(PG_URL_ENV, "")
        if not url:
            pytest.skip(
                "LAB BLOCKED: no dedicated PostgreSQL configured "
                f"({PG_URL_ENV} unset) — the true caller/store interleaving + "
                "concurrent-replay MVCC semantics stay explicitly UNVERIFIED "
                "(constraint 2: SQLite's single-writer lock cannot certify them)."
            )
        engine = create_engine(url)
        Base.metadata.create_all(engine)
        return engine

    def test_open_caller_write_transaction_does_not_block_the_independent_commit(self):
        """The caller holds an OPEN write transaction WHILE the store commits the
        attempt on a SECOND connection, then the caller rolls its WHOLE transaction
        back. PostgreSQL MVCC: the independent commit SUCCEEDS and SURVIVES; the
        rolled-back caller row vanishes. (On SQLite this raises "database is locked"
        — the exact reason the capability is UNVERIFIABLE there.)"""
        engine = self._engine()
        try:
            store = DurableDispatchAttemptStore(engine)
            caller_binding = _pg_binding()  # execution_id A — the caller's open write
            store_binding = _pg_binding()  # execution_id B — the durable pre-dispatch
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
            # terminal -> recovery flags it as a MANUAL reconciliation candidate.
            with Session(engine) as reader:
                rows = reader.scalars(select(DispatchAttempt)).all()
                assert [r.execution_id for r in rows] == [
                    uuid.UUID(store_binding.execution_id)
                ]
                unreconciled = find_unreconciled_attempts(reader)
                assert [a.attempt_id for a in unreconciled] == [
                    uuid.UUID(store_binding.attempt_id)
                ]
        finally:
            engine.dispose()

    def test_concurrent_replay_commits_exactly_one_attempt(self):
        """Two threads race ``store.record()`` on the SAME execution_id: the unique
        index commits EXACTLY ONE and the loser raises ``IntegrityError`` (which the
        Service maps to the typed 409 with ZERO external calls — proven deterministically
        in ``test_dispatch_durable_integration.py``). This is the TRUE parallel race
        SQLite serialises away."""
        engine = self._engine()
        try:
            store = DurableDispatchAttemptStore(engine)
            execution_id = uuid.uuid4()
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
                rows = reader.scalars(select(DispatchAttempt)).all()
            # EXACTLY ONE durable attempt -> at most ONE external request proceeds.
            assert len(rows) == 1
            assert rows[0].execution_id == execution_id
        finally:
            engine.dispose()
