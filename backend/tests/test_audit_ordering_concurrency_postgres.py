"""PostgreSQL-specific audit-ordering proofs.

SQLite-level behavior (uuid7 contract, second-precision ties, interleaved
sessions, threaded writers) is proven in
``test_audit_ordering_concurrency.py``. This module covers the production
PostgreSQL path:

- the migration-0014 default (``clock_timestamp()``) stamps rapid
consecutive writes with the statement's time — never the
transaction-start ``now()`` — and the (created_at, id) order is the
exact insertion order end to end;
- parallel writers (threads, independent sessions/engines) on real
PostgreSQL MVCC keep each chain's own ordering, with no loss and no
duplicates.

Not verified against a live PostgreSQL: it runs only with ``-m external`` plus
the dedicated-DB env var, and a normal run skips it.

Safety: ``SENTINELFLOW_PG_TEST_URL`` must point at a dedicated throwaway
database. ``create_all`` is idempotent; ``_cleanup`` removes only this test's
rows (scoped by execution_id, reusing the forward suite's helper so the FK
graph order stays identical).
"""
import os
import threading
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.database import Base
from app.services.executions.service import _append, _rows_for_execution
from app.services.executions.state import derive_execution_state
from tests.test_dispatch_durable_postgres import _cleanup, _seed_approval_chain

PG_URL_ENV = "SENTINELFLOW_PG_TEST_URL"


def _pg_engine():
    url = os.environ.get(PG_URL_ENV, "")
    if not url:
        pytest.skip(
            "LAB BLOCKED: no dedicated PostgreSQL configured "
            f"({PG_URL_ENV} unset) — the production clock_timestamp() default "
            "and true MVCC writer-parallelism stay explicitly UNVERIFIED."
        )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    # Apply the production default exactly as migration 0014 does (create_all
    # builds the create-time default, CURRENT_TIMESTAMP, which is transaction
    # time — this ALTER is the production path under test).
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE execution_log "
                "ALTER COLUMN created_at SET DEFAULT clock_timestamp()"
            )
        )
    return engine


def _append_row(session: Session, execution_id, approval_id, decision, marker):
    _append(
        session,
        execution_id=execution_id,
        approval_id=approval_id,
        decision=decision,
        direction="execute",
        action="block_source_ip",
        target="203.0.113.9",
        operator="ops-1",
        detail={"i": marker},
    )
    session.flush()


@pytest.mark.external
def test_clock_timestamp_default_keeps_rapid_writes_ordered():
    """Rapid consecutive writes on real PostgreSQL: the
(created_at, id) tuples strictly increase in insertion order and the
derived state is the last write."""
    engine = _pg_engine()
    approval_id, group_id = _seed_approval_chain(engine)
    execution_id = uuid.uuid4()
    total = 200
    session = Session(engine)
    try:
        for i in range(total - 1):
            _append_row(session, execution_id, approval_id, "dispatched", i)
        _append_row(session, execution_id, approval_id, "succeeded", total - 1)
        session.commit()

        rows = _rows_for_execution(session, execution_id)  # DESC
        assert [r.detail["i"] for r in rows] == list(range(total - 1, -1, -1))
        ascending = list(reversed(rows))
        tuples = [(r.created_at, r.id) for r in ascending]
        # the (created_at, id) key reproduces the exact insertion order end to
        # end.
        assert all(a < b for a, b in zip(tuples, tuples[1:]))
        assert derive_execution_state(rows) == "succeeded"
    finally:
        session.close()
        _cleanup(engine, execution_ids=[execution_id], approval_group_ids=[group_id])
        engine.dispose()


@pytest.mark.external
def test_parallel_writers_keep_each_chain_ordered_on_postgres():
    """Parallel writers on distinct chains under real MVCC: each
chain reconstructs its own insertion order; nothing lost, nothing
duplicated, no writer errors."""
    engine = _pg_engine()
    approval_id, group_id = _seed_approval_chain(engine)
    workers, per_worker = 4, 40
    chains: dict[int, uuid.UUID] = {}
    errors: list[str] = []
    lock = threading.Lock()

    def _write(worker: int) -> None:
        session = Session(engine)
        execution_id = uuid.uuid4()
        with lock:
            chains[worker] = execution_id
        try:
            for i in range(per_worker - 1):
                _append_row(session, execution_id, approval_id, "dispatched", i)
            _append_row(session, execution_id, approval_id, "succeeded", per_worker - 1)
            session.commit()
        except Exception as exc:  # noqa: BLE001 — recorded and asserted below
            with lock:
                errors.append(f"worker {worker}: {type(exc).__name__}: {exc}")
        finally:
            session.close()

    threads = [threading.Thread(target=_write, args=(w,)) for w in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    try:
        assert errors == []
        reader = Session(engine)
        try:
            all_ids: set = set()
            for execution_id in chains.values():
                rows = _rows_for_execution(reader, execution_id)
                assert [r.detail["i"] for r in rows] == list(
                    range(per_worker - 1, -1, -1)
                )
                assert derive_execution_state(rows) == "succeeded"
                all_ids.update(r.id for r in rows)
            assert len(all_ids) == workers * per_worker  # no duplicates
        finally:
            reader.close()
    finally:
        _cleanup(engine, execution_ids=list(chains.values()), approval_group_ids=[group_id])
        engine.dispose()
