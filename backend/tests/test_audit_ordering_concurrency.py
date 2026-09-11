"""Audit ordering under concurrency (no process-global clock state).

An earlier implementation stamped rows from a process-global high-water mark
(``_LAST_AUDIT_STAMP``): not thread-safe (a read-modify-write race could give
two rows the same stamp) and per-process only, so the
``(created_at, id)`` tie-break degraded to a random-uuid lottery. Ordering now
comes from the database plus an insert-ordered uuid7 id:

- ``created_at`` is stamped by the database at INSERT (SQLite keeps
second-precision ``CURRENT_TIMESTAMP`` — the hardest tie case — while
PostgreSQL production uses ``clock_timestamp()``, migration 0014);
- ``id`` (``app.core.ids.uuid7``) is strictly increasing within the writing
process, so a ``created_at`` tie resolves to the true insertion order.

This module proves the local properties: the uuid7 contract itself, rapid
consecutive writes on the hardest (second-precision) dialect, interleaved
sessions, and parallel threads writing independent chains. Real-PostgreSQL
MVCC behavior lives in ``test_audit_ordering_concurrency_postgres.py``.
"""
import threading
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.core.ids as ids_module
from app.core.database import Base
from app.core.ids import uuid7
from app.services.executions.service import _append, _rows_for_execution
from app.services.executions.state import derive_execution_state

BASE_TIME = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def file_engine(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'audit-ordering.db'}",
        connect_args={"timeout": 30},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def _append_row(session: Session, execution_id, decision: str, marker: int) -> None:
    _append(
        session,
        execution_id=execution_id,
        approval_id=uuid.uuid4(),
        decision=decision,
        direction="execute",
        action="block_source_ip",
        target="203.0.113.9",
        operator="ops-1",
        detail={"i": marker},
    )
    session.flush()


def _assert_chain_ordered(session: Session, execution_id, expected: list[int]) -> None:
    rows = _rows_for_execution(session, execution_id)  # created_at DESC, id DESC
    assert [r.detail["i"] for r in rows] == list(reversed(expected))
    # non-decreasing timestamps and strictly increasing insert-ordered ids
    ascending = list(reversed(rows))
    stamps = [r.created_at for r in ascending]
    assert all(a <= b for a, b in zip(stamps, stamps[1:]))
    ids = [r.id for r in ascending]
    assert all(a < b for a, b in zip(ids, ids[1:]))


#
# The uuid7 contract itself
#
class TestUuid7Contract:
    def test_burst_is_strictly_increasing_and_well_formed(self):
        ids = [uuid7() for _ in range(10_000)]
        assert all(a < b for a, b in zip(ids, ids[1:]))
        assert all(one.version == 7 for one in ids)
        assert all(one.variant == uuid.RFC_4122 for one in ids)

    def test_clock_regression_is_clamped_not_reordered(self, monkeypatch):
        saved_last, saved_counter = ids_module._LAST_MS, ids_module._COUNTER
        try:
            fixed_ns = 1_800_000_000_000_000_000  # far-future value for the patched clock
            monkeypatch.setattr(ids_module.time, "time_ns", lambda: fixed_ns)
            first = uuid7()
            second = uuid7()
            # the wall clock steps backward by 5 seconds — the generator must
            # keep minting strictly greater ids (counter path, clamped ms)
            monkeypatch.setattr(
                ids_module.time, "time_ns", lambda: fixed_ns - 5_000_000_000
            )
            third = uuid7()
            assert first < second < third
        finally:
            ids_module._LAST_MS = saved_last
            ids_module._COUNTER = saved_counter


#
# Rapid consecutive writes on the hardest (second-precision) dialect
#
class TestRapidWrites:
    def test_insertion_order_survives_second_precision_ties(self, file_engine):
        """300 rows written in one burst: SQLite stamps them all with (at most)
one-second precision — the uuid7 tie-break alone must reconstruct the
exact insertion order."""
        session = Session(file_engine)
        execution_id = uuid.uuid4()
        total = 300
        try:
            for i in range(total - 1):
                _append_row(session, execution_id, "dispatched", i)
            _append_row(session, execution_id, "succeeded", total - 1)
            session.commit()

            _assert_chain_ordered(session, execution_id, list(range(total)))
            rows = _rows_for_execution(session, execution_id)
            assert derive_execution_state(rows) == "succeeded"
        finally:
            session.close()

    def test_no_duplicate_semantic_record_under_rapid_writes(self, file_engine):
        session = Session(file_engine)
        execution_id = uuid.uuid4()
        try:
            for i in range(150):
                _append_row(session, execution_id, "dispatched", i)
            session.commit()
            rows = _rows_for_execution(session, execution_id)
            assert len(rows) == 150                       # nothing lost
            assert len({r.id for r in rows}) == 150       # nothing duplicated
        finally:
            session.close()


#
# Interleaved sessions and parallel threads
#
class TestConcurrentWriters:
    def test_two_sessions_interleave_chains_without_cross_contamination(
        self, file_engine
    ):
        """Two sessions alternate write batches (each committing before the
other resumes — SQLite is single-writer by nature), interleaving two
chains: each chain must still reconstruct its own order."""
        first, second = Session(file_engine), Session(file_engine)
        chain_a, chain_b = uuid.uuid4(), uuid.uuid4()
        expected_a, expected_b = [], []
        try:
            for round_index in range(4):
                for i in range(5):
                    marker = round_index * 5 + i
                    _append_row(first, chain_a, "dispatched", marker)
                    expected_a.append(marker)
                first.commit()
                for i in range(5):
                    marker = 1000 + round_index * 5 + i
                    _append_row(second, chain_b, "dispatched", marker)
                    expected_b.append(marker)
                second.commit()
            _append_row(first, chain_a, "succeeded", 999)
            expected_a.append(999)
            first.commit()
            _append_row(second, chain_b, "succeeded", 1999)
            expected_b.append(1999)
            second.commit()

            _assert_chain_ordered(first, chain_a, expected_a)
            _assert_chain_ordered(second, chain_b, expected_b)
        finally:
            first.close()
            second.close()

    def test_threaded_writers_keep_each_chain_ordered(self, file_engine):
        """Multiple threads (the multi-session / multi-worker-equivalent shape)
write independent chains in parallel: every chain must reconstruct its
own insertion order, with no loss and no duplicates across writers."""
        threads_count, per_thread = 3, 25
        chains: dict[int, uuid.UUID] = {}
        errors: list[str] = []
        lock = threading.Lock()

        def _write(worker: int) -> None:
            session = Session(file_engine)
            execution_id = uuid.uuid4()
            with lock:
                chains[worker] = execution_id
            try:
                for i in range(per_thread - 1):
                    _append_row(session, execution_id, "dispatched", i)
                _append_row(session, execution_id, "succeeded", per_thread - 1)
                session.commit()
            except Exception as exc:  # noqa: BLE001 — recorded and asserted
                with lock:
                    errors.append(f"worker {worker}: {type(exc).__name__}: {exc}")
            finally:
                session.close()

        threads = [
            threading.Thread(target=_write, args=(w,)) for w in range(threads_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        reader = Session(file_engine)
        try:
            all_ids: set = set()
            for worker, execution_id in chains.items():
                expected = list(range(per_thread))
                rows = _rows_for_execution(reader, execution_id)
                assert [r.detail["i"] for r in rows] == list(reversed(expected))
                assert derive_execution_state(rows) == "succeeded"
                all_ids.update(r.id for r in rows)
            assert len(all_ids) == threads_count * per_thread  # no duplicates
        finally:
            reader.close()
