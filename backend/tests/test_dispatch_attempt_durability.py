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
from app.services.executions.binding import build_dispatch_binding
from app.services.executions.durable_dispatch import DurableDispatchAttemptStore


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
