"""M4-F §1/§2 — the durable pre-dispatch store is LIVE in the real dispatch API.

Cycle 1 proved the STORE commits durably on an independent connection; Cycle 2a
proved the SERVICE calls ``store.record()`` before ``executor.execute()``. This
cycle closes the loop at the HTTP boundary: ``POST /api/v1/executions`` must
actually INJECT a durable store, so the pre-dispatch guarantee is operative in the
live path (an unused parameter would be an inert fix — the reviewer's exact
concern that M4-A "cannot pass by only adding test names").

Three proofs:
- the endpoint resolves ``get_dispatch_attempt_store`` and passes it to the Service
  (a recorder store sees ``record()`` BEFORE the executor's ``execute()``);
- the DEFAULT provider binds a real ``DurableDispatchAttemptStore`` (production wires
  durability, not ``None``);
- a REAL file-backed store, injected through the endpoint, leaves a COMMITTED
  ``dispatch_attempt`` row readable on an independent connection after the request.

SQLite honesty (constraint 2): the caller's chain rides the in-memory ``StaticPool``
``db_session``; the durable store rides a SEPARATE file-backed engine, so its
independent commit is genuinely isolated (no shared-connection artifact). True
same-engine caller/store interleaving under a crash is PostgreSQL-MVCC semantics,
covered by an ``external``-marked test that stays DESELECTED — never faked green.
"""
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.api.v1.response_execution import (
    get_dispatch_attempt_store,
    get_response_executor,
)
from app.core.config import settings
from app.core.database import Base
from app.main import app
from app.models import DispatchAttempt
from app.services.executions.durable_dispatch import DurableDispatchAttemptStore
from app.services.executions.mock import MockExecutor
from tests.test_execution_service import seed_approved

EXECUTE = "/api/v1/executions"
TOKEN = "exec-secret-endpoint-durable-0001"


@pytest.fixture()
def auth(monkeypatch):
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def file_engine(tmp_path):
    """A FILE-backed engine (real, non-shared pool) for the durable store, so its
    independent commit is genuinely isolated from the in-memory caller session."""
    db_path = tmp_path / "endpoint_durable.db"
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


class _Recorder:
    """A durable-store double that logs ``record()`` order vs the executor's call."""

    def __init__(self, events):
        self._events = events
        self.recorded = []

    def record(self, binding):
        self._events.append("record")
        self.recorded.append(binding)


class _CountingMock(MockExecutor):
    """The REAL mock executor (zero outbound) that also counts ``execute()``."""

    def __init__(self, events):
        super().__init__()
        self._events = events
        self.calls = 0

    def execute(self, dispatch):
        self.calls += 1
        self._events.append("execute")
        return super().execute(dispatch)


def _post(client, approval, execution_id, auth):
    return client.post(
        EXECUTE,
        json={
            "execution_id": str(execution_id),
            "approval_id": str(approval.id),
            "operator": "ops-1",
        },
        headers=auth,
    )


class TestEndpointInjectsDurableStore:
    def test_endpoint_records_the_binding_before_the_external_request(
        self, client, db_session, auth
    ):
        approval = seed_approved(db_session)
        events = []
        recorder = _Recorder(events)
        executor = _CountingMock(events)
        app.dependency_overrides[get_dispatch_attempt_store] = lambda: recorder
        app.dependency_overrides[get_response_executor] = lambda: executor

        response = _post(client, approval, uuid.uuid4(), auth)

        assert response.status_code == 201
        # THE live-path guarantee: the endpoint injected the store, and it recorded
        # the binding BEFORE the executor's external call.
        assert len(recorder.recorded) == 1
        assert events.index("record") < events.index("execute")
        assert executor.calls == 1

    def test_default_provider_binds_a_real_store(self, db_session):
        # Production wiring: the default provider returns a REAL durable store (not
        # None), so the live endpoint commits the pre-dispatch binding.
        store = get_dispatch_attempt_store(db_session)
        assert isinstance(store, DurableDispatchAttemptStore)

    def test_a_real_store_commits_the_attempt_through_the_endpoint(
        self, client, db_session, auth, file_engine
    ):
        approval = seed_approved(db_session)
        store = DurableDispatchAttemptStore(file_engine)
        execution_id = uuid.uuid4()
        app.dependency_overrides[get_dispatch_attempt_store] = lambda: store

        response = _post(client, approval, execution_id, auth)

        assert response.status_code == 201
        assert response.json()["derived_state"] == "succeeded"
        # The attempt is COMMITTED on the independent file-backed engine — readable
        # on a brand-new connection, proving durability through the live API path.
        with Session(file_engine) as session:
            rows = session.scalars(select(DispatchAttempt)).all()
        assert len(rows) == 1
        assert rows[0].execution_id == execution_id
