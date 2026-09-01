"""Phase 3.3.3.3.2: Health API — the observed-health read model exposed
as a read-only audit view:

    GET /api/v1/executions/health
        -> collect_observed_health -> execution_log -> verdicts

Locks the acceptance gate:

- 200 empty (adapters={}), single & multi adapter shapes
- recent window semantics over HTTP (newest-20 basis)
- the four frozen verdicts reachable over HTTP: healthy / degraded /
  failing / unknown — the word stays ``observed_status``, never a
  boolean ``healthy`` flag
- recent_failures / last_execution / timeout / unavailable /
  protocol_violation surfaced
- guard_rejected floods never poison adapter health; in-flight chains
  stay out of the health window
- NO token, NO executor, NO credentials, ZERO external requests
- GET writes NOTHING (row count + content identical before/after)
- multi-GET consistency: response1 == response2 except generated_at
- response schema aligned field-for-field with the frozen read model
"""
import inspect
from dataclasses import fields as dc_fields

import pytest
from sqlalchemy import select

from app.api.v1 import response_execution as api_module
from app.models.execution_log import ExecutionLog
from app.schemas.response_execution import (
    AdapterHealthRead,
    ObservedHealthRead,
    RecentFailureRead,
)
from app.services.executions.health import (
    AdapterHealth,
    ObservedHealth,
    RecentFailure,
)
from tests.test_execution_health import SuccessStub, add_in_flight_chain
from tests.test_execution_metrics import DENY_POLICY, FailingStub, run_chain

HEALTH = "/api/v1/executions/health"


def log_snapshot(db_session):
    rows = db_session.scalars(select(ExecutionLog)).all()
    return sorted(
        (str(row.id), row.decision, row.direction, str(row.created_at))
        for row in rows
    )


# --------------------------------------------------------------------------
# 1. Shapes: empty / single / multi adapter
# --------------------------------------------------------------------------
class TestShapes:
    def test_empty_200_with_no_adapters(self, client):
        response = client.get(HEALTH)
        assert response.status_code == 200
        body = response.json()
        assert body["adapters"] == {}
        assert body["window_size"] == 20
        assert body["generated_at"] is not None

    def test_single_adapter(self, client, db_session):
        run_chain(db_session)
        body = client.get(HEALTH).json()
        assert set(body["adapters"]) == {"mock"}
        assert body["adapters"]["mock"]["observed_status"] == "healthy"

    def test_multi_adapter_independent_verdicts(self, client, db_session):
        run_chain(db_session)
        for _ in range(2):
            run_chain(db_session, FailingStub("timeout", name="probe-a"))
        body = client.get(HEALTH).json()
        assert set(body["adapters"]) == {"mock", "probe-a"}
        assert body["adapters"]["mock"]["observed_status"] == "healthy"
        assert body["adapters"]["probe-a"]["observed_status"] == "failing"


# --------------------------------------------------------------------------
# 2. The four frozen verdicts over HTTP + recent window
# --------------------------------------------------------------------------
class TestVerdictsOverHttp:
    def test_all_four_statuses_reachable(self, client, db_session):
        # healthy: mock all green
        run_chain(db_session)
        # degraded: probe-d 5 ok + 4 failed = 55.6%
        for _ in range(5):
            run_chain(db_session, SuccessStub("probe-d"))
        for _ in range(4):
            run_chain(db_session, FailingStub("adapter_error", name="probe-d"))
        # failing: probe-f 1 ok + 4 failed = 20%
        run_chain(db_session, SuccessStub("probe-f"))
        for _ in range(4):
            run_chain(db_session, FailingStub("timeout", name="probe-f"))
        # unknown: probe-u only ever saw a governance refusal — zero
        # terminal chains observed.
        run_chain(db_session, SuccessStub("probe-u"), policy=DENY_POLICY)
        body = client.get(HEALTH).json()
        statuses = {
            name: view["observed_status"]
            for name, view in body["adapters"].items()
        }
        assert statuses == {
            "mock": "healthy",
            "probe-d": "degraded",
            "probe-f": "failing",
            "probe-u": "unknown",
        }

    def test_unknown_status_for_refusal_only_adapter(self, client, db_session):
        """An adapter whose chains were ALL refused before dispatch has
        observed nothing — unknown, never healthy."""
        # DENY_POLICY refusal lands in the mock bucket (requested row
        # records detail.executor = mock): 2 refusals, 0 terminals.
        run_chain(db_session, policy=DENY_POLICY)
        run_chain(db_session, policy=DENY_POLICY)
        body = client.get(HEALTH).json()
        assert body["adapters"]["mock"]["observed_status"] == "unknown"
        assert body["adapters"]["mock"]["window_size"] == 0
        assert body["adapters"]["mock"]["window_success_rate"] is None

    def test_recent_window_over_http(self, client, db_session):
        # 3 early failures + 20 successes (same adapter): the default
        # 20-wide window holds only the newest successes -> healthy,
        # while all-time facts keep the failures visible.
        for _ in range(3):
            run_chain(db_session, FailingStub("timeout", name="probe-a"))
        for _ in range(20):
            run_chain(db_session, SuccessStub("probe-a"))
        view = client.get(HEALTH).json()["adapters"]["probe-a"]
        assert view["window_size"] == 20
        assert view["window_succeeded"] == 20
        assert view["window_failed"] == 0
        assert view["observed_status"] == "healthy"
        assert view["total_chains"] == 23
        assert view["all_time_failed"] == 3


# --------------------------------------------------------------------------
# 3. Classifications, recent_failures, last_execution
# --------------------------------------------------------------------------
class TestWindowFacts:
    def test_classification_counts_and_recent_failures(self, client, db_session):
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, FailingStub("adapter_unavailable", name="probe-a"))
        run_chain(db_session, SuccessStub("probe-a"))
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        view = client.get(HEALTH).json()["adapters"]["probe-a"]
        assert view["timeout_count"] == 2
        assert view["unavailable_count"] == 1
        assert view["protocol_violation_count"] == 0
        # Newest first.
        assert [f["classification"] for f in view["recent_failures"]] == [
            "timeout",
            "adapter_unavailable",
            "timeout",
        ]
        for failure in view["recent_failures"]:
            assert failure["execution_id"]
            assert failure["failed_at"]

    def test_last_execution_surfaces_any_outcome(self, client, db_session):
        run_chain(db_session)
        run_chain(db_session, FailingStub("timeout", name="mock"))
        view = client.get(HEALTH).json()["adapters"]["mock"]
        assert view["last_execution_state"] == "failed"
        assert view["last_execution_at"] is not None


# --------------------------------------------------------------------------
# 4. Governance / in-flight can never poison adapter health
# --------------------------------------------------------------------------
class TestAttributionLock:
    def test_guard_rejections_do_not_affect_health(self, client, db_session):
        run_chain(db_session)
        for _ in range(10):
            run_chain(db_session, policy=DENY_POLICY)
        for _ in range(10):
            run_chain(db_session, status="rejected")
        view = client.get(HEALTH).json()["adapters"]["mock"]
        assert view["observed_status"] == "healthy"
        assert view["window_failed"] == 0
        assert view["all_time_guard_rejected"] == 20

    def test_in_flight_excluded_from_health_window(self, client, db_session):
        run_chain(db_session)
        for _ in range(3):
            add_in_flight_chain(db_session)
        view = client.get(HEALTH).json()["adapters"]["mock"]
        assert view["observed_status"] == "healthy"
        assert view["window_size"] == 1
        assert view["all_time_in_flight"] == 3


# --------------------------------------------------------------------------
# 5. Read-only contract: no token / no writes / multi-GET consistency
# --------------------------------------------------------------------------
class TestReadOnlyContract:
    def test_no_token_required(self, client, db_session, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "")
        assert client.get(HEALTH).status_code == 200
        # Garbage auth headers are irrelevant on a read view.
        response = client.get(
            HEALTH, headers={"Authorization": "Bearer wrong"}
        )
        assert response.status_code == 200

    def test_row_count_and_content_unchanged(self, client, db_session):
        run_chain(db_session)
        run_chain(db_session, FailingStub("timeout"))
        before_rows = len(list(db_session.scalars(select(ExecutionLog))))
        before = log_snapshot(db_session)
        for _ in range(3):
            assert client.get(HEALTH).status_code == 200
        after_rows = len(list(db_session.scalars(select(ExecutionLog))))
        assert after_rows == before_rows
        assert log_snapshot(db_session) == before

    def test_multi_get_consistency_except_generated_at(self, client, db_session):
        run_chain(db_session)
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, policy=DENY_POLICY)
        first = client.get(HEALTH).json()
        second = client.get(HEALTH).json()
        # generated_at is the ONLY field allowed to differ.
        assert first["window_size"] == second["window_size"]
        assert first["adapters"] == second["adapters"]

    def test_endpoint_surface_and_route_order(self):
        # No executor, no auth — re-execution/probes are structurally
        # impossible on this route.
        signature = inspect.signature(api_module.execution_health)
        assert set(signature.parameters) == {"db"}
        paths = [route.path for route in api_module.router.routes]
        assert paths.index("/executions/health") < paths.index(
            "/executions/{execution_id}"
        )


# --------------------------------------------------------------------------
# 6. Schema alignment: Read mirrors == frozen read model, field for field
# --------------------------------------------------------------------------
class TestSchemaAlignment:
    def test_mirrors_match_dataclass_fields_exactly(self):
        assert set(ObservedHealthRead.model_fields) == {
            f.name for f in dc_fields(ObservedHealth)
        }
        assert set(AdapterHealthRead.model_fields) == {
            f.name for f in dc_fields(AdapterHealth)
        }
        assert set(RecentFailureRead.model_fields) == {
            f.name for f in dc_fields(RecentFailure)
        }

    def test_no_boolean_healthy_field_in_response_schema(self):
        assert "healthy" not in AdapterHealthRead.model_fields
        assert "is_healthy" not in AdapterHealthRead.model_fields
        assert "observed_status" in AdapterHealthRead.model_fields
