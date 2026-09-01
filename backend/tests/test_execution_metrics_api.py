"""Phase 3.3.3.2: Metrics API — the read model exposed as a read-only
audit view:

    GET /api/v1/executions/metrics
        -> collect_execution_metrics -> execution_log -> numbers

Locks the acceptance gate:

- 200 on the empty dataset, rates serialized as JSON null (frozen None
  semantics — never a fake 0% / 100%)
- 200 on the canonical mixed workload: every number field-for-field
  identical to the read model (body mirrors the frozen dataclasses)
- adapter distribution / failure classifications / latency surfaced
- in-flight chains count toward totals only, never toward denominators
- GET requires NO token (read ≠ execute), auth headers are irrelevant
- GET writes NOTHING: execution_log row count and content identical
  before and after any number of calls (the read-only nail)
- the route is registered BEFORE the parameterized execution-id route
  ("metrics" can never be captured as an execution id)
- the endpoint signature carries no executor and no auth dependency —
  re-execution is structurally impossible here

No health probe, no outbound traffic, no Prometheus/OTel, no React.
"""
import inspect
import uuid
from typing import get_type_hints

import pytest
from sqlalchemy import select

from app.api.v1 import response_execution as api_module
from app.models.execution_log import ExecutionLog
from app.services.executions.metrics import collect_execution_metrics
from tests.test_execution_service import seed_approved
from tests.test_execution_metrics import seed_mix

METRICS = "/api/v1/executions/metrics"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def log_snapshot(db_session):
    """Full content fingerprint of execution_log — rows AND values."""
    rows = db_session.scalars(select(ExecutionLog)).all()
    return sorted(
        (str(row.id), row.decision, row.direction, str(row.created_at))
        for row in rows
    )


def add_in_flight_chain(db_session):
    """One chain stuck at requested (never dispatched) — an in-flight
    fact the read model may count toward totals only."""
    approval = seed_approved(db_session)
    db_session.add(
        ExecutionLog(
            execution_id=uuid.uuid4(),
            approval_id=approval.id,
            decision="requested",
            direction="execute",
            action="block_source_ip",
            target="203.0.113.7",
            operator="ops-metrics-api",
            detail={"executor": "mock"},
        )
    )
    db_session.flush()


# --------------------------------------------------------------------------
# 1. Empty dataset: 200 + explicit JSON nulls
# --------------------------------------------------------------------------
class TestEmptyDataset:
    def test_empty_200_with_null_rates(self, client, db_session):
        response = client.get(METRICS)
        assert response.status_code == 200
        body = response.json()
        assert body["total_chains"] == 0
        assert body["executed_chains"] == 0
        assert body["succeeded"] == 0
        assert body["failed"] == 0
        assert body["guard_rejected"] == 0
        assert body["in_flight"] == 0
        # Frozen None semantics -> JSON null, never a fake percentage.
        assert body["success_rate"] is None
        assert body["executor_failure_rate"] is None
        assert body["guard_rejection_rate"] is None
        assert body["rejections_by_source"] == {}
        assert body["failure_classifications"] == {}
        assert body["by_adapter"] == {}
        assert body["latency"]["count"] == 0
        assert body["latency"]["average_seconds"] is None
        assert body["latency"]["min_seconds"] is None
        assert body["latency"]["max_seconds"] is None


# --------------------------------------------------------------------------
# 2. Normal data: the body is the read model, field for field
# --------------------------------------------------------------------------
class TestNormalData:
    def test_body_mirrors_read_model_exactly(self, client, db_session):
        seed_mix(db_session)
        expected = collect_execution_metrics(db_session)

        response = client.get(METRICS)
        assert response.status_code == 200
        body = response.json()

        assert body["total_chains"] == expected.total_chains == 10
        assert body["executed_chains"] == expected.executed_chains == 8
        assert body["succeeded"] == expected.succeeded == 3
        assert body["failed"] == expected.failed == 5
        assert body["guard_rejected"] == expected.guard_rejected == 2
        assert body["in_flight"] == expected.in_flight == 0
        assert body["success_rate"] == pytest.approx(expected.success_rate)
        assert body["success_rate"] == pytest.approx(3 / 8)
        assert body["executor_failure_rate"] == pytest.approx(5 / 8)
        assert body["guard_rejection_rate"] == pytest.approx(2 / 10)
        assert body["rejections_by_source"] == {"policy": 1, "guard": 1}
        assert body["failure_classifications"] == {
            "timeout": 3,
            "adapter_error": 1,
            "protocol_violation": 1,
        }

    def test_adapter_distribution(self, client, db_session):
        seed_mix(db_session)
        body = client.get(METRICS).json()
        # Adapter identity = server-recorded detail.executor; the keys
        # are exactly the adapters the chains really ran on.
        assert set(body["by_adapter"]) == {"mock", "stub-a", "bad-outcome"}
        mock = body["by_adapter"]["mock"]
        assert mock["total_chains"] == 5  # 3 succeeded + 2 rejections
        assert mock["succeeded"] == 3
        assert mock["failed"] == 0
        assert mock["guard_rejected"] == 2
        assert mock["success_rate"] == pytest.approx(1.0)
        stub_a = body["by_adapter"]["stub-a"]
        assert stub_a["total_chains"] == 4
        assert stub_a["failed"] == 4
        assert stub_a["success_rate"] == pytest.approx(0.0)
        assert stub_a["failure_classifications"] == {
            "timeout": 3,
            "adapter_error": 1,
        }

    def test_latency_surfaced(self, client, db_session):
        seed_mix(db_session)
        body = client.get(METRICS).json()
        latency = body["latency"]
        # Every terminal EXECUTOR chain has a dispatched row -> a span.
        assert latency["count"] == 8
        assert latency["min_seconds"] is not None
        assert latency["max_seconds"] is not None
        assert latency["average_seconds"] is not None
        assert latency["min_seconds"] <= latency["average_seconds"]
        assert latency["average_seconds"] <= latency["max_seconds"]


# --------------------------------------------------------------------------
# 3. In-flight chains never enter outcome denominators
# --------------------------------------------------------------------------
class TestInFlightSemantics:
    def test_in_flight_excluded_from_rates(self, client, db_session):
        seed_mix(db_session)
        add_in_flight_chain(db_session)
        body = client.get(METRICS).json()
        assert body["total_chains"] == 11
        assert body["in_flight"] == 1
        # Denominators unchanged: success is still 3/8, never 3/9.
        assert body["executed_chains"] == 8
        assert body["success_rate"] == pytest.approx(3 / 8)
        assert body["executor_failure_rate"] == pytest.approx(5 / 8)
        # Governance share is over ALL chains (in-flight included).
        assert body["guard_rejection_rate"] == pytest.approx(2 / 11)


# --------------------------------------------------------------------------
# 4. Read ≠ execute: no token, no writes — nailed by row counts
# --------------------------------------------------------------------------
class TestReadOnlyContract:
    def test_get_requires_no_token(self, client, db_session, monkeypatch):
        # No Authorization header AND nothing configured server-side —
        # the read path stays open (read ≠ execute).
        from app.core.config import settings

        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "")
        response = client.get(METRICS)
        assert response.status_code == 200

    def test_get_ignores_garbage_auth_header(self, client, db_session):
        # Authentication is simply not part of this route.
        response = client.get(
            METRICS, headers={"Authorization": "Bearer totally-wrong"}
        )
        assert response.status_code == 200

    def test_row_count_identical_before_and_after(self, client, db_session):
        """The read-only nail: GET creates/modifies/deletes NOTHING."""
        seed_mix(db_session)
        before_rows = len(list(db_session.scalars(select(ExecutionLog))))
        before = log_snapshot(db_session)

        # Any number of calls, all green, none writing.
        for _ in range(3):
            assert client.get(METRICS).status_code == 200

        after_rows = len(list(db_session.scalars(select(ExecutionLog))))
        after = log_snapshot(db_session)

        assert after_rows == before_rows
        assert after == before

    def test_get_never_reexecutes(self, client, db_session):
        """A metrics GET over a rejection-heavy log cannot flip any
        chain's derived outcome — terminal facts stay terminal."""
        seed_mix(db_session)
        before = collect_execution_metrics(db_session)
        client.get(METRICS)
        after = collect_execution_metrics(db_session)
        assert before == after


# --------------------------------------------------------------------------
# 5. Structural locks: route order + endpoint surface
# --------------------------------------------------------------------------
class TestStructuralLocks:
    def test_metrics_route_registered_before_param_route(self):
        paths = [route.path for route in api_module.router.routes]
        assert paths.index("/executions/metrics") < paths.index(
            "/executions/{execution_id}"
        )

    def test_endpoint_signature_has_no_executor_or_auth(self):
        signature = inspect.signature(api_module.execution_metrics)
        # Only the DB session — no executor dependency (re-execution is
        # structurally impossible), no auth dependency (read view).
        assert set(signature.parameters) == {"db"}
        hints = get_type_hints(api_module.execution_metrics)
        assert hints.get("return") is not None
