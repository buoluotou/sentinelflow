"""Phase 3.3.3.5: Cross-layer regression — the whole observability
chain proven together, end to end:

    Operator -> RBAC -> Approval -> Guard -> Policy -> Executor
    -> ExecutionLog -> Metrics Read Model / Health Read Model
    -> GET /executions/metrics / GET /executions/health

This suite does NOT re-test pure read-model logic (3.3.3.1 / 3.3.3.3.1),
the API mirrors (3.3.3.2 / 3.3.3.3.2) or the React layer (3.3.3.4).
Every journey drives the REAL production chain — real HTTP API, real
operator auth, real Guard + policy_from_settings, real adapters (Mock
registry-produced; Shuffle / Wazuh / TheHive over their frozen offline
transport seam) — and then proves the two read models and their GET
endpoints agree with the stored facts.

Journeys (acceptance gate):
1. Successful execution -> metrics succeeded +1, health window updates
2. Adapter failure: timeout / adapter_unavailable / adapter_error /
   protocol_violation all land in the ADAPTER failure statistics
3. Governance flood: 1 succeeded + 20 guard_rejected -> adapter stays
   observed healthy while guard_rejection_rate moves independently —
   the most important cross-layer check of 3.3.3
4. In-flight chains count toward totals only — never toward
   success_rate or the health window denominator
5. Multi-adapter: mock / shuffle / wazuh / thehive land in their own
   buckets, no cross-bucket bleed
6. Empty state: success_rate = null, adapters = {} (UI: N/A /
   "No adapter observations")
7. Read-only invariance: executions may append facts, but GETting
   metrics/health changes NOTHING (execution_log + Phase 2 world
   byte-identical before/after, zero executor calls)
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.api.v1.response_execution import get_response_executor
from app.core.config import settings
from app.models import ExecutionLog
from app.services.executions import service as service_module
from app.services.executions.health import collect_observed_health
from app.services.executions.metrics import collect_execution_metrics
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.shuffle import ShuffleExecutor
from app.services.executions.thehive import TheHiveExecutor
from app.services.executions.wazuh import WazuhExecutor
from tests.test_execution_metrics import FailingStub
from tests.test_execution_policy_cross_layer import (
    EXECUTE,
    OPERATORS_JSON,
    StubTransport,
    assert_world_unchanged,
    close_window,
    execute_body,
    policy_on,  # noqa: F401  (fixture re-export for journey signatures)
    seed_world,
    world_snapshot,
)
from tests.test_execution_service import BadOutcomeExecutor

METRICS_URL = "/api/v1/executions/metrics"
HEALTH_URL = "/api/v1/executions/health"
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Deterministic server clock (Policy judges SERVER time only) — same
# frozen seam as 3.3.2.6.
# --------------------------------------------------------------------------
class _FrozenDatetime:
    fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        moment = cls.fixed
        return moment if tz is not None else moment.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def frozen_server_clock(monkeypatch):
    _FrozenDatetime.fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(service_module, "datetime", _FrozenDatetime)
    yield


@pytest.fixture()
def operator_auth(monkeypatch):
    """3.3.1 registry path: executor-role operator token."""
    monkeypatch.setattr(settings, "OPERATORS_JSON", OPERATORS_JSON)
    return {"Authorization": "Bearer tok-xlayer-exec"}


@pytest.fixture()
def app():
    from app.main import app as fastapi_app

    return fastapi_app


# --------------------------------------------------------------------------
# Shared probes: read models direct + over HTTP
# --------------------------------------------------------------------------
def get_metrics(client):
    response = client.get(METRICS_URL)
    assert response.status_code == 200
    return response.json()


def get_health(client):
    response = client.get(HEALTH_URL)
    assert response.status_code == 200
    return response.json()


def log_snapshot(db_session):
    """Byte-level fingerprint of the whole execution_log."""
    db_session.expire_all()
    rows = list(
        db_session.scalars(
            select(ExecutionLog).order_by(
                ExecutionLog.execution_id,
                ExecutionLog.created_at.asc(),
                ExecutionLog.id.asc(),
            )
        )
    )
    return [
        (
            str(row.execution_id),
            row.decision,
            row.direction,
            row.operator,
            row.created_at,
            json.dumps(row.detail, sort_keys=True, default=str),
        )
        for row in rows
    ]


def execute_ok(client, db_session, headers, **world_kwargs) -> dict:
    """One approved full-chain execution through the real HTTP API."""
    world = seed_world(db_session, **world_kwargs)
    response = client.post(EXECUTE, json=execute_body(world["approval"]), headers=headers)
    assert response.status_code == 201
    return response.json()


def add_in_flight_row(db_session, approval_id, decisions):
    """Crash-between-rows simulation (pattern frozen in 3.3.3.1): a
    chain that never reached a terminal outcome."""
    now = datetime.now(timezone.utc)
    execution_id = uuid.uuid4()
    for decision in decisions:
        db_session.add(
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval_id,
                decision=decision,
                direction="execute",
                action="block_source_ip",
                target="203.0.113.10",
                operator="ops-obs",
                detail={"executor": "mock"},
                created_at=now,
            )
        )
    db_session.commit()


# --------------------------------------------------------------------------
# 1. Successful execution -> Metrics/Health
# --------------------------------------------------------------------------
class TestSuccessJourney:
    def test_success_increments_metrics_and_updates_health_window(
        self, client, db_session, operator_auth, policy_on
    ):
        """approved -> execute -> succeeded -> metrics succeeded +1 and
        the mock adapter's health window tracks the fact — direct read
        models and both GET endpoints agree."""
        body = execute_ok(client, db_session, operator_auth)
        assert body["derived_state"] == "succeeded"

        metrics = collect_execution_metrics(db_session)
        assert metrics.succeeded == 1
        assert metrics.success_rate == pytest.approx(1.0)
        health = collect_observed_health(db_session, now=NOW)
        mock = health.adapters["mock"]
        assert mock.observed_status == "healthy"
        assert mock.window_succeeded == 1
        assert mock.window_failed == 0

        # +1 on the next success — the read model follows the log.
        execute_ok(client, db_session, operator_auth)
        over_http = get_metrics(client)
        assert over_http["succeeded"] == 2
        assert over_http["success_rate"] == pytest.approx(1.0)
        over_http_health = get_health(client)
        assert over_http_health["adapters"]["mock"]["observed_status"] == "healthy"
        assert over_http_health["adapters"]["mock"]["window_succeeded"] == 2


# --------------------------------------------------------------------------
# 2. Adapter failure -> all four classifications feed ADAPTER statistics
# --------------------------------------------------------------------------
class TestAdapterFailureClassifications:
    @pytest.mark.parametrize(
        ("classification", "counter"),
        [
            ("timeout", "timeout_count"),
            ("adapter_unavailable", "unavailable_count"),
            ("adapter_error", None),
        ],
    )
    def test_classification_lands_in_adapter_statistics(
        self, client, db_session, operator_auth, policy_on, app,
        classification, counter,
    ):
        world = seed_world(db_session)
        app.dependency_overrides[get_response_executor] = (
            lambda: FailingStub(classification, name="mock")
        )
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "failed"

        metrics = get_metrics(client)
        assert metrics["failed"] == 1
        assert metrics["failure_classifications"] == {classification: 1}
        assert metrics["by_adapter"]["mock"]["failed"] == 1
        assert metrics["by_adapter"]["mock"]["failure_classifications"] == {
            classification: 1
        }

        adapter = get_health(client)["adapters"]["mock"]
        assert adapter["observed_status"] == "failing"
        assert adapter["window_failed"] == 1
        if counter is not None:
            assert adapter[counter] == 1

    def test_protocol_violation_is_adapter_failure(
        self, client, db_session, operator_auth, policy_on, app
    ):
        """A rogue adapter outcome (forbidden word) is judged
        failed+protocol_violation by the platform and counted as an
        adapter failure in its own bucket."""
        world = seed_world(db_session)
        app.dependency_overrides[get_response_executor] = lambda: BadOutcomeExecutor()
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "failed"

        metrics = get_metrics(client)
        assert metrics["failure_classifications"] == {"protocol_violation": 1}
        assert metrics["by_adapter"]["bad-outcome"]["failed"] == 1
        adapter = get_health(client)["adapters"]["bad-outcome"]
        assert adapter["observed_status"] == "failing"
        assert adapter["protocol_violation_count"] == 1


# --------------------------------------------------------------------------
# 3. Governance flood never poisons adapter health (THE 3.3.3 check)
# --------------------------------------------------------------------------
class TestGovernanceAttributionCrossLayer:
    def test_one_success_plus_twenty_rejections_stays_healthy(
        self, client, db_session, operator_auth, policy_on, monkeypatch
    ):
        """1 succeeded + 20 policy refusals -> the adapter's observed
        status stays healthy (refusals never touched it) while the
        governance rate moves independently."""
        execute_ok(client, db_session, operator_auth)
        close_window(monkeypatch)
        for _ in range(20):
            world = seed_world(db_session)
            response = client.post(
                EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
            )
            assert response.status_code == 201
            assert response.json()["derived_state"] == "guard_rejected"

        metrics = get_metrics(client)
        assert metrics["total_chains"] == 21
        assert metrics["succeeded"] == 1
        assert metrics["guard_rejected"] == 20
        assert metrics["success_rate"] == pytest.approx(1.0)
        assert metrics["guard_rejection_rate"] == pytest.approx(20 / 21)
        assert metrics["rejections_by_source"] == {"policy": 20}
        # The refusals attribute to the same adapter as GOVERNANCE...
        assert metrics["by_adapter"]["mock"]["guard_rejected"] == 20
        assert metrics["by_adapter"]["mock"]["failed"] == 0

        # ...and must NOT flip the adapter verdict.
        adapter = get_health(client)["adapters"]["mock"]
        assert adapter["observed_status"] == "healthy"
        assert adapter["window_succeeded"] == 1
        assert adapter["window_failed"] == 0
        assert adapter["all_time_guard_rejected"] == 20


# --------------------------------------------------------------------------
# 4. In-flight chains: totals only, never outcome denominators
# --------------------------------------------------------------------------
class TestInFlightCrossLayer:
    def test_in_flight_in_totals_not_in_rates_or_window(
        self, client, db_session, operator_auth, policy_on, app
    ):
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.json()["derived_state"] == "succeeded"
        app.dependency_overrides[get_response_executor] = (
            lambda: FailingStub("timeout", name="mock")
        )
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.json()["derived_state"] == "failed"

        # Two crash-between-rows chains: requested-only and
        # requested+dispatched (pattern frozen in 3.3.3.1). Every chain
        # needs its OWN approval (approval_id uniqueness, D5).
        add_in_flight_row(
            db_session, seed_world(db_session)["approval"].id, ["requested"]
        )
        add_in_flight_row(
            db_session,
            seed_world(db_session)["approval"].id,
            ["requested", "dispatched"],
        )

        metrics = get_metrics(client)
        assert metrics["total_chains"] == 4
        assert metrics["in_flight"] == 2
        # Denominators see ONLY the terminal chains: 1/(1+1).
        assert metrics["success_rate"] == pytest.approx(0.5)
        assert metrics["executor_failure_rate"] == pytest.approx(0.5)

        adapter = get_health(client)["adapters"]["mock"]
        assert adapter["window_succeeded"] == 1
        assert adapter["window_failed"] == 1
        assert adapter["all_time_in_flight"] == 2
        # 50% window -> degraded band, in-flight never tilted it.
        assert adapter["observed_status"] == "degraded"


# --------------------------------------------------------------------------
# 5. Multi-adapter: own buckets, no cross-bleed
# --------------------------------------------------------------------------
class TestMultiAdapterBuckets:
    def test_four_adapters_land_in_their_own_buckets(
        self, client, db_session, operator_auth, policy_on, app
    ):
        # mock: registry-produced, zero seams.
        execute_ok(client, db_session, operator_auth)

        # shuffle over the frozen offline transport seam.
        shuffle_stub = StubTransport(payload={"success": True})
        app.dependency_overrides[get_response_executor] = lambda: ShuffleExecutor(
            AdapterCredentials(
                adapter="shuffle", base_url="http://stub", api_key="sh-secret"
            ),
            {"block_source_ip": "wf-block"},
            timeout=1.0,
            transport=shuffle_stub,
        )
        execute_ok(client, db_session, operator_auth)

        # wazuh.
        wazuh_stub = StubTransport(payload={"success": True, "command_id": "c-1"})
        app.dependency_overrides[get_response_executor] = lambda: WazuhExecutor(
            AdapterCredentials(
                adapter="wazuh", base_url="http://stub",
                username="wz-user", password="wz-secret",
            ),
            timeout=1.0,
            transport=wazuh_stub,
        )
        execute_ok(
            client, db_session, operator_auth,
            action="isolate_host", target="agent001",
        )

        # thehive.
        thehive_stub = StubTransport(payload={"case_id": "case-1"})
        app.dependency_overrides[get_response_executor] = lambda: TheHiveExecutor(
            AdapterCredentials(
                adapter="thehive", base_url="http://stub", api_key="th-secret"
            ),
            timeout=1.0,
            transport=thehive_stub,
        )
        execute_ok(
            client, db_session, operator_auth,
            action="escalate_to_incident", target="INC-2026-0142",
        )

        metrics = get_metrics(client)
        assert set(metrics["by_adapter"]) == {"mock", "shuffle", "wazuh", "thehive"}
        for name in ("mock", "shuffle", "wazuh", "thehive"):
            bucket = metrics["by_adapter"][name]
            assert bucket["total_chains"] == 1
            assert bucket["succeeded"] == 1
            assert bucket["failed"] == 0

        adapters = get_health(client)["adapters"]
        assert set(adapters) == {"mock", "shuffle", "wazuh", "thehive"}
        for name in ("mock", "shuffle", "wazuh", "thehive"):
            assert adapters[name]["observed_status"] == "healthy"
            assert adapters[name]["window_succeeded"] == 1

        # The offline seam saw exactly one outbound call per adapter.
        assert len(shuffle_stub.calls) == 1
        assert len(wazuh_stub.calls) == 1
        assert len(thehive_stub.calls) == 1


# --------------------------------------------------------------------------
# 6. Empty state
# --------------------------------------------------------------------------
class TestEmptyState:
    def test_empty_log_yields_null_rates_and_no_adapters(self, client):
        metrics = get_metrics(client)
        assert metrics["total_chains"] == 0
        assert metrics["success_rate"] is None
        assert metrics["executor_failure_rate"] is None
        assert metrics["guard_rejection_rate"] is None
        assert metrics["by_adapter"] == {}

        health = get_health(client)
        assert health["adapters"] == {}
        assert health["window_size"] >= 1


# --------------------------------------------------------------------------
# 7. Read-only invariance of the two GET endpoints
# --------------------------------------------------------------------------
class TestReadOnlyInvariance:
    def test_gets_change_nothing(self, client, db_session, operator_auth, policy_on, app):
        """Executions append facts (expected); GETting metrics/health
        then changes NOTHING: execution_log byte-identical, Phase 2
        world untouched, zero executor invocations."""
        world = seed_world(db_session)
        before_world = world_snapshot(db_session, world)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.json()["derived_state"] == "succeeded"
        assert_world_unchanged(db_session, world, before_world)

        # Canary executor: any executor call during a GET would trip.
        class _Tripwire:
            name = "tripwire"

            def supports(self, action):
                raise AssertionError("GET must never consult an executor")

            def supports_compensation(self, action):
                raise AssertionError("GET must never consult an executor")

            def execute(self, dispatch):
                raise AssertionError("GET must never execute")

            def compensate(self, dispatch):
                raise AssertionError("GET must never compensate")

        app.dependency_overrides[get_response_executor] = lambda: _Tripwire()

        before_log = log_snapshot(db_session)
        first_metrics = get_metrics(client)
        first_health = get_health(client)
        second_metrics = get_metrics(client)
        second_health = get_health(client)
        assert log_snapshot(db_session) == before_log
        assert_world_unchanged(db_session, world, before_world)

        # Multi-GET consistency (frozen 3.3.3.3.2): identical except the
        # generated_at stamp.
        assert first_metrics == second_metrics
        assert {
            k: v for k, v in first_health.items() if k != "generated_at"
        } == {k: v for k, v in second_health.items() if k != "generated_at"}
