"""Phase 3.3.3.1: Metrics read model tests — execution_log is the ONLY
fact source.

Locks the acceptance gate:

- pure read / deterministic / no DB write (source-level locks too)
- execution_log is the sole source: every number derived from REAL
  service-produced chains (no hand-written facts for the main paths)
- guard_rejected counted SEPARATELY from adapter outcomes
- frozen rate definitions:
    success_rate          = succeeded / (succeeded + failed)
    guard_rejection_rate  = guard_rejected / total chains
- failure classifications reuse the frozen vocabulary only
- per-adapter statistics derived from detail.executor (server fact —
  no client-controllable metric field exists)
- empty dataset explicit (rates None, never fake percentages)
- compensation rows and in-flight chains never pollute outcome rates
"""
import ast
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.execution_log import ExecutionLog
from app.services.executions.metrics import (
    UNKNOWN_ADAPTER,
    AdapterMetrics,
    ExecutionMetrics,
    LatencyStats,
    collect_execution_metrics,
)
from app.services.executions.mock import MockExecutor
from app.services.executions.policy import ExecutionPolicy
from app.services.executions.service import execute_response
from tests.test_execution_service import BadOutcomeExecutor, seed_approved

METRICS_SOURCE = (
    Path(__file__).parent.parent / "app" / "services" / "executions" / "metrics.py"
)


# --------------------------------------------------------------------------
# Chain production — REAL service runs, no hand-written rows
# --------------------------------------------------------------------------
class FailingStub:
    """Deterministic adapter failure with a chosen frozen classification."""

    def __init__(self, classification: str, name: str = "stub-fail"):
        self.name = name
        self._classification = classification

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return True

    def execute(self, dispatch):
        return {
            "status": "failed",
            "detail": {"classification": self._classification, "message": "stub"},
            "raw_response": {"stub": True},
        }

    def compensate(self, dispatch):
        raise AssertionError("compensate must never be reached")


#: Policy whose risk threshold can never be met by a seed without an
#: EventRisk row — drives a source="policy" refusal deterministically.
DENY_POLICY = ExecutionPolicy(
    enabled=True, min_risk_by_action={"block_source_ip": 99}
)


def run_chain(
    db_session,
    executor=None,
    *,
    policy=None,
    status="approved",
):
    approval = seed_approved(db_session, status=status)
    kwargs = dict(
        approval_id=approval.id,
        execution_id=uuid.uuid4(),
        operator="ops-metrics",
        executor=executor or MockExecutor(),
    )
    if policy is not None:
        kwargs["policy"] = policy
    return execute_response(db_session, **kwargs)


def seed_mix(db_session):
    """The canonical mixed workload:
    3 succeeded (mock)
    3 failed timeout (stub-a) + 1 failed adapter_error (stub-a)
      + 1 failed protocol_violation (bad-outcome, rogue outcome)
    1 guard_rejected source=policy (mock) + 1 source=guard (mock)
    => total 10, executed 8, succeeded 3, failed 5, guard_rejected 2."""
    for _ in range(3):
        run_chain(db_session)
    for _ in range(3):
        run_chain(db_session, FailingStub("timeout", name="stub-a"))
    run_chain(db_session, FailingStub("adapter_error", name="stub-a"))
    run_chain(db_session, BadOutcomeExecutor())  # protocol_violation
    run_chain(db_session, policy=DENY_POLICY)  # source=policy
    run_chain(db_session, status="rejected")  # source=guard


# --------------------------------------------------------------------------
# 1. Frozen rate definitions on the canonical mix
# --------------------------------------------------------------------------
class TestFrozenRateDefinitions:
    def test_canonical_mix_numbers(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        assert metrics.total_chains == 10
        assert metrics.executed_chains == 8
        assert metrics.succeeded == 3
        assert metrics.failed == 5
        assert metrics.guard_rejected == 2
        assert metrics.in_flight == 0
        # success_rate = succeeded / (succeeded + failed) = 3/8 —
        # guard_rejected never touched the Executor and stays OUT.
        assert metrics.success_rate == pytest.approx(3 / 8)
        assert metrics.executor_failure_rate == pytest.approx(5 / 8)
        # guard_rejection_rate = governance share over ALL chains.
        assert metrics.guard_rejection_rate == pytest.approx(2 / 10)

    def test_rejections_split_by_provenance(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        assert dict(metrics.rejections_by_source) == {"policy": 1, "guard": 1}

    def test_failure_classifications_reuse_frozen_vocabulary(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        assert dict(metrics.failure_classifications) == {
            "timeout": 3,
            "adapter_error": 1,
            "protocol_violation": 1,
        }

        # No invented words ever appear.
        assert set(metrics.failure_classifications) <= {
            "adapter_unavailable",
            "timeout",
            "adapter_error",
            "protocol_violation",
        }

    def test_latency_derived_from_created_at_only(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        # Exactly the chains with a terminal executor outcome were
        # dispatched — guard refusals have no adapter time.
        assert metrics.latency.count == 8
        assert metrics.latency.average_seconds is not None
        assert metrics.latency.min_seconds >= 0.0
        assert metrics.latency.min_seconds <= metrics.latency.max_seconds


# --------------------------------------------------------------------------
# 2. Per-adapter statistics (adapter = server-recorded fact)
# --------------------------------------------------------------------------
class TestPerAdapterStatistics:
    def test_adapters_split_by_recorded_executor(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        assert set(metrics.by_adapter) == {"mock", "stub-a", "bad-outcome"}
        mock = metrics.by_adapter["mock"]
        stub = metrics.by_adapter["stub-a"]
        rogue = metrics.by_adapter["bad-outcome"]
        assert (mock.succeeded, mock.failed, mock.guard_rejected) == (3, 0, 2)
        assert mock.total_chains == 5
        assert mock.success_rate == pytest.approx(1.0)
        assert (stub.succeeded, stub.failed, stub.guard_rejected) == (0, 4, 0)
        assert stub.success_rate == pytest.approx(0.0)
        assert (rogue.succeeded, rogue.failed) == (0, 1)
        assert dict(mock.failure_classifications) == {}
        assert dict(stub.failure_classifications) == {
            "timeout": 3,
            "adapter_error": 1,
        }
        assert dict(rogue.failure_classifications) == {"protocol_violation": 1}

    def test_adapter_identity_never_comes_from_client(self, db_session):
        """Every chain lands detail.executor from the SERVER-selected
        adapter; the read model groups exclusively on that fact. There
        is no client field named adapter anywhere in the surface."""
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        assert UNKNOWN_ADAPTER not in metrics.by_adapter
        rows = db_session.scalars(
            select(ExecutionLog).where(ExecutionLog.decision == "requested")
        ).all()
        recorded = {row.detail["executor"] for row in rows}
        assert recorded == set(metrics.by_adapter)


# --------------------------------------------------------------------------
# 3. Empty dataset + boundary semantics
# --------------------------------------------------------------------------
class TestEmptyAndBoundary:
    def test_empty_dataset_is_explicit(self, db_session):
        metrics = collect_execution_metrics(db_session)
        assert metrics == ExecutionMetrics()
        assert metrics.total_chains == 0
        # Undefined rates are None — never a fake 0% or 100%.
        assert metrics.success_rate is None
        assert metrics.executor_failure_rate is None
        assert metrics.guard_rejection_rate is None
        assert metrics.latency == LatencyStats()
        assert dict(metrics.by_adapter) == {}

    def test_guard_rejection_only_dataset(self, db_session):
        run_chain(db_session, policy=DENY_POLICY)
        metrics = collect_execution_metrics(db_session)
        assert metrics.executed_chains == 0
        assert metrics.success_rate is None  # nothing reached an adapter
        assert metrics.guard_rejection_rate == pytest.approx(1.0)

    def test_all_succeeded_dataset(self, db_session):
        for _ in range(3):
            run_chain(db_session)
        metrics = collect_execution_metrics(db_session)
        assert metrics.success_rate == pytest.approx(1.0)
        assert metrics.executor_failure_rate == pytest.approx(0.0)
        assert metrics.guard_rejection_rate == pytest.approx(0.0)

    def test_compensation_rows_never_pollute_metrics(self, db_session):
        from app.services.executions.service import compensate_response

        result = run_chain(db_session)
        before = collect_execution_metrics(db_session)
        compensate_response(
            db_session,
            compensates_execution_id=result.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-metrics",
            executor=MockExecutor(),
        )
        after = collect_execution_metrics(db_session)
        assert after == before  # compensate is another direction

    def test_in_flight_chains_count_toward_totals_only(self, db_session):
        """A lone requested row (crash between rows) is in flight: it
        counts toward totals and the rejection-free denominator, never
        toward the outcome rates."""
        run_chain(db_session)
        now = datetime.now(timezone.utc)
        db_session.add(
            ExecutionLog(
                execution_id=uuid.uuid4(),
                approval_id=seed_approved(db_session).id,
                decision="requested",
                direction="execute",
                action="block_source_ip",
                target="203.0.113.10",
                operator="ops-metrics",
                detail={"executor": "mock"},
                created_at=now,
            )
        )
        db_session.flush()
        metrics = collect_execution_metrics(db_session)
        assert metrics.total_chains == 2
        assert metrics.in_flight == 1
        assert metrics.succeeded == 1
        assert metrics.success_rate == pytest.approx(1.0)

    def test_foreign_classification_is_counted_nowhere(self, db_session):
        """The classification vocabulary is CLOSED: a failed row whose
        detail carries an invented word feeds no counter."""
        run_chain(db_session)
        execution_id = uuid.uuid4()
        approval = seed_approved(db_session)
        base = datetime.now(timezone.utc)
        for index, (decision, detail) in enumerate(
            [
                ("requested", {"executor": "mock"}),
                ("dispatched", {"executor": "mock"}),
                (
                    "failed",
                    {"classification": "metrics_error", "raw_response": None},
                ),
            ]
        ):
            db_session.add(
                ExecutionLog(
                    execution_id=execution_id,
                    approval_id=approval.id,
                    decision=decision,
                    direction="execute",
                    action="block_source_ip",
                    target="203.0.113.10",
                    operator="ops-metrics",
                    detail=detail,
                    created_at=base + timedelta(microseconds=index),
                )
            )
        db_session.flush()
        metrics = collect_execution_metrics(db_session)
        assert metrics.failed == 1  # only the synthetic chain failed
        # ...but the foreign word appears in NO classification counter.
        assert dict(metrics.failure_classifications) == {}
        assert metrics.by_adapter["mock"].failed == 1
        assert dict(metrics.by_adapter["mock"].failure_classifications) == {}


# --------------------------------------------------------------------------
# 4. Purity locks: read-only, deterministic, no writes
# --------------------------------------------------------------------------
class TestPurityLocks:
    def test_collection_changes_nothing(self, db_session):
        seed_mix(db_session)
        rows_before = db_session.scalars(select(ExecutionLog)).all()
        snapshot = [
            (row.id, row.decision, row.direction, dict(row.detail), row.created_at)
            for row in rows_before
        ]
        collect_execution_metrics(db_session)
        collect_execution_metrics(db_session)
        rows_after = db_session.scalars(select(ExecutionLog)).all()
        assert [
            (row.id, row.decision, row.direction, dict(row.detail), row.created_at)
            for row in rows_after
        ] == snapshot

    def test_deterministic_across_calls(self, db_session):
        seed_mix(db_session)
        assert collect_execution_metrics(db_session) == collect_execution_metrics(
            db_session
        )

    def test_source_has_no_write_calls(self):
        source = METRICS_SOURCE.read_text(encoding="utf-8")
        for marker in (".add(", ".flush(", ".commit(", ".rollback("):
            assert marker not in source, marker

    def test_source_never_imports_executors(self):
        """The read model observes facts; it must never reach an
        adapter (no outbound surface, no executor coupling)."""
        tree = ast.parse(METRICS_SOURCE.read_text(encoding="utf-8"))
        forbidden = {
            "app.services.executions.mock",
            "app.services.executions.shuffle",
            "app.services.executions.wazuh",
            "app.services.executions.thehive",
            "app.services.executions.base",
            "app.services.executions.registry",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden
                assert "executor" not in (node.module or "").lower()

    def test_result_objects_are_frozen(self, db_session):
        seed_mix(db_session)
        metrics = collect_execution_metrics(db_session)
        with pytest.raises(Exception):
            metrics.succeeded = 999  # type: ignore[misc]
        adapter = metrics.by_adapter["mock"]
        assert isinstance(adapter, AdapterMetrics)
        with pytest.raises(Exception):
            adapter.failed = 999  # type: ignore[misc]
