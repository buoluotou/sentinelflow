"""Phase 3.3.3.3.1: Observed-Health read model tests — health is what
the execution facts SHOW, never a live probe.

Locks the frozen adjudications:

- vocabulary OBSERVED_STATUSES = {healthy, degraded, failing, unknown};
  NO boolean ``healthy`` field (would be misread as a live probe)
- judgement rule over the recent-N terminal window (default N=20):
    unknown  = zero terminal chains observed
    healthy  = success_rate >= 0.9
    degraded = success_rate >= 0.5
    failing  = success_rate <  0.5
- window basis: ONLY terminal executor chains (succeeded / failed);
  guard_rejected chains — no matter how many — can NEVER make an
  adapter unhealthy (governance pressure is never misattributed to an
  external system); in-flight chains excluded the same way
- pure read / deterministic / execution_log untouched / zero outbound
  traffic (no probe exists by design)

Chain production reuses the REAL service runs from the metrics suite.
"""
import ast
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.execution_log import ExecutionLog
from app.services.executions.health import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WINDOW_SIZE,
    OBSERVED_STATUSES,
    AdapterHealth,
    HealthThresholds,
    ObservedHealth,
    collect_observed_health,
)
from tests.test_execution_metrics import FailingStub, run_chain, DENY_POLICY
from tests.test_execution_service import seed_approved


class SuccessStub:
    """Deterministic adapter success under a chosen name — lets one
    adapter bucket mix successes and failures."""

    def __init__(self, name: str):
        self.name = name

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return True

    def execute(self, dispatch):
        return {
            "status": "succeeded",
            "detail": {"message": "ok"},
            "raw_response": {"ok": True},
        }

    def compensate(self, dispatch):
        raise AssertionError("compensate must never be reached")

HEALTH_SOURCE = (
    Path(__file__).parent.parent / "app" / "services" / "executions" / "health.py"
)

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def health(db_session, **kwargs):
    kwargs.setdefault("now", NOW)
    return collect_observed_health(db_session, **kwargs)


def add_in_flight_chain(db_session):
    """One chain stuck at requested (same shape as the metrics API
    suite) — an in-flight fact with no outcome yet."""
    approval = seed_approved(db_session)
    db_session.add(
        ExecutionLog(
            execution_id=uuid.uuid4(),
            approval_id=approval.id,
            decision="requested",
            direction="execute",
            action="block_source_ip",
            target="203.0.113.7",
            operator="ops-health",
            detail={"executor": "mock"},
        )
    )
    db_session.flush()


# --------------------------------------------------------------------------
# 1. Frozen vocabulary + field discipline
# --------------------------------------------------------------------------
class TestFrozenVocabulary:
    def test_vocabulary_is_exactly_the_four_frozen_words(self):
        assert OBSERVED_STATUSES == {"healthy", "degraded", "failing", "unknown"}

    def test_every_observed_status_is_in_the_vocabulary(self, db_session):
        for _ in range(2):
            run_chain(db_session)
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        snapshot = health(db_session)
        for adapter_health in snapshot.adapters.values():
            assert adapter_health.observed_status in OBSERVED_STATUSES

    def test_no_boolean_healthy_field_exists(self):
        """The misread trap is banned by construction: the only verdict
        is the observed_status word."""
        fields = AdapterHealth.__dataclass_fields__
        assert "healthy" not in fields
        assert "is_healthy" not in fields
        assert "status" not in fields  # only observed_status


# --------------------------------------------------------------------------
# 2. Empty / single / multi adapter shapes
# --------------------------------------------------------------------------
class TestAdapterShapes:
    def test_empty_log_has_no_adapters_and_keeps_config(self, db_session):
        snapshot = health(db_session)
        assert snapshot.adapters == {}
        assert snapshot.window_size == DEFAULT_WINDOW_SIZE == 20
        assert snapshot.generated_at == NOW

    def test_single_adapter_unknown_with_zero_terminal_chains(self, db_session):
        # Governance refusals only — the adapter ran NOTHING.
        run_chain(db_session, policy=DENY_POLICY)
        run_chain(db_session, status="rejected")
        view = health(db_session).adapters["mock"]
        assert view.observed_status == "unknown"
        assert view.window_size == 0
        assert view.window_success_rate is None
        # ...yet the refusals remain visible as governance facts.
        assert view.all_time_guard_rejected == 2
        assert view.total_chains == 2
        assert view.last_execution_state == "guard_rejected"

    def test_multi_adapter_independent_views(self, db_session):
        for _ in range(2):
            run_chain(db_session)  # mock: all green
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        snapshot = health(db_session)
        assert set(snapshot.adapters) == {"mock", "probe-a"}
        assert snapshot.adapters["mock"].observed_status == "healthy"
        assert snapshot.adapters["probe-a"].observed_status == "failing"


# --------------------------------------------------------------------------
# 3. Recent-N window + judgement bands
# --------------------------------------------------------------------------
class TestWindowAndJudgement:
    def test_recent_n_window_only_counts_newest_terminal_chains(self, db_session):
        # 2 failures, then 3 successes (SAME adapter): with a 2-wide
        # window the old failures fall OUT — the window holds only the
        # newest terminal chains.
        for _ in range(2):
            run_chain(db_session, FailingStub("timeout", name="probe-a"))
        for _ in range(3):
            run_chain(db_session, SuccessStub("probe-a"))
        view = health(db_session, window_size=2).adapters["probe-a"]
        assert view.window_size == 2
        assert view.window_succeeded == 2
        assert view.window_failed == 0
        assert view.observed_status == "healthy"
        # All-time keeps the full history.
        assert view.total_chains == 5
        assert view.all_time_failed == 2

    def test_band_boundaries_are_inclusive_at_healthy(self, db_session):
        # Exactly 90%: 9 successes + 1 failure -> healthy (>= 0.9).
        for _ in range(9):
            run_chain(db_session, SuccessStub("mock"))
        run_chain(db_session, FailingStub("timeout", name="mock"))
        view = health(db_session).adapters["mock"]
        assert view.window_success_rate == pytest.approx(0.9)
        assert view.observed_status == "healthy"

    def test_degraded_band(self, db_session):
        # 5 successes + 4 failures = 55.6% -> degraded.
        for _ in range(5):
            run_chain(db_session, SuccessStub("mock"))
        for _ in range(4):
            run_chain(db_session, FailingStub("adapter_error", name="mock"))
        view = health(db_session).adapters["mock"]
        assert view.observed_status == "degraded"

    def test_failing_band(self, db_session):
        # 1 success + 4 failures = 20% -> failing.
        run_chain(db_session, SuccessStub("mock"))
        for _ in range(4):
            run_chain(db_session, FailingStub("timeout", name="mock"))
        view = health(db_session).adapters["mock"]
        assert view.observed_status == "failing"

    def test_custom_thresholds_change_the_verdict_deterministically(
        self, db_session
    ):
        for _ in range(5):
            run_chain(db_session, SuccessStub("mock"))
        for _ in range(4):
            run_chain(db_session, FailingStub("adapter_error", name="mock"))
        strict = HealthThresholds(healthy=0.99, degraded=0.95)
        view = health(db_session, thresholds=strict).adapters["mock"]
        assert view.observed_status == "failing"  # 55.6% < 0.95


# --------------------------------------------------------------------------
# 4. Failure classifications inside the window
# --------------------------------------------------------------------------
class TestFailureClassification:
    def test_timeout_unavailable_protocol_counts(self, db_session):
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, FailingStub("adapter_unavailable", name="probe-a"))
        run_chain(db_session)  # mock success
        view = health(db_session).adapters["probe-a"]
        assert view.timeout_count == 2
        assert view.unavailable_count == 1
        assert view.protocol_violation_count == 0

    def test_recent_failures_newest_first_with_frozen_words(self, db_session):
        run_chain(db_session, FailingStub("timeout", name="probe-a"))
        run_chain(db_session, FailingStub("adapter_error", name="probe-a"))
        run_chain(db_session)  # success between failures
        run_chain(db_session, FailingStub("adapter_unavailable", name="probe-a"))
        view = health(db_session).adapters["probe-a"]
        assert [f.classification for f in view.recent_failures] == [
            "adapter_unavailable",  # newest
            "adapter_error",
            "timeout",  # oldest
        ]
        stamps = [f.failed_at for f in view.recent_failures]
        assert stamps == sorted(stamps, reverse=True)


# --------------------------------------------------------------------------
# 5. Governance never poisons adapter health (the attribution lock)
# --------------------------------------------------------------------------
class TestGovernanceAttributionLock:
    def test_many_guard_rejections_never_make_adapter_unhealthy(self, db_session):
        # One success, then a flood of governance refusals: the adapter
        # stays HEALTHY — Policy/Approval/RBAC pressure is not a
        # Shuffle/Wazuh/TheHive problem.
        run_chain(db_session)
        for _ in range(10):
            run_chain(db_session, policy=DENY_POLICY)
        for _ in range(10):
            run_chain(db_session, status="rejected")
        view = health(db_session).adapters["mock"]
        assert view.observed_status == "healthy"
        assert view.window_succeeded == 1
        assert view.window_failed == 0
        assert view.all_time_guard_rejected == 20

    def test_in_flight_chains_excluded_from_window(self, db_session):
        run_chain(db_session)
        for _ in range(3):
            add_in_flight_chain(db_session)
        view = health(db_session).adapters["mock"]
        assert view.observed_status == "healthy"
        assert view.window_size == 1
        assert view.all_time_in_flight == 3


# --------------------------------------------------------------------------
# 6. Last execution facts
# --------------------------------------------------------------------------
class TestLastExecution:
    def test_last_execution_reflects_the_newest_chain_any_outcome(self, db_session):
        run_chain(db_session, SuccessStub("mock"))
        run_chain(db_session, FailingStub("timeout", name="mock"))
        view = health(db_session).adapters["mock"]
        assert view.last_execution_state == "failed"
        assert view.last_execution_at is not None

    def test_last_execution_updates_after_a_refusal(self, db_session):
        run_chain(db_session)
        run_chain(db_session, policy=DENY_POLICY)
        view = health(db_session).adapters["mock"]
        assert view.last_execution_state == "guard_rejected"


# --------------------------------------------------------------------------
# 7. Read-only / deterministic / immutable nails
# --------------------------------------------------------------------------
class TestPurityNails:
    def test_row_count_and_content_unchanged(self, db_session):
        run_chain(db_session)
        run_chain(db_session, FailingStub("timeout"))
        before = sorted(
            (str(r.id), r.decision, str(r.created_at))
            for r in db_session.scalars(select(ExecutionLog))
        )
        health(db_session)
        health(db_session)
        after = sorted(
            (str(r.id), r.decision, str(r.created_at))
            for r in db_session.scalars(select(ExecutionLog))
        )
        assert after == before

    def test_deterministic_same_stamp(self, db_session):
        run_chain(db_session)
        run_chain(db_session, FailingStub("timeout"))
        assert health(db_session) == health(db_session)

    def test_different_now_changes_only_the_stamp(self, db_session):
        run_chain(db_session)
        a = health(db_session)
        b = health(db_session, now=NOW + timedelta(hours=1))
        assert a.generated_at != b.generated_at
        assert a.adapters == b.adapters


# --------------------------------------------------------------------------
# 8. Structural locks (source level)
# --------------------------------------------------------------------------
class TestStructuralLocks:
    def test_no_db_write_calls_in_source(self):
        source = HEALTH_SOURCE.read_text(encoding="utf-8")
        for banned in (".add(", ".flush(", ".commit(", ".rollback("):
            assert banned not in source

    def test_no_outbound_or_executor_imports(self):
        """No probe exists by design: no HTTP library, no executor
        module may ever be imported here."""
        tree = ast.parse(HEALTH_SOURCE.read_text(encoding="utf-8"))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        for name in imports:
            assert not name.startswith(("httpx", "requests", "urllib"))
            assert name not in {
                "app.services.executions.base",
                "app.services.executions.mock",
                "app.services.executions.registry",
                "app.services.executions.shuffle",
                "app.services.executions.wazuh",
                "app.services.executions.thehive",
            }

    def test_threshold_validation_fail_closed(self):
        with pytest.raises(ValueError):
            HealthThresholds(healthy=1.2, degraded=0.5)
        with pytest.raises(ValueError):
            HealthThresholds(healthy=0.5, degraded=0.9)
        with pytest.raises(ValueError):
            HealthThresholds(healthy=True, degraded=0.5)

    def test_window_size_validation_fail_closed(self, db_session):
        with pytest.raises(ValueError):
            health(db_session, window_size=0)
        with pytest.raises(ValueError):
            health(db_session, window_size=-3)
