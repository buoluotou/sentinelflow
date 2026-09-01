"""Phase 3.3.2.4: Service Integration — the Execution Policy wired into
the frozen forward chain (design B-3):

    requested -> Guard -> Policy -> dispatched -> Executor

Locks the acceptance gate row by row:

- Policy allow  -> dispatched -> Executor called exactly once
- Policy deny   -> requested -> guard_rejected, detail.source = "policy",
                   NO dispatched row, Executor ZERO calls (canary)
- code/reason stable and deterministic across identical evaluations
- Guard runs BEFORE Policy: a capability miss carries source="guard"
  even when the policy would deny too
- Facts immutable on denial: EventRisk / Incident / Recommendation /
  Approval untouched, zero new rows
- policy_from_settings path: EXECUTION_POLICY_ENABLED=false keeps the
  exact 3.1/3.2 behavior; enabled settings drive allow/deny verdicts
- HTTP surface: the legacy EXECUTION_TOKEN and registry operators both
  pass through the Policy; RBAC is never bypassed by it; forged risk /
  severity / timestamp fields stay a 422 at the schema boundary; a
  misconfigured policy fails closed with 503 and zero executor calls

Service-level verdicts are driven with a frozen server clock (the Policy
judges the SERVER time — datetime.now in the service module is patched,
so every assertion is clock-deterministic). No React, no real external
systems.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    EventRisk,
    ExecutionLog,
    Incident,
)
from app.services.executions import service as service_module
from app.services.executions.mock import MockExecutor
from app.services.executions.policy import ExecutionPolicy
from app.services.executions.service import execute_response


# --------------------------------------------------------------------------
# Deterministic server clock — the Policy judges the SERVER time only
# --------------------------------------------------------------------------
class _FrozenDatetime:
    """Stands in for datetime inside the service module; now() returns a
    fixed instant so every policy verdict is clock-deterministic."""

    fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        moment = cls.fixed
        return moment if tz is not None else moment.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def frozen_server_clock(monkeypatch):
    """Patch the service's clock to a fixed instant INSIDE the default
    execution window. Tests move the hands via _FrozenDatetime.fixed."""
    _FrozenDatetime.fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(service_module, "datetime", _FrozenDatetime)
    yield


def at(hour: int, minute: int) -> None:
    _FrozenDatetime.fixed = datetime(2026, 9, 1, hour, minute, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Seeding + canary executor + policies
# --------------------------------------------------------------------------
def seed_approved(db_session, *, risk_score: int | None = 85):
    """alert_group -> recommendation -> approval (+ optional EventRisk,
    the Policy's ONLY risk fact). Returns (approval, recommendation)."""
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.10", "rationale": "abuse"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    if risk_score is not None:
        db_session.add(
            EventRisk(alert_group_id=group.id, score=risk_score, level="high")
        )
        db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status="approved",
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.flush()
    return approval, record


def seed_incident(db_session, recommendation, risk_score: int) -> Incident:
    incident = Incident(
        alert_group_id=recommendation.alert_group_id,
        title="Case: SSH Brute Force",
        severity="high",
        risk_score=risk_score,
        status="open",
    )
    db_session.add(incident)
    db_session.flush()
    return incident


class CanaryExecutor(MockExecutor):
    """Counts every adapter call — the proof that a policy refusal
    reaches the Executor as ZERO calls."""

    def __init__(self):
        super().__init__()
        self.execute_calls = 0
        self.compensate_calls = 0

    def execute(self, dispatch):
        self.execute_calls += 1
        return super().execute(dispatch)

    def compensate(self, dispatch):
        self.compensate_calls += 1
        return super().compensate(dispatch)


class NoCapabilityExecutor:
    """Supports nothing — drives the Guard stage miss used to prove the
    Guard verdict lands BEFORE the Policy ever runs."""

    name = "incapable"

    def supports(self, action):
        return False

    def supports_compensation(self, action):
        return False


def business_hours(**overrides) -> ExecutionPolicy:
    """Enabled policy allowing the frozen 10:00 default instant with the
    frozen default thresholds (block_source_ip needs >= 70)."""
    return ExecutionPolicy(enabled=True, **overrides)


#: Window 23:00-23:59 UTC — the frozen 22:15 instant sits OUTSIDE it.
DENY_WINDOW = ExecutionPolicy(enabled=True, window_start="23:00", window_end="23:59")
DENY_RISK = ExecutionPolicy(enabled=True, window_start="00:00", window_end="23:59")
FULL_ALLOW = ExecutionPolicy(enabled=True, window_start="00:00", window_end="23:59")


def rows_asc(db_session, execution_id):
    return list(
        db_session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


# --------------------------------------------------------------------------
# Allow path: Policy -> dispatched -> Executor
# --------------------------------------------------------------------------
class TestPolicyAllowDispatches:
    def test_allow_chain_calls_executor_exactly_once(self, db_session):
        approval, _ = seed_approved(db_session, risk_score=85)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            policy=business_hours(),
        )
        assert result.chain == ("requested", "dispatched", "succeeded")
        assert executor.execute_calls == 1

    def test_missing_risk_fact_allows_when_policy_disabled(
        self, db_session, monkeypatch
    ):
        """Disabled policy = ALLOW regardless of the risk fact — the
        exact frozen 3.1/3.2 behavior (regression gate)."""
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", False)
        approval, _ = seed_approved(db_session, risk_score=None)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=CanaryExecutor(),
        )
        assert result.chain == ("requested", "dispatched", "succeeded")


# --------------------------------------------------------------------------
# Deny paths: requested -> guard_rejected, Executor at ZERO calls
# --------------------------------------------------------------------------
class TestPolicyDenyLandsGuardRejected:
    def test_window_denial_chain_and_detail(self, db_session):
        at(22, 15)  # outside 09:00-18:00 UTC
        approval, _ = seed_approved(db_session, risk_score=95)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            policy=DENY_WINDOW,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert result.final_decision == "guard_rejected"
        assert executor.execute_calls == 0
        rows = rows_asc(db_session, result.execution_id)
        assert [row.decision for row in rows] == ["requested", "guard_rejected"]
        assert all(row.decision != "dispatched" for row in rows)
        detail = rows[-1].detail
        assert detail["source"] == "policy"
        assert detail["code"] == "outside_execution_window"
        assert "23:00-23:59" in detail["reason"]
        assert "22:15" in detail["reason"]  # the SERVER time, frozen

    def test_risk_below_threshold_denied(self, db_session):
        approval, _ = seed_approved(db_session, risk_score=40)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            policy=DENY_RISK,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert executor.execute_calls == 0
        detail = rows_asc(db_session, result.execution_id)[-1].detail
        assert detail == {
            "source": "policy",
            "code": "risk_threshold_not_met",
            "reason": detail["reason"],
        }
        assert "at least 70" in detail["reason"]
        assert "40" in detail["reason"]

    def test_missing_risk_fact_fails_closed(self, db_session):
        """No EventRisk row = missing server fact -> refuse, never a
        passing zero."""
        approval, _ = seed_approved(db_session, risk_score=None)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            policy=FULL_ALLOW,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert executor.execute_calls == 0
        detail = rows_asc(db_session, result.execution_id)[-1].detail
        assert detail["source"] == "policy"
        assert detail["code"] == "risk_threshold_not_met"
        assert "no risk assessment" in detail["reason"]

    def test_code_reason_stable_across_identical_evaluations(self, db_session):
        details = []
        for _ in range(2):
            approval, _ = seed_approved(db_session, risk_score=40)
            result = execute_response(
                db_session,
                approval_id=approval.id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=CanaryExecutor(),
                policy=DENY_RISK,
            )
            details.append(rows_asc(db_session, result.execution_id)[-1].detail)
        assert details[0] == details[1]


# --------------------------------------------------------------------------
# Chain order: requested -> Guard -> Policy -> Executor
# --------------------------------------------------------------------------
class TestGuardRunsBeforePolicy:
    def test_guard_rejection_wins_over_policy_denial(self, db_session):
        """A capability miss is judged by the Guard stage and carries
        source="guard" even though the policy would deny as well — the
        Policy is AFTER the Guard, never before it."""
        at(22, 15)
        approval, _ = seed_approved(db_session, risk_score=95)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=NoCapabilityExecutor(),
            policy=DENY_WINDOW,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert executor.execute_calls == 0
        detail = rows_asc(db_session, result.execution_id)[-1].detail
        assert detail["source"] == "guard"
        assert detail["code"] == "executor_unsupported"


# --------------------------------------------------------------------------
# Facts immutable: a policy refusal changes NOTHING but the audit rows
# --------------------------------------------------------------------------
class TestFactsImmutableOnDenial:
    def test_denial_leaves_every_entity_untouched(self, db_session):
        at(22, 15)
        approval, recommendation = seed_approved(db_session, risk_score=85)
        incident = seed_incident(db_session, recommendation, 85)
        snapshot = {
            "risk": (85, "high"),
            "incident": ("open", 85, None),
            "recommendation": list(recommendation.recommendations),
            "approval": (approval.status, approval.reviewer),
        }
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=CanaryExecutor(),
            policy=DENY_WINDOW,
        )
        assert result.final_decision == "guard_rejected"
        db_session.expire_all()
        risk = db_session.scalar(
            select(EventRisk).where(
                EventRisk.alert_group_id == recommendation.alert_group_id
            )
        )
        refreshed_incident = db_session.get(Incident, incident.id)
        refreshed_recommendation = db_session.get(
            AIResponseRecommendation, recommendation.id
        )
        refreshed_approval = db_session.get(AIResponseApproval, approval.id)
        assert (risk.score, risk.level) == snapshot["risk"]
        assert (
            refreshed_incident.status,
            refreshed_incident.risk_score,
            refreshed_incident.disposition,
        ) == snapshot["incident"]
        assert refreshed_recommendation.recommendations == snapshot["recommendation"]
        assert (
            refreshed_approval.status,
            refreshed_approval.reviewer,
        ) == snapshot["approval"]
        # No new entity rows — the refusal only appended audit rows.
        assert len(db_session.scalars(select(Incident)).all()) == 1
        assert len(db_session.scalars(select(AIResponseRecommendation)).all()) == 1
        assert len(db_session.scalars(select(AIResponseApproval)).all()) == 1
        assert len(db_session.scalars(select(EventRisk)).all()) == 1


# --------------------------------------------------------------------------
# .env -> Settings -> Policy (the policy_from_settings seam)
# --------------------------------------------------------------------------
class TestPolicyFromSettingsWiring:
    def test_enabled_settings_allow_inside_window(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "09:00")
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "18:00")
        monkeypatch.setattr(
            settings, "EXECUTION_POLICY_MIN_RISK_BLOCK_SOURCE_IP", 70
        )
        approval, _ = seed_approved(db_session, risk_score=85)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert result.chain == ("requested", "dispatched", "succeeded")
        assert executor.execute_calls == 1

    def test_enabled_settings_deny_below_threshold(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        monkeypatch.setattr(
            settings, "EXECUTION_POLICY_MIN_RISK_BLOCK_SOURCE_IP", 70
        )
        approval, _ = seed_approved(db_session, risk_score=40)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert executor.execute_calls == 0
        detail = rows_asc(db_session, result.execution_id)[-1].detail
        assert detail["source"] == "policy"
        assert detail["code"] == "risk_threshold_not_met"

    def test_enabled_settings_deny_outside_window(self, db_session, monkeypatch):
        at(3, 30)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        approval, _ = seed_approved(db_session, risk_score=95)
        executor = CanaryExecutor()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert result.chain == ("requested", "guard_rejected")
        assert executor.execute_calls == 0
        detail = rows_asc(db_session, result.execution_id)[-1].detail
        assert detail["code"] == "outside_execution_window"

    def test_default_disabled_settings_keep_31_behavior(self, db_session):
        """The shipped defaults (policy disabled) reproduce the frozen
        3.1/3.2 chain verbatim — no injected policy, no monkeypatch."""
        assert settings.EXECUTION_POLICY_ENABLED is False
        approval, _ = seed_approved(db_session, risk_score=85)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=CanaryExecutor(),
        )
        assert result.chain == ("requested", "dispatched", "succeeded")


# --------------------------------------------------------------------------
# HTTP surface: legacy token + registry operators + RBAC + smuggling
# --------------------------------------------------------------------------
EXECUTE_URL = "/api/v1/executions"
TOKEN = "exec-secret-policy-integration-01"
OPERATORS_JSON = json.dumps(
    [
        {"token": "tok-executor-policy-01", "name": "ops-exec", "role": "executor"},
        {"token": "tok-viewer-policy-01", "name": "ops-view", "role": "viewer"},
    ]
)


def _execute_body(approval) -> dict:
    return {
        "execution_id": str(uuid.uuid4()),
        "approval_id": str(approval.id),
    }


def _seed_api_approval(db_session):
    approval, _ = seed_approved(db_session, risk_score=85)
    db_session.commit()
    return approval


class TestHttpPolicyIntegration:
    def test_legacy_token_denied_by_policy(self, client, db_session, monkeypatch):
        """The legacy EXECUTION_TOKEN path goes through the Policy like
        any registry operator (spec §11)."""
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        # Empty window [05:00, 05:00) denies at ANY real clock time.
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "05:00")
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "05:00")
        approval = _seed_api_approval(db_session)
        response = client.post(
            EXECUTE_URL,
            json=_execute_body(approval),
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["chain"] == ["requested", "guard_rejected"]
        last = body["history"][-1]
        assert last["detail"]["source"] == "policy"
        assert last["detail"]["code"] == "outside_execution_window"
        assert TOKEN not in response.text

    def test_legacy_token_allowed_when_policy_allows(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "00:00")
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "23:59")
        approval = _seed_api_approval(db_session)
        response = client.post(
            EXECUTE_URL,
            json=_execute_body(approval),
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "succeeded"

    def test_registry_operator_denied_by_policy(self, client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", OPERATORS_JSON)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "05:00")
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "05:00")
        approval = _seed_api_approval(db_session)
        response = client.post(
            EXECUTE_URL,
            json=_execute_body(approval),
            headers={"Authorization": "Bearer tok-executor-policy-01"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["history"][-1]["detail"]["source"] == "policy"
        # The authenticated identity stands — the policy touches no RBAC.
        assert body["history"][0]["operator"] == "ops-exec"

    def test_policy_never_bypasses_rbac(self, client, db_session, monkeypatch):
        """Policy enabled + viewer role = still 403. The Policy sits
        AFTER RBAC and can never grant execution ability."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", OPERATORS_JSON)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        approval = _seed_api_approval(db_session)
        response = client.post(
            EXECUTE_URL,
            json=_execute_body(approval),
            headers={"Authorization": "Bearer tok-viewer-policy-01"},
        )
        assert response.status_code == 403
        assert (
            len(db_session.query(ExecutionLog).filter_by(decision="dispatched").all())
            == 0
        )

    def test_forged_policy_facts_rejected_at_schema(
        self, client, db_session, monkeypatch
    ):
        """risk_score / severity / timestamp have no channel into the
        Policy — extra="forbid" 422s them at the boundary."""
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        approval = _seed_api_approval(db_session)
        body = _execute_body(approval)
        body.update({"risk_score": 100, "severity": "critical", "timestamp": "2026-01-01T00:00:00Z"})
        response = client.post(
            EXECUTE_URL,
            json=body,
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 422
        assert len(db_session.query(ExecutionLog).all()) == 0

    def test_misconfigured_policy_fails_closed_503(
        self, client, db_session, monkeypatch
    ):
        """A broken policy configuration is a deployment fault: 503,
        fail-closed — never a silent allow, never an executor call."""
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
        monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "nine-am")
        approval = _seed_api_approval(db_session)
        response = client.post(
            EXECUTE_URL,
            json=_execute_body(approval),
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Execution policy misconfigured"
        # The aborted transaction rolled back: a broken policy leaves NO
        # half-written chain — zero audit rows, zero executor calls.
        assert db_session.query(ExecutionLog).count() == 0
