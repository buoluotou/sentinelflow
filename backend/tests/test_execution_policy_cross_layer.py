"""Phase 3.3.2.6: Cross-layer regression — the Execution Policy proven
inside the REAL chain, end to end:

    Token -> Operator / RBAC -> Approval -> Guard -> Policy
    -> ResponseExecutor -> ExecutionLog

This suite deliberately does NOT re-test pure policy unit logic
(3.3.2.1) or the Service seam in isolation (3.3.2.4). Every journey
runs through the REAL production stack — real HTTP API, real operator
authentication, real Service, real Guard, real policy_from_settings
(.env -> Settings), real adapters (Mock registry-produced; Shuffle /
Wazuh / TheHive through their frozen offline transport seam), real DB.

Journeys (acceptance gate):
1. Policy Allow    approved -> RBAC pass -> Guard pass -> Policy allow
                   -> dispatched -> succeeded (DB + API agree)
2. Policy Reject   same chain, policy refusal -> requested ->
                   guard_rejected, source=policy, Executor = 0 calls
3. Guard/Policy precedence: a Guard rejection lands source="guard" even
                   when the policy would deny too
4. Legacy token    EXECUTION_TOKEN path runs through the Policy — no
                   bypass; registry operators keep their RBAC
5. Dual policy     risk passed + time denied -> outside_execution_window
                   time passed + risk denied -> risk_threshold_not_met
6. Invariance      EventRisk / Incident / Recommendation / Approval
                   byte-identical before vs after (allow AND deny)
7. Adapter chains  Mock full run (registry-produced, zero overrides);
                   Shuffle / Wazuh / TheHive full runs over the stub
                   transport; a policy refusal reaches every adapter as
                   ZERO outbound calls

Discipline: no new state word (guard_rejected only), no policy_rejected,
no ExecutionLog schema change, v1.2.0 untouched.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.api.v1.response_execution import get_response_executor
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
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.shuffle import ShuffleExecutor
from app.services.executions.thehive import TheHiveExecutor
from app.services.executions.wazuh import WazuhExecutor

EXECUTE = "/api/v1/executions"
TOKEN = "exec-secret-policy-cross-layer-01"
OPERATORS_JSON = json.dumps(
    [
        {"token": "tok-xlayer-exec", "name": "ops-xlayer", "role": "executor"},
        {"token": "tok-xlayer-view", "name": "view-xlayer", "role": "viewer"},
    ]
)


# --------------------------------------------------------------------------
# Deterministic server clock (Policy judges SERVER time only)
# --------------------------------------------------------------------------
class _FrozenDatetime:
    fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        moment = cls.fixed
        return moment if tz is not None else moment.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def frozen_server_clock(monkeypatch):
    """Pin the Service clock to 10:00 UTC so every window verdict is
    deterministic; journeys move time only via settings windows."""
    _FrozenDatetime.fixed = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(service_module, "datetime", _FrozenDatetime)
    yield


# --------------------------------------------------------------------------
# Deployment fixtures: auth paths + policy switch
# --------------------------------------------------------------------------
@pytest.fixture()
def legacy_auth(monkeypatch):
    """Legacy EXECUTION_TOKEN path (must traverse the Policy too)."""
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def operator_auth(monkeypatch):
    """3.3.1 registry path: executor-role operator token."""
    monkeypatch.setattr(settings, "OPERATORS_JSON", OPERATORS_JSON)
    return {"Authorization": "Bearer tok-xlayer-exec"}


@pytest.fixture()
def policy_on(monkeypatch):
    """Policy enabled, window open around the frozen 10:00 instant,
    default frozen thresholds. Journeys narrow the window / risk per
    case via extra monkeypatching."""
    monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", True)
    monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "00:00")
    monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "23:59")


def close_window(monkeypatch):
    """Empty window [05:00, 05:00) — denies at ANY clock instant."""
    monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_START", "05:00")
    monkeypatch.setattr(settings, "EXECUTION_POLICY_WINDOW_END", "05:00")


@pytest.fixture()
def app():
    """Executor dependency-override seam (cleared on client teardown).
    Journeys without an override run the registry-produced REAL adapter."""
    from app.main import app as fastapi_app

    return fastapi_app


# --------------------------------------------------------------------------
# Seeding: complete Phase 1+2 world (event + risk + incident + approval)
# --------------------------------------------------------------------------
def seed_world(
    db_session,
    *,
    action="block_source_ip",
    target="203.0.113.10",
    risk_score: int | None = 85,
    status="approved",
):
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
    risk = None
    if risk_score is not None:
        risk = EventRisk(
            alert_group_id=group.id, score=risk_score, level="high",
            factors={"severity": 4},
        )
        db_session.add(risk)
        db_session.flush()
    incident = Incident(
        alert_group_id=group.id,
        title="SSH brute force investigation",
        severity="high",
        risk_score=risk_score if risk_score is not None else 0,
        status="open",
    )
    db_session.add(incident)
    recommendation = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[{"action": action, "target": target, "rationale": "abuse"}],
        confidence=0.7,
    )
    db_session.add(recommendation)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=recommendation.id,
        status=status,
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.commit()
    return {
        "approval": approval,
        "recommendation": recommendation,
        "risk": risk,
        "incident": incident,
    }


def world_snapshot(db_session, world) -> dict:
    """Byte-level capture of every Phase 2/3.1 entity the Policy must
    never touch."""
    approval, recommendation = world["approval"], world["recommendation"]
    db_session.expire_all()
    risk = world["risk"]
    incident = world["incident"]
    return {
        "risk": None
        if risk is None
        else (risk.score, risk.level, dict(risk.factors or {})),
        "incident": (
            incident.title,
            incident.severity,
            incident.risk_score,
            incident.status,
            incident.disposition,
        ),
        "recommendation": (
            json.dumps(recommendation.recommendations, sort_keys=True),
            recommendation.provider,
            recommendation.model,
            recommendation.confidence,
        ),
        "approval": (
            approval.status,
            approval.reviewer,
            approval.reviewed_at,
        ),
    }


def assert_world_unchanged(db_session, world, before: dict) -> None:
    db_session.expire_all()
    risk = db_session.get(EventRisk, world["risk"].id) if world["risk"] else None
    incident = db_session.get(Incident, world["incident"].id)
    recommendation = db_session.get(
        AIResponseRecommendation, world["recommendation"].id
    )
    approval = db_session.get(AIResponseApproval, world["approval"].id)
    after = {
        "risk": None
        if risk is None
        else (risk.score, risk.level, dict(risk.factors or {})),
        "incident": (
            incident.title,
            incident.severity,
            incident.risk_score,
            incident.status,
            incident.disposition,
        ),
        "recommendation": (
            json.dumps(recommendation.recommendations, sort_keys=True),
            recommendation.provider,
            recommendation.model,
            recommendation.confidence,
        ),
        "approval": (
            approval.status,
            approval.reviewer,
            approval.reviewed_at,
        ),
    }
    assert after == before
    # No NEW Phase 2/3.1 entities may appear either.
    assert len(db_session.scalars(select(EventRisk)).all()) == (1 if risk else 0)
    assert len(db_session.scalars(select(Incident)).all()) == 1
    assert len(db_session.scalars(select(AIResponseRecommendation)).all()) == 1
    assert len(db_session.scalars(select(AIResponseApproval)).all()) == 1


def db_rows(db_session, execution_id):
    return list(
        db_session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


def execute_body(approval) -> dict:
    return {"execution_id": str(uuid.uuid4()), "approval_id": str(approval.id)}


# --------------------------------------------------------------------------
# Zero-call canary executor (proves refusal stops BEFORE the adapter)
# --------------------------------------------------------------------------
class CanaryExecutor:
    name = "canary"

    def __init__(self):
        self.execute_calls = 0
        self.compensate_calls = 0

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return True

    def execute(self, dispatch):
        self.execute_calls += 1
        return {
            "status": "succeeded",
            "detail": {"provider": "canary"},
            "raw_response": {"canary": True},
        }

    def compensate(self, dispatch):
        self.compensate_calls += 1
        return {
            "status": "succeeded",
            "detail": {"provider": "canary"},
            "raw_response": {"canary": True},
        }


# --------------------------------------------------------------------------
# 1. Policy Allow journey: full chain to succeeded
# --------------------------------------------------------------------------
class TestPolicyAllowChain:
    def test_legacy_token_full_chain_succeeds(
        self, client, db_session, legacy_auth, policy_on
    ):
        """Legacy EXECUTION_TOKEN -> RBAC -> Guard -> Policy allow ->
        dispatched -> succeeded, registry-produced MockExecutor, DB and
        API agree row for row."""
        world = seed_world(db_session)
        before = world_snapshot(db_session, world)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]
        assert body["history"][0]["operator"] == "legacy-execution"
        # DB rows match the API view exactly.
        rows = db_rows(db_session, uuid.UUID(body["execution_id"]))
        assert [row.decision for row in rows] == body["chain"]
        assert rows[0].action == "block_source_ip"
        assert rows[0].target == "203.0.113.10"
        assert_world_unchanged(db_session, world, before)

    def test_registry_operator_full_chain_succeeds(
        self, client, db_session, operator_auth, policy_on
    ):
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=operator_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["history"][0]["operator"] == "ops-xlayer"

    def test_rbac_still_gates_when_policy_allows(
        self, client, db_session, policy_on, monkeypatch
    ):
        """Policy allow never substitutes for RBAC: viewer stays 403."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", OPERATORS_JSON)
        world = seed_world(db_session)
        response = client.post(
            EXECUTE,
            json=execute_body(world["approval"]),
            headers={"Authorization": "Bearer tok-xlayer-view"},
        )
        assert response.status_code == 403
        assert db_session.query(ExecutionLog).count() == 0


# --------------------------------------------------------------------------
# 2/5. Policy Reject journeys + dual-policy ordering
# --------------------------------------------------------------------------
class TestPolicyRejectChains:
    def test_time_denied_with_risk_passed(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        """Dual policy A: risk (85 >= 70) passes, window denies -> the
        verdict is outside_execution_window and the adapter gets ZERO
        calls."""
        close_window(monkeypatch)
        canary = CanaryExecutor()
        app.dependency_overrides[get_response_executor] = lambda: canary
        world = seed_world(db_session, risk_score=85)
        before = world_snapshot(db_session, world)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["chain"] == ["requested", "guard_rejected"]
        last = body["history"][-1]["detail"]
        assert last["source"] == "policy"
        assert last["code"] == "outside_execution_window"
        assert canary.execute_calls == 0
        # DB agrees; no dispatched row ever landed.
        rows = db_rows(db_session, uuid.UUID(body["execution_id"]))
        assert [row.decision for row in rows] == ["requested", "guard_rejected"]
        assert rows[-1].detail["source"] == "policy"
        assert_world_unchanged(db_session, world, before)

    def test_risk_denied_with_time_passed(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        """Dual policy B: window open, risk (40 < 70) denies -> stable
        risk_threshold_not_met verdict."""
        canary = CanaryExecutor()
        app.dependency_overrides[get_response_executor] = lambda: canary
        details = []
        for _ in range(2):
            world = seed_world(db_session, risk_score=40)
            response = client.post(
                EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
            )
            assert response.status_code == 201
            body = response.json()
            assert body["derived_state"] == "guard_rejected"
            details.append(body["history"][-1]["detail"])
        assert details[0]["source"] == "policy"
        assert details[0]["code"] == "risk_threshold_not_met"
        assert details[0] == details[1]  # code / reason stable
        assert canary.execute_calls == 0

    def test_missing_risk_fact_denied_through_full_chain(
        self, client, db_session, legacy_auth, policy_on, app
    ):
        canary = CanaryExecutor()
        app.dependency_overrides[get_response_executor] = lambda: canary
        world = seed_world(db_session, risk_score=None)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["history"][-1]["detail"]["code"] == "risk_threshold_not_met"
        assert canary.execute_calls == 0

    def test_guard_rejection_beats_policy_denial(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        """Guard reject + Policy reject -> the audit says source=guard:
        the Policy runs AFTER the Guard and never shadows it."""
        close_window(monkeypatch)
        canary = CanaryExecutor()
        app.dependency_overrides[get_response_executor] = lambda: canary
        # Only approved/rejected persist (CHECK constraint) — a
        # REJECTED approval is the Guard-stage miss under test.
        world = seed_world(db_session, risk_score=95, status="rejected")
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        last = body["history"][-1]["detail"]
        assert last["source"] == "guard"
        assert last["code"] == "approval_not_approved"
        assert canary.execute_calls == 0

    def test_policy_disabled_keeps_original_chain(
        self, client, db_session, legacy_auth, monkeypatch
    ):
        """Policy disabled = the untouched 3.1/3.2 behavior, even with
        NO risk fact (an enabled policy would refuse fail-closed)."""
        monkeypatch.setattr(settings, "EXECUTION_POLICY_ENABLED", False)
        world = seed_world(db_session, risk_score=None)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]


# --------------------------------------------------------------------------
# 7. Real adapter chains: Mock / Shuffle / Wazuh / TheHive
# --------------------------------------------------------------------------
class _StubResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        pass


class StubTransport:
    """Offline transport seam — records outbound calls, plays back one
    scripted response. ``len(calls)`` is the adapter-level proof of the
    zero-call invariant."""

    def __init__(self, *, status=200, payload=None):
        self._status = status
        self._body = json.dumps(payload or {}).encode("utf-8")
        self.calls: list[dict] = []

    def __call__(self, request, timeout=None):
        self.calls.append({"url": request.full_url, "method": request.get_method()})
        return _StubResponse(self._status, self._body)


class TestRealAdapterChains:
    def test_mock_full_run_no_override(self, client, db_session, legacy_auth, policy_on):
        """The registry-produced REAL MockExecutor runs the full chain
        with the policy enabled — zero seams touched."""
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["history"][1]["detail"]["executor"] == "mock"

    def test_shuffle_allow_executes_once_deny_zero(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        allow_stub = StubTransport(payload={"success": True})
        executor = ShuffleExecutor(
            AdapterCredentials(
                adapter="shuffle", base_url="http://stub", api_key="sh-secret"
            ),
            {"block_source_ip": "wf-block"},
            timeout=1.0,
            transport=allow_stub,
        )
        app.dependency_overrides[get_response_executor] = lambda: executor
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "succeeded"
        assert len(allow_stub.calls) == 1

        # Same adapter, denying window -> ZERO outbound calls.
        close_window(monkeypatch)
        deny_stub = StubTransport(payload={"success": True})
        executor = ShuffleExecutor(
            AdapterCredentials(
                adapter="shuffle", base_url="http://stub", api_key="sh-secret"
            ),
            {"block_source_ip": "wf-block"},
            timeout=1.0,
            transport=deny_stub,
        )
        app.dependency_overrides[get_response_executor] = lambda: executor
        world = seed_world(db_session)
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["history"][-1]["detail"]["source"] == "policy"
        assert len(deny_stub.calls) == 0

    def test_wazuh_allow_executes_once_deny_zero(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        def make_executor(stub):
            return WazuhExecutor(
                AdapterCredentials(
                    adapter="wazuh", base_url="http://stub",
                    username="wz-user", password="wz-secret",
                ),
                timeout=1.0,
                transport=stub,
            )

        allow_stub = StubTransport(payload={"success": True, "command_id": "c-1"})
        app.dependency_overrides[get_response_executor] = lambda: make_executor(
            allow_stub
        )
        world = seed_world(db_session, action="isolate_host", target="agent001")
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "succeeded"
        assert len(allow_stub.calls) == 1

        close_window(monkeypatch)
        deny_stub = StubTransport(payload={"success": True, "command_id": "c-2"})
        app.dependency_overrides[get_response_executor] = lambda: make_executor(
            deny_stub
        )
        world = seed_world(db_session, action="isolate_host", target="agent001")
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "guard_rejected"
        assert len(deny_stub.calls) == 0

    def test_thehive_allow_executes_once_deny_zero(
        self, client, db_session, legacy_auth, policy_on, monkeypatch, app
    ):
        def make_executor(stub):
            return TheHiveExecutor(
                AdapterCredentials(
                    adapter="thehive", base_url="http://stub", api_key="th-secret"
                ),
                timeout=1.0,
                transport=stub,
            )

        allow_stub = StubTransport(payload={"case_id": "case-1"})
        app.dependency_overrides[get_response_executor] = lambda: make_executor(
            allow_stub
        )
        world = seed_world(
            db_session, action="escalate_to_incident", target="INC-2026-0142"
        )
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "succeeded"
        assert len(allow_stub.calls) == 1

        close_window(monkeypatch)
        deny_stub = StubTransport(payload={"case_id": "case-2"})
        app.dependency_overrides[get_response_executor] = lambda: make_executor(
            deny_stub
        )
        world = seed_world(
            db_session, action="escalate_to_incident", target="INC-2026-0142"
        )
        response = client.post(
            EXECUTE, json=execute_body(world["approval"]), headers=legacy_auth
        )
        assert response.status_code == 201
        assert response.json()["derived_state"] == "guard_rejected"
        assert len(deny_stub.calls) == 0
