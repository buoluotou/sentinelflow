"""Phase 3.1.10: Cross-layer regression — the first system-level proof
that the whole response-execution chain composes consistently:

    Approval -> Execute Intent -> HTTP API -> Service -> Guard
    -> Mock Executor -> execution_log -> Derived State -> Audit API

Discipline (14.4 standard, carried forward): every fact under test is
produced by the REAL production stack — real API, real Service, real
Guard, real MockExecutor (registry-produced, no override), real DB.
The ONLY seams touched:
- the executor dependency is overridden with malicious adapters for the
  protocol-violation journey (D9 needs a rogue adapter to judge) and
  with a canary for the guard-rejection journey (proving the executor
  is NEVER reached);
- approval / event skeletons are seeded via ORM (no AI pipeline exists
  offline), exactly like the 3.1.7 suite.

Coverage map (8 journeys + security attacks):
1. success chain          requested -> dispatched -> succeeded (DB+API agree)
2. guard rejection        requested -> guard_rejected, executor untouched
3. adapter failure        adapter_unavailable / timeout / adapter_error
4. protocol violation     rogue adapter outcomes -> failed + protocol_violation
5. duplicate / replay     same id+approval, id+other approval, re-execute
                          after ANY terminal state — first facts untouched
6. compensation chain     inherited facts, compensates link, audit A<->B
7. Phase 2 invariance     EventRisk / Incident / recommendation / approval
                          fields byte-identical before vs after execution
8. HTTP/DB consistency    401/422/404 write 0 rows; 409 writes no new
                          chain; 201 always means a persisted fact

The three invariants this phase exists to lock:
- no duplicate execution
- no tampering with execution facts
- no pollution of Phase 2 data
"""
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
from app.services.executions.mock import MockExecutor
from app.services.executions.models import ExecutionOutcome

EXECUTE = "/api/v1/executions"
COMPENSATE = "/api/v1/executions/compensate"
TOKEN = "exec-secret-cross-layer-0001"

SNAPSHOT_ACTION = "block_source_ip"
SNAPSHOT_TARGET = "203.0.113.10"


@pytest.fixture()
def auth(monkeypatch):
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def app():
    """Executor dependency-override seam; the client fixture clears all
    overrides on teardown. Journeys 1-3, 5-8 leave it untouched, so the
    registry-produced REAL MockExecutor runs."""
    from app.main import app as fastapi_app

    return fastapi_app


# --------------------------------------------------------------------------
# Seeding (event skeleton with Phase 2 facts, approval via ORM)
# --------------------------------------------------------------------------
def seed_world(db_session, *, status="approved"):
    """One complete Phase 1+2 world: AlertGroup -> EventRisk, Incident,
    recommendation snapshot, approval. Returns (approval, event_risk,
    incident, recommendation) for invariance assertions."""
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
    risk = EventRisk(alert_group_id=group.id, score=80, level="high", factors={"severity": 4})
    db_session.add(risk)
    incident = Incident(
        alert_group_id=group.id,
        title="SSH brute force investigation",
        severity="high",
        risk_score=80,
        status="open",
    )
    db_session.add(incident)
    recommendation = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": SNAPSHOT_ACTION, "target": SNAPSHOT_TARGET, "rationale": "abuse"}
        ],
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
    return approval, risk, incident, recommendation


def phase2_snapshot(db_session, approval, risk, incident, recommendation):
    """Byte-level snapshot of every Phase 2 fact the execution layer must
    never touch."""
    db_session.expire_all()
    approval = db_session.get(AIResponseApproval, approval.id)
    recommendation = db_session.get(AIResponseRecommendation, recommendation.id)
    return {
        "risk": (risk.score, risk.level, risk.factors),
        "incident": (incident.status, incident.severity, incident.risk_score, incident.disposition),
        "recommendation": (
            recommendation.provider,
            recommendation.model,
            recommendation.overall_rationale,
            list(recommendation.recommendations or []),
            recommendation.confidence,
        ),
        "approval": (
            approval.status,
            approval.reviewer,
            approval.reviewed_at,
            approval.review_comment,
            approval.recommendation_id,
        ),
    }


# --------------------------------------------------------------------------
# Request + row helpers
# --------------------------------------------------------------------------
def execute_body(approval, execution_id=None, **overrides):
    body = {
        "execution_id": str(execution_id or uuid.uuid4()),
        "approval_id": str(approval.id),
        "operator": "ops-1",
    }
    body.update(overrides)
    return body


def post_execute(client, auth, approval, execution_id=None, **overrides):
    return client.post(
        EXECUTE, json=execute_body(approval, execution_id, **overrides), headers=auth
    )


def rows_for(db_session, execution_id):
    """DB truth for one chain, chronological."""
    return list(
        db_session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


def all_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def detail(client, execution_id):
    return client.get(f"{EXECUTE}/{execution_id}")


def assert_chain_rows(db_session, execution_id, decisions):
    """DB rows == exactly the expected chain, in order, with strictly
    increasing audit stamps (the high-water mark clause)."""
    rows = rows_for(db_session, execution_id)
    assert [row.decision for row in rows] == decisions
    stamps = [row.created_at for row in rows]
    assert stamps == sorted(stamps) and len(set(stamps)) == len(stamps)
    return rows


def assert_api_matches_db(client, db_session, execution_id, derived_state, chain):
    """GET detail agrees with the database row by row — the Audit API is a
    pure read of execution_log, never a reinterpretation."""
    response = detail(client, execution_id)
    assert response.status_code == 200
    body = response.json()
    assert body["derived_state"] == derived_state
    assert body["chain"] == chain
    db_rows = rows_for(db_session, execution_id)
    assert len(body["history"]) == len(db_rows)
    for api_row, db_row in zip(body["history"], db_rows):
        assert api_row["decision"] == db_row.decision
        assert api_row["direction"] == db_row.direction
        assert api_row["action"] == db_row.action
        assert api_row["target"] == db_row.target
        assert api_row["operator"] == db_row.operator
        assert api_row["detail"] == db_row.detail
        assert uuid.UUID(api_row["id"]) == db_row.id


# --------------------------------------------------------------------------
# 1. Success chain
# --------------------------------------------------------------------------
class TestSuccessChain:
    def test_full_chain_db_and_api_agree(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        execution_id = uuid.uuid4()

        response = post_execute(client, auth, approval, execution_id)

        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]
        # action/target are SERVER facts from the snapshot — echoed verbatim
        assert body["action"] == SNAPSHOT_ACTION
        assert body["target"] == SNAPSHOT_TARGET
        assert body["direction"] == "execute"

        rows = assert_chain_rows(db_session, execution_id,
                                 ["requested", "dispatched", "succeeded"])
        # every row carries the same immutable identity facts
        for row in rows:
            assert row.approval_id == approval.id
            assert row.action == SNAPSHOT_ACTION
            assert row.target == SNAPSHOT_TARGET
            assert row.direction == "execute"
        # the real mock adapter ran (DryRun echo + raw response present)
        assert rows[1].detail == {"executor": "mock"}
        assert rows[2].detail["raw_response"] == {"mock": "ok", "operation": "execute"}
        assert rows[2].detail["dry_run"]["executor"] == "mock"

        # Audit API reads the same facts back — no reinterpretation
        assert_api_matches_db(
            client, db_session, execution_id, "succeeded",
            ["requested", "dispatched", "succeeded"],
        )
        # the token never lands in any audit detail
        for row in rows:
            assert TOKEN not in str(row.detail)


# --------------------------------------------------------------------------
# 2. Guard rejection chain
# --------------------------------------------------------------------------
class CanaryExecutor(MockExecutor):
    """Proves the adapter is NEVER reached when a guard rejects."""

    def execute(self, dispatch):
        raise AssertionError("executor must never run after a guard rejection")


class FailOnceAdapter(MockExecutor):
    """Forward execute fails (adapter_error), compensation succeeds — the
    canonical 'failed execution, successful rollback' journey. A plain
    MockExecutor(fail_with=…) would poison BOTH directions."""

    def execute(self, dispatch):
        return ExecutionOutcome(
            status="failed",
            detail={"classification": "adapter_error", "dry_run": self._dry_run_echo(dispatch, "execute")},
            raw_response=None,
        )


class TestGuardRejectionChain:
    def test_rejected_approval_fact_chain(self, client, db_session, auth, app):
        approval, *_ = seed_world(db_session, status="rejected")
        app.dependency_overrides[get_response_executor] = lambda: CanaryExecutor()
        execution_id = uuid.uuid4()

        response = post_execute(client, auth, approval, execution_id)

        # 201 = an execution FACT exists; the verdict lives in derived_state
        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["chain"] == ["requested", "guard_rejected"]

        rows = assert_chain_rows(db_session, execution_id,
                                 ["requested", "guard_rejected"])
        # guard reason present, dispatched absent, no executor success data
        assert rows[1].detail["code"] == "approval_not_approved"
        assert "reason" in rows[1].detail
        assert "dispatched" not in [row.decision for row in rows]
        for row in rows:
            assert "raw_response" not in row.detail

        assert_api_matches_db(
            client, db_session, execution_id, "guard_rejected",
            ["requested", "guard_rejected"],
        )


# --------------------------------------------------------------------------
# 3. Adapter failure classifications (real MockExecutor.fail_with)
# --------------------------------------------------------------------------
class TestAdapterFailure:
    @pytest.mark.parametrize("classification",
                             ["adapter_unavailable", "timeout", "adapter_error"])
    def test_adapter_failure_classification_matches(
        self, client, db_session, auth, app, classification
    ):
        approval, *_ = seed_world(db_session)
        app.dependency_overrides[get_response_executor] = (
            lambda: MockExecutor(fail_with=classification)
        )
        execution_id = uuid.uuid4()

        response = post_execute(client, auth, approval, execution_id)

        assert response.status_code == 201
        assert response.json()["derived_state"] == "failed"

        rows = assert_chain_rows(db_session, execution_id,
                                 ["requested", "dispatched", "failed"])
        # classification mirrors the injected adapter failure exactly
        assert rows[2].detail["classification"] == classification
        assert rows[2].detail["raw_response"] is None

        assert_api_matches_db(
            client, db_session, execution_id, "failed",
            ["requested", "dispatched", "failed"],
        )


# --------------------------------------------------------------------------
# 4. Protocol violation — rogue adapter outcomes judged by the platform
# --------------------------------------------------------------------------
class MaliciousAdapter(MockExecutor):
    """A rogue adapter returning a fixed invalid outcome. protocol_violation
    is NOT injectable through MockExecutor.fail_with (D9) — the only way to
    reach it is the platform parse judging a bad result."""

    def __init__(self, bad_outcome):
        super().__init__()
        self._bad_outcome = bad_outcome

    def execute(self, dispatch):
        return self._bad_outcome


ROGUE_OUTCOMES = [
    pytest.param({"status": "dispatched", "detail": {}, "raw_response": {}},
                 id="status-dispatched"),
    pytest.param({"status": "succeeded", "detail": {}, "raw_response": {},
                  "extra": "smuggled"}, id="extra-field"),
    pytest.param({"detail": {}, "raw_response": {}}, id="missing-status"),
    pytest.param({"status": "failed",
                  "detail": {"classification": "totally_unknown"},
                  "raw_response": {}}, id="unknown-classification"),
    pytest.param({"status": "failed",
                  "detail": {"classification": "protocol_violation"},
                  "raw_response": {}}, id="self-reported-violation"),
    pytest.param("not-a-dict", id="non-outcome-value"),
]


class TestProtocolViolation:
    @pytest.mark.parametrize("bad_outcome", ROGUE_OUTCOMES)
    def test_rogue_outcome_never_masquerades_as_success(
        self, client, db_session, auth, app, bad_outcome
    ):
        approval, *_ = seed_world(db_session)
        app.dependency_overrides[get_response_executor] = (
            lambda: MaliciousAdapter(bad_outcome)
        )
        execution_id = uuid.uuid4()

        response = post_execute(client, auth, approval, execution_id)

        assert response.status_code == 201
        body = response.json()
        # the platform judges: failed + protocol_violation, never succeeded
        assert body["derived_state"] == "failed"
        assert body["chain"] == ["requested", "dispatched", "failed"]

        rows = assert_chain_rows(db_session, execution_id,
                                 ["requested", "dispatched", "failed"])
        assert rows[2].detail["classification"] == "protocol_violation"
        assert rows[2].detail["violation"]  # the parse reason is audited
        assert rows[2].detail["raw_response"] is None


# --------------------------------------------------------------------------
# 5. Duplicate / replay — the first facts always stand
# --------------------------------------------------------------------------
class TestDuplicateReplay:
    def test_same_execution_same_approval_replay_refused(
        self, client, db_session, auth
    ):
        approval, *_ = seed_world(db_session)
        execution_id = uuid.uuid4()
        first = post_execute(client, auth, approval, execution_id)
        assert first.status_code == 201
        original = rows_for(db_session, execution_id)

        replay = post_execute(client, auth, approval, execution_id)

        assert replay.status_code == 409
        db_session.expire_all()
        # the first execution's facts are byte-identical; no 4th row
        assert len(all_rows(db_session)) == 3
        current = rows_for(db_session, execution_id)
        assert [(r.id, r.decision, r.detail) for r in current] == \
               [(r.id, r.decision, r.detail) for r in original]

    def test_same_execution_other_approval_replay_refused(
        self, client, db_session, auth
    ):
        approval_a, *_ = seed_world(db_session)
        approval_b, *_ = seed_world(db_session)
        execution_id = uuid.uuid4()
        assert post_execute(client, auth, approval_a, execution_id).status_code == 201
        original = rows_for(db_session, execution_id)

        attack = post_execute(client, auth, approval_b, execution_id)

        assert attack.status_code == 409
        db_session.expire_all()
        assert len(all_rows(db_session)) == 3
        current = rows_for(db_session, execution_id)
        # execution_id can never rebind to another approval
        assert all(row.approval_id == approval_a.id for row in current)
        assert [(r.id, r.decision) for r in current] == \
               [(r.id, r.decision) for r in original]

    @pytest.mark.parametrize("terminal_setup", ["succeeded", "failed", "guard_rejected"])
    def test_no_re_execute_after_any_terminal_state(
        self, client, db_session, auth, app, terminal_setup
    ):
        approval, *_ = seed_world(db_session)
        if terminal_setup == "failed":
            app.dependency_overrides[get_response_executor] = (
                lambda: MockExecutor(fail_with="timeout")
            )
        elif terminal_setup == "guard_rejected":
            approval.status = "rejected"
            db_session.commit()
        first = post_execute(client, auth, approval)
        assert first.status_code == 201
        assert first.json()["derived_state"] == terminal_setup
        row_count = len(all_rows(db_session))

        retry = post_execute(client, auth, approval)

        # occupied approval slot — whatever the terminal state was
        assert retry.status_code == 409
        db_session.expire_all()
        assert len(all_rows(db_session)) == row_count


# --------------------------------------------------------------------------
# 6. Compensation chain — inherited facts + bidirectional audit relation
# --------------------------------------------------------------------------
class TestCompensationChain:
    @pytest.mark.parametrize("forward_setup", ["succeeded", "failed"])
    def test_full_compensation_chain(
        self, client, db_session, auth, app, forward_setup
    ):
        approval, *_ = seed_world(db_session)
        if forward_setup == "failed":
            app.dependency_overrides[get_response_executor] = lambda: FailOnceAdapter()
        exec_a = uuid.uuid4()
        assert post_execute(client, auth, approval, exec_a).status_code == 201

        exec_b = uuid.uuid4()
        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(exec_b),
                "compensates_execution_id": str(exec_a),
                "operator": "ops-2",
            },
            headers=auth,
        )

        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "compensation_succeeded"
        assert body["chain"] == ["compensation_requested", "compensation_succeeded"]

        rows_b = assert_chain_rows(
            db_session, exec_b,
            ["compensation_requested", "compensation_succeeded"],
        )
        # B inherits every identity fact SERVER-SIDE from A
        for row in rows_b:
            assert row.approval_id == approval.id
            assert row.action == SNAPSHOT_ACTION
            assert row.target == SNAPSHOT_TARGET
            assert row.compensates_execution_id == exec_a
            assert row.direction == "compensate"

        # Audit: A is unchanged, B is visible, both directions resolve
        db_session.expire_all()
        assert [r.decision for r in rows_for(db_session, exec_a)] == \
               ["requested", "dispatched",
                "succeeded" if forward_setup == "succeeded" else "failed"]
        body_a = detail(client, exec_a).json()
        body_b = detail(client, exec_b).json()
        assert body_b["history"][0]["compensates_execution_id"] == str(exec_a)
        assert body_a["execution_id"] == str(exec_a)
        # the list shows BOTH chains under the same approval
        listing = client.get(f"{EXECUTE}?approval_id={approval.id}").json()
        assert {item["execution_id"] for item in listing["items"]} == \
               {str(exec_a), str(exec_b)}
        comp_entry = next(i for i in listing["items"] if i["execution_id"] == str(exec_b))
        assert comp_entry["derived_state"] == "compensation_succeeded"

    def test_compensation_of_compensation_refused(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        exec_a = uuid.uuid4()
        assert post_execute(client, auth, approval, exec_a).status_code == 201
        exec_b = uuid.uuid4()
        assert client.post(
            COMPENSATE,
            json={"execution_id": str(exec_b),
                  "compensates_execution_id": str(exec_a),
                  "operator": "ops-2"},
            headers=auth,
        ).status_code == 201

        # undoing an undo is not part of the frozen state machine
        response = client.post(
            COMPENSATE,
            json={"execution_id": str(uuid.uuid4()),
                  "compensates_execution_id": str(exec_b),
                  "operator": "ops-2"},
            headers=auth,
        )
        assert response.status_code == 409
        db_session.expire_all()
        assert len(all_rows(db_session)) == 5  # 3 forward + 2 compensation

    def test_double_compensation_refused(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        exec_a = uuid.uuid4()
        assert post_execute(client, auth, approval, exec_a).status_code == 201
        first = client.post(
            COMPENSATE,
            json={"execution_id": str(uuid.uuid4()),
                  "compensates_execution_id": str(exec_a),
                  "operator": "ops-2"},
            headers=auth,
        )
        assert first.status_code == 201

        second = client.post(
            COMPENSATE,
            json={"execution_id": str(uuid.uuid4()),
                  "compensates_execution_id": str(exec_a),
                  "operator": "ops-2"},
            headers=auth,
        )
        assert second.status_code == 409
        db_session.expire_all()
        assert len(all_rows(db_session)) == 5

    def test_compensation_request_smuggled_approval_refused(
        self, client, db_session, auth
    ):
        approval, *_ = seed_world(db_session)
        exec_a = uuid.uuid4()
        assert post_execute(client, auth, approval, exec_a).status_code == 201

        response = client.post(
            COMPENSATE,
            json={"execution_id": str(uuid.uuid4()),
                  "compensates_execution_id": str(exec_a),
                  "operator": "ops-2",
                  "approval_id": str(uuid.uuid4())},  # smuggled — absent by design
            headers=auth,
        )
        assert response.status_code == 422
        db_session.expire_all()
        assert len(all_rows(db_session)) == 3


# --------------------------------------------------------------------------
# 7. Phase 2 invariance — execution produces execution_log ONLY
# --------------------------------------------------------------------------
class TestPhase2Invariance:
    @pytest.mark.parametrize("journey", ["succeeded", "failed", "compensated"])
    def test_phase2_facts_byte_identical(self, client, db_session, auth, app, journey):
        approval, risk, incident, recommendation = seed_world(db_session)
        if journey == "failed":
            app.dependency_overrides[get_response_executor] = (
                lambda: MockExecutor(fail_with="adapter_error")
            )
        before = phase2_snapshot(db_session, approval, risk, incident, recommendation)

        exec_a = uuid.uuid4()
        assert post_execute(client, auth, approval, exec_a).status_code == 201
        if journey == "compensated":
            assert client.post(
                COMPENSATE,
                json={"execution_id": str(uuid.uuid4()),
                      "compensates_execution_id": str(exec_a),
                      "operator": "ops-2"},
                headers=auth,
            ).status_code == 201

        after = phase2_snapshot(db_session, approval, risk, incident, recommendation)
        assert after == before
        # and the ONLY new table touched is execution_log
        db_session.expire_all()
        assert len(all_rows(db_session)) == (5 if journey == "compensated" else 3)


# --------------------------------------------------------------------------
# 8. HTTP / DB consistency — HTTP error != execution fact; 201 = fact
# --------------------------------------------------------------------------
class TestHttpDbConsistency:
    def test_401_writes_zero_rows(self, client, db_session):
        approval, *_ = seed_world(db_session)
        response = client.post(EXECUTE, json=execute_body(approval))
        assert response.status_code == 401
        assert all_rows(db_session) == []

    def test_422_writes_zero_rows(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        response = post_execute(client, auth, approval, action="isolate_host")
        assert response.status_code == 422
        assert all_rows(db_session) == []

    def test_404_writes_zero_rows(self, client, db_session, auth):
        seed_world(db_session)
        response = client.post(
            EXECUTE,
            json={"execution_id": str(uuid.uuid4()),
                  "approval_id": str(uuid.uuid4()),
                  "operator": "ops-1"},
            headers=auth,
        )
        assert response.status_code == 404
        assert all_rows(db_session) == []

    def test_409_writes_no_new_chain(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        execution_id = uuid.uuid4()
        assert post_execute(client, auth, approval, execution_id).status_code == 201

        conflict = post_execute(client, auth, approval, execution_id)

        assert conflict.status_code == 409
        db_session.expire_all()
        assert len(all_rows(db_session)) == 3
        assert {row.execution_id for row in all_rows(db_session)} == {execution_id}

    @pytest.mark.parametrize("verdict", ["succeeded", "failed", "guard_rejected"])
    def test_201_always_persists_a_fact(self, client, db_session, auth, app, verdict):
        approval, *_ = seed_world(db_session)
        if verdict == "failed":
            app.dependency_overrides[get_response_executor] = (
                lambda: MockExecutor(fail_with="timeout")
            )
        elif verdict == "guard_rejected":
            approval.status = "rejected"
            db_session.commit()
        execution_id = uuid.uuid4()

        response = post_execute(client, auth, approval, execution_id)

        assert response.status_code == 201
        assert response.json()["derived_state"] == verdict
        db_session.expire_all()
        rows = rows_for(db_session, execution_id)
        assert len(rows) > 0
        # the persisted terminal decision IS the advertised derived state
        assert rows[-1].decision == verdict
        assert detail(client, execution_id).json()["derived_state"] == verdict


# --------------------------------------------------------------------------
# Security attack special — fact smuggling never enters an execution fact
# --------------------------------------------------------------------------
class TestFactSmugglingAttacks:
    @pytest.mark.parametrize("field,value", [
        ("action", "isolate_host"),
        ("target", "10.66.0.1"),
        ("status", "succeeded"),
        ("direction", "compensate"),
        ("detail", {"classification": "timeout"}),
        ("created_at", "2020-01-01T00:00:00"),
    ])
    def test_smuggled_field_422_zero_rows(
        self, client, db_session, auth, field, value
    ):
        approval, *_ = seed_world(db_session)
        response = post_execute(client, auth, approval, **{field: value})
        assert response.status_code == 422
        assert all_rows(db_session) == []

    def test_tampered_approval_id_404_zero_rows(self, client, db_session, auth):
        approval, *_ = seed_world(db_session)
        body = execute_body(approval)
        body["approval_id"] = str(uuid.uuid4())  # points nowhere
        response = client.post(EXECUTE, json=body, headers=auth)
        assert response.status_code == 404
        assert all_rows(db_session) == []

    def test_smuggled_action_never_reaches_even_a_rejected_row(
        self, client, db_session, auth
    ):
        """Defense in depth: even with a rejected approval (the
        guard_rejected path writes rows), a smuggled action dies at the
        schema boundary first — zero rows, not a polluted fact."""
        approval, *_ = seed_world(db_session, status="rejected")
        response = post_execute(client, auth, approval, action="disable_account")
        assert response.status_code == 422
        assert all_rows(db_session) == []
