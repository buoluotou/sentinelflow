"""Phase 3.1.7: Execution API tests — the first HTTP surface of the
response-execution layer.

Locks the frozen HTTP contract:

    HTTP Auth -> Request Schema -> Service

Coverage map (acceptance gate):
- 401 x3 write-path shapes (missing / wrong / malformed) + fail-closed
  unconfigured token; 401 writes ZERO execution_log rows
- 422 fact-smuggling: action / target / direction / detail / created_at
  / status on execute, approval_id on compensate, missing operator
- 404 unknown approval / unknown & malformed execution ids
- 409 duplicate replay + same-execution_id-different-approval attack
- 201 semantics: succeeded / failed / guard_rejected all 201
- Compensation: 201 compensation_succeeded, server-inherited facts,
  409 double / non-terminal / compensation-of-compensation,
  capability miss -> compensation_failed (classification distinguishes)
- GET list/detail: no token, derive_execution_state() drives every
  derived_state, detail history created_at ASC
- Token never appears in any response, exception string or audit row
- commit boundary lives at the API layer (rollback-after-201 proof)

No React, no real external systems — executor overrides are local stubs.
"""
import inspect
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.api.v1 import response_execution as api_module
from app.api.v1.response_execution import get_response_executor
from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
)

EXECUTE = "/api/v1/executions"
COMPENSATE = "/api/v1/executions/compensate"
TOKEN = "exec-secret-test-token-0001"


@pytest.fixture()
def auth(monkeypatch):
    """Configure the shared secret and return the valid header."""
    monkeypatch.setattr(settings, "EXECUTION_TOKEN", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def app():
    """The FastAPI application — used to override the executor seam.
    The client fixture clears all dependency overrides on teardown."""
    from app.main import app as fastapi_app

    return fastapi_app


# --------------------------------------------------------------------------
# Seeding + executor stubs
# --------------------------------------------------------------------------
def seed_approval(db_session, *, status="approved") -> AIResponseApproval:
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
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status=status,
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


class FailingExecutor:
    """Deterministic adapter failure (classification: timeout)."""

    name = "failing-stub"

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return True

    def execute(self, dispatch):
        return {
            "status": "failed",
            "detail": {"classification": "timeout", "message": "stub timeout"},
            "raw_response": {"stub": True},
        }

    def compensate(self, dispatch):
        return {"status": "succeeded", "detail": {}, "raw_response": {}}


class ExecuteOnlyStub:
    """Executes everything but supports NO compensation — drives the
    capability-missing -> compensation_failed path at the API layer."""

    name = "execute-only-stub"

    def supports(self, action):
        return True

    def supports_compensation(self, action):
        return False

    def execute(self, dispatch):
        return {"status": "succeeded", "detail": {}, "raw_response": {}}

    def compensate(self, dispatch):
        raise AssertionError("compensate must never be reached")


def override_executor(app, stub):
    app.dependency_overrides[get_response_executor] = lambda: stub


def execute_body(approval, execution_id=None, **overrides):
    body = {
        "execution_id": str(execution_id or uuid.uuid4()),
        "approval_id": str(approval.id),
        "operator": "ops-1",
    }
    body.update(overrides)
    return body


def all_rows(db_session):
    return list(db_session.scalars(select(ExecutionLog)))


def post_execute(client, auth, approval, execution_id=None, **overrides):
    return client.post(EXECUTE, json=execute_body(approval, execution_id, **overrides), headers=auth)


# --------------------------------------------------------------------------
# 401 — write-path auth (zero rows, uniform status, fail-closed)
# --------------------------------------------------------------------------
class TestWritePathAuth:
    def test_missing_token_401_and_zero_rows(self, client, db_session, auth):
        approval = seed_approval(db_session)
        response = client.post(EXECUTE, json=execute_body(approval))  # no header

        assert response.status_code == 401
        assert all_rows(db_session) == []

    def test_wrong_token_401_and_zero_rows(self, client, db_session, auth):
        approval = seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json=execute_body(approval),
            headers={"Authorization": "Bearer wrong-token"},
        )

        assert response.status_code == 401
        assert all_rows(db_session) == []

    def test_malformed_scheme_401(self, client, db_session, auth):
        approval = seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json=execute_body(approval),
            headers={"Authorization": f"Token {TOKEN}"},
        )

        assert response.status_code == 401
        assert all_rows(db_session) == []

    def test_unconfigured_token_fail_closed(self, client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "")
        approval = seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json=execute_body(approval),
            headers={"Authorization": "Bearer anything"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Execution credentials not configured"
        assert all_rows(db_session) == []

    def test_compensate_requires_token_too(self, client, db_session, auth):
        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(uuid.uuid4()),
                "operator": "ops-1",
            },
        )
        assert response.status_code == 401


# --------------------------------------------------------------------------
# 422 — schema boundary: every smuggling attempt dies before the Service
# --------------------------------------------------------------------------
class TestSchemaSmuggling:
    @pytest.mark.parametrize(
        "smuggled_field",
        ["action", "target", "direction", "detail", "created_at", "status"],
    )
    def test_execute_rejects_smuggled_facts(self, client, db_session, auth, smuggled_field):
        approval = seed_approval(db_session)
        body = execute_body(approval, **{smuggled_field: "evil-value"})

        response = client.post(EXECUTE, json=body, headers=auth)

        assert response.status_code == 422
        assert all_rows(db_session) == []

    def test_execute_rejects_missing_operator(self, client, db_session, auth):
        approval = seed_approval(db_session)
        body = execute_body(approval)
        del body["operator"]

        response = client.post(EXECUTE, json=body, headers=auth)

        assert response.status_code == 422
        assert all_rows(db_session) == []

    def test_execute_rejects_malformed_approval_id(self, client, db_session, auth):
        approval = seed_approval(db_session)
        body = execute_body(approval)
        body["approval_id"] = "not-a-uuid"

        response = client.post(EXECUTE, json=body, headers=auth)

        assert response.status_code == 422
        assert all_rows(db_session) == []

    def test_compensate_rejects_client_approval_id(self, client, db_session, auth):
        """approval_id is server-inherited (D11); a client-supplied one is
        a smuggling attempt -> 422 via extra='forbid'."""
        approval = seed_approval(db_session)
        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(uuid.uuid4()),
                "operator": "ops-1",
                "approval_id": str(approval.id),
            },
            headers=auth,
        )
        assert response.status_code == 422
        assert all_rows(db_session) == []


# --------------------------------------------------------------------------
# POST /executions — the 201 semantics (fact formed, verdict varies)
# --------------------------------------------------------------------------
class TestExecuteEndpoint:
    def test_201_succeeded_full_chain(self, client, db_session, auth):
        approval = seed_approval(db_session)
        execution_id = uuid.uuid4()

        response = post_execute(
            client, auth, approval, execution_id, comment="contain the brute force"
        )

        assert response.status_code == 201
        body = response.json()
        assert body["execution_id"] == str(execution_id)
        assert body["approval_id"] == str(approval.id)
        assert body["direction"] == "execute"
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]
        # action/target are SERVER snapshot facts, never client input
        assert body["action"] == "block_source_ip"
        assert body["target"] == "203.0.113.10"
        assert len(body["history"]) == 3
        assert body["history"][0]["detail"]["comment"] == "contain the brute force"
        # timestamps strictly increasing within the chain (frozen clause)
        stamps = [row["created_at"] for row in body["history"]]
        assert stamps == sorted(stamps) and len(set(stamps)) == 3
        assert len(all_rows(db_session)) == 3

    def test_201_guard_rejected_rejected_approval(self, client, db_session, auth):
        """Only approved + legal Intent + policy refusal produces the
        requested -> guard_rejected audit chain; still 201 (D13). The
        approval CHECK constraint only persists approved/rejected, so a
        REJECTED approval is the legal non-approved G2 trigger."""
        approval = seed_approval(db_session, status="rejected")

        response = post_execute(client, auth, approval)

        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "guard_rejected"
        assert body["chain"] == ["requested", "guard_rejected"]
        assert body["history"][-1]["detail"]["code"] == "approval_not_approved"

    def test_201_failed_adapter(self, client, db_session, auth, app):
        approval = seed_approval(db_session)
        override_executor(app, FailingExecutor())

        response = post_execute(client, auth, approval)

        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "failed"
        assert body["chain"] == ["requested", "dispatched", "failed"]
        assert body["history"][-1]["detail"]["classification"] == "timeout"

    def test_404_unknown_approval_zero_rows(self, client, db_session, auth):
        seed_approval(db_session)
        body = execute_body(seed_approval(db_session))
        body["approval_id"] = str(uuid.uuid4())

        response = client.post(EXECUTE, json=body, headers=auth)

        assert response.status_code == 404
        assert response.json()["detail"]["error"] == "ApprovalNotFound"
        assert all_rows(db_session) == []

    def test_409_duplicate_replay_first_facts_stand(self, client, db_session, auth):
        approval = seed_approval(db_session)
        execution_id = uuid.uuid4()
        first = post_execute(client, auth, approval, execution_id)
        assert first.status_code == 201

        replay = post_execute(client, auth, approval, execution_id)

        assert replay.status_code == 409
        rows = all_rows(db_session)
        assert len(rows) == 3  # the first chain stands untouched

    def test_409_same_execution_id_different_approval(self, client, db_session, auth):
        """Attack: bind execution_id X to approval A, then replay X with a
        different approval B -> 409, and the first facts never change."""
        approval_a = seed_approval(db_session)
        approval_b = seed_approval(db_session)
        execution_id = uuid.uuid4()
        first = post_execute(client, auth, approval_a, execution_id)
        assert first.status_code == 201

        attack = post_execute(client, auth, approval_b, execution_id)

        assert attack.status_code == 409
        assert attack.json()["detail"]["error"] == "ExecutionIdAlreadyBound"
        rows = all_rows(db_session)
        assert len(rows) == 3
        assert {str(row.approval_id) for row in rows} == {str(approval_a.id)}


# --------------------------------------------------------------------------
# POST /executions/compensate
# --------------------------------------------------------------------------
class TestCompensateEndpoint:
    def _execute_first(self, client, db_session, auth, approval):
        execution_id = uuid.uuid4()
        response = post_execute(client, auth, approval, execution_id)
        assert response.status_code == 201
        return execution_id

    def test_201_compensation_succeeded_inherits_facts(self, client, db_session, auth):
        approval = seed_approval(db_session)
        original_id = self._execute_first(client, db_session, auth, approval)
        compensation_id = uuid.uuid4()

        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(compensation_id),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )

        assert response.status_code == 201
        body = response.json()
        assert body["direction"] == "compensate"
        assert body["derived_state"] == "compensation_succeeded"
        assert body["chain"] == ["compensation_requested", "compensation_succeeded"]
        # server-side inheritance, never client input
        assert body["approval_id"] == str(approval.id)
        assert body["action"] == "block_source_ip"
        assert body["target"] == "203.0.113.10"
        assert body["history"][0]["compensates_execution_id"] == str(original_id)

    def test_404_unknown_original_execution(self, client, db_session, auth):
        seed_approval(db_session)
        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(uuid.uuid4()),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert response.status_code == 404
        assert response.json()["detail"]["error"] == "ExecutionNotFound"
        assert all_rows(db_session) == []

    def test_409_double_compensation(self, client, db_session, auth):
        approval = seed_approval(db_session)
        original_id = self._execute_first(client, db_session, auth, approval)
        first = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert first.status_code == 201

        second = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert second.status_code == 409
        assert second.json()["detail"]["error"] == "ExecutionAlreadyCompensated"

    def test_409_non_terminal_original(self, client, db_session, auth):
        """A guard_rejected chain never settled — nothing to undo."""
        approval = seed_approval(db_session, status="rejected")
        rejected = post_execute(client, auth, approval)
        assert rejected.status_code == 201
        original_id = rejected.json()["execution_id"]

        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": original_id,
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "OriginalExecutionNotTerminal"

    def test_409_compensation_of_compensation(self, client, db_session, auth):
        approval = seed_approval(db_session)
        original_id = self._execute_first(client, db_session, auth, approval)
        compensation_id = uuid.uuid4()
        first = client.post(
            COMPENSATE,
            json={
                "execution_id": str(compensation_id),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert first.status_code == 201

        undo_the_undo = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(compensation_id),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert undo_the_undo.status_code == 409
        assert undo_the_undo.json()["detail"]["error"] == "CompensationOfCompensation"

    def test_201_capability_missing_is_compensation_failed(self, client, db_session, auth, app):
        """Frozen semantics: capability miss terminates as
        compensation_failed, told apart via detail.classification."""
        approval = seed_approval(db_session)
        original_id = self._execute_first(client, db_session, auth, approval)
        override_executor(app, ExecuteOnlyStub())

        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(uuid.uuid4()),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )

        assert response.status_code == 201
        body = response.json()
        assert body["derived_state"] == "compensation_failed"
        last_detail = body["history"][-1]["detail"]
        assert last_detail["classification"] == "capability_missing"
        assert last_detail["code"] == "executor_unsupported"


# --------------------------------------------------------------------------
# GET — read-only audit views, no token
# --------------------------------------------------------------------------
class TestReadEndpoints:
    def test_list_empty(self, client, db_session, auth):
        seed_approval(db_session)
        response = client.get(EXECUTE)  # no Authorization header
        assert response.status_code == 200
        assert response.json() == {"total": 0, "page": 1, "size": 20, "items": []}

    def test_list_derives_state_per_execution(self, client, db_session, auth):
        approval_a = seed_approval(db_session)
        approval_b = seed_approval(db_session, status="rejected")
        ok_id = uuid.uuid4()
        assert post_execute(client, auth, approval_a, ok_id).status_code == 201
        rejected = post_execute(client, auth, approval_b)
        assert rejected.status_code == 201
        rejected_id = rejected.json()["execution_id"]

        response = client.get(EXECUTE)

        assert response.status_code == 200
        entries = {entry["execution_id"]: entry for entry in response.json()["items"]}
        assert entries[str(ok_id)]["derived_state"] == "succeeded"
        assert entries[str(ok_id)]["chain"] == ["requested", "dispatched", "succeeded"]
        assert entries[str(rejected_id)]["derived_state"] == "guard_rejected"
        assert entries[str(rejected_id)]["action"] == "block_source_ip"

    def test_list_shows_compensation_as_separate_entry(self, client, db_session, auth):
        approval = seed_approval(db_session)
        original_id = uuid.uuid4()
        assert post_execute(client, auth, approval, original_id).status_code == 201
        compensation_id = uuid.uuid4()
        response = client.post(
            COMPENSATE,
            json={
                "execution_id": str(compensation_id),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        )
        assert response.status_code == 201

        entries = client.get(EXECUTE).json()["items"]

        assert len(entries) == 2
        directions = {entry["execution_id"]: entry["direction"] for entry in entries}
        assert directions[str(original_id)] == "execute"
        assert directions[str(compensation_id)] == "compensate"

    def test_list_most_recent_activity_first(self, client, db_session, auth):
        """Design §10 frozen read order: the chain with the latest
        activity leads the page (the compensation settled last)."""
        approval = seed_approval(db_session)
        original_id = uuid.uuid4()
        assert post_execute(client, auth, approval, original_id).status_code == 201
        compensation_id = uuid.uuid4()
        assert client.post(
            COMPENSATE,
            json={
                "execution_id": str(compensation_id),
                "compensates_execution_id": str(original_id),
                "operator": "ops-2",
            },
            headers=auth,
        ).status_code == 201

        items = client.get(EXECUTE).json()["items"]

        assert [item["execution_id"] for item in items] == [
            str(compensation_id),
            str(original_id),
        ]

    def test_list_filters_status_direction_approval_id(self, client, db_session, auth):
        """Filters narrow the derived-state view server-side; they never
        re-derive anything (3.1.9 frozen query contract)."""
        approval_a = seed_approval(db_session)
        approval_b = seed_approval(db_session, status="rejected")
        ok_id = uuid.uuid4()
        assert post_execute(client, auth, approval_a, ok_id).status_code == 201
        rejected_id = post_execute(client, auth, approval_b).json()["execution_id"]

        failed_only = client.get(EXECUTE, params={"status": "succeeded"}).json()
        assert failed_only["total"] == 1
        assert failed_only["items"][0]["execution_id"] == str(ok_id)

        guard_only = client.get(EXECUTE, params={"status": "guard_rejected"}).json()
        assert [item["execution_id"] for item in guard_only["items"]] == [str(rejected_id)]

        by_approval = client.get(
            EXECUTE, params={"approval_id": str(approval_a.id)}
        ).json()
        assert by_approval["total"] == 1
        assert by_approval["items"][0]["approval_id"] == str(approval_a.id)

        by_direction = client.get(EXECUTE, params={"direction": "execute"}).json()
        assert by_direction["total"] == 2
        assert client.get(EXECUTE, params={"direction": "compensate"}).json()["total"] == 0

    def test_list_pagination_page_size(self, client, db_session, auth):
        for _ in range(3):
            assert post_execute(client, auth, seed_approval(db_session)).status_code == 201

        first = client.get(EXECUTE, params={"page": 1, "size": 2}).json()
        second = client.get(EXECUTE, params={"page": 2, "size": 2}).json()

        assert first["total"] == 3 and second["total"] == 3
        assert len(first["items"]) == 2 and len(second["items"]) == 1
        first_ids = {item["execution_id"] for item in first["items"]}
        second_ids = {item["execution_id"] for item in second["items"]}
        assert first_ids.isdisjoint(second_ids)
        assert client.get(EXECUTE, params={"page": 3, "size": 2}).json()["items"] == []

    @pytest.mark.parametrize(
        "params",
        [
            {"status": "exploded"},
            {"direction": "sideways"},
            {"approval_id": "not-a-uuid"},
            {"page": 0},
            {"size": 0},
            {"size": 101},
        ],
    )
    def test_list_invalid_filter_values_422(self, client, db_session, auth, params):
        seed_approval(db_session)
        assert client.get(EXECUTE, params=params).status_code == 422

    def test_detail_full_history_asc_no_token(self, client, db_session, auth):
        approval = seed_approval(db_session)
        execution_id = uuid.uuid4()
        assert post_execute(client, auth, approval, execution_id).status_code == 201

        response = client.get(f"{EXECUTE}/{execution_id}")  # no token

        assert response.status_code == 200
        body = response.json()
        assert body["derived_state"] == "succeeded"
        assert body["chain"] == ["requested", "dispatched", "succeeded"]
        assert [row["decision"] for row in body["history"]] == body["chain"]
        stamps = [row["created_at"] for row in body["history"]]
        assert stamps == sorted(stamps)

    def test_detail_404_unknown_execution(self, client, db_session, auth):
        seed_approval(db_session)
        response = client.get(f"{EXECUTE}/{uuid.uuid4()}")
        assert response.status_code == 404

    def test_detail_404_malformed_id(self, client, db_session, auth):
        seed_approval(db_session)
        response = client.get(f"{EXECUTE}/not-a-uuid")
        assert response.status_code == 404

    def test_list_uses_frozen_derive_function_not_a_reimplementation(self):
        """Source contract: derived state in the read endpoints comes from
        derive_execution_state(), never a local recompute."""
        source = inspect.getsource(api_module)
        assert source.count("derive_execution_state(") >= 2  # list + detail


# --------------------------------------------------------------------------
# Token security + commit boundary
# --------------------------------------------------------------------------
class TestTokenSecurityAndCommit:
    def test_token_never_appears_in_responses_or_audit(self, client, db_session, auth, app):
        approval = seed_approval(db_session)
        responses = [
            client.post(EXECUTE, json=execute_body(approval), headers={"Authorization": "Bearer wrong"}),
            post_execute(client, auth, approval),
            client.get(EXECUTE),
        ]
        executed_id = responses[1].json()["execution_id"]
        responses.append(client.get(f"{EXECUTE}/{executed_id}"))

        for response in responses:
            assert TOKEN not in response.text
        for row in all_rows(db_session):
            assert TOKEN not in str(row.detail)
            assert TOKEN != row.operator

    def test_api_commits_rows_survive_test_rollback(self, client, db_session, auth):
        """commit() boundary lives at the API layer: after 201 the rows
        are committed — a test-side rollback cannot erase them."""
        approval = seed_approval(db_session)
        response = post_execute(client, auth, approval)
        assert response.status_code == 201

        db_session.rollback()

        assert len(all_rows(db_session)) == 3

    def test_no_commit_on_conflict(self, client, db_session, auth):
        approval = seed_approval(db_session)
        execution_id = uuid.uuid4()
        assert post_execute(client, auth, approval, execution_id).status_code == 201

        replay = post_execute(client, auth, approval, execution_id)
        assert replay.status_code == 409
        db_session.rollback()
        assert len(all_rows(db_session)) == 3


# --------------------------------------------------------------------------
# Frozen clause (3.1.6 acceptance): high-water mark encapsulation
# --------------------------------------------------------------------------
class TestHighWaterMarkDiscipline:
    def test_append_never_accepts_client_created_at(self):
        """_append() is the ONLY stamping site: no created_at parameter,
        so no caller — today or future — can supply or roll back the
        audit clock."""
        from app.services.executions.service import _append

        assert "created_at" not in inspect.signature(_append).parameters

    def test_execute_and_compensate_never_stamp_their_own_rows(self):
        """Service entrypoints must route every row through _append() and
        never manufacture timestamps themselves."""
        from app.services.executions import service as service_module

        for entrypoint in ("execute_response", "compensate_response"):
            source = inspect.getsource(getattr(service_module, entrypoint))
            assert "created_at" not in source
