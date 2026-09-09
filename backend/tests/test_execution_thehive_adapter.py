"""Phase 3.2.5 — TheHive Adapter regression.

Locks the complete offline chain:

    API -> Service -> Guard -> TheHiveExecutor -> (stubbed) TheHive
    Case API -> case creation -> ExecutionOutcome -> D9 protocol
    parser -> execution_log

Frozen responsibility (3.2.5 adjudication, E1): TheHive is a Case
Management / Investigation provider ONLY — the adapter turns ONE
approved escalate_to_incident decision into ONE TheHive case, after
which human investigators take over. It NEVER executes endpoint
responses (Wazuh), NEVER triggers workflows (Shuffle), NEVER modifies
risk scores / approvals / incidents, and it NEVER compensates: the case
lifecycle belongs to the investigation and cases are never auto-closed.

    SentinelFlow decision -> TheHive case creation -> human
    investigation. NOT: SentinelFlow -> TheHive -> automatic
    investigation / automatic closure.

Request -> response -> decision -> execution_log. No polling, no async
callback, no task queue, no retry — the suite is deliberately NOT a
copy of 3.2.3/3.2.4: case creation semantics replace command semantics.

Discipline battery:
- succeeded requires 200/201 + a STRING resource reference (_id/id — the
  TheHive 4.1.24-1 v0 OutputCase; caseId is the Int human case NUMBER,
  kept for audit only and NEVER the reference). A creation without a valid
  string _id/id is a protocol lie -> ExecutorOutcomeViolation -> D9;
- 202 -> failed adapter_error (no waiting state — 3.1 froze "no
  asynchronous execution facts");
- 409 -> failed fail-closed ALWAYS: TheHive v0 case creation has no
  certified idempotency / duplicate-recovery contract (CaseSrv.create
  auto-assigns the next case number), so a conflict — duplicate marker,
  foreign execution_id, different event or none — is never claimed as
  success (M1 §4);
- classification table: 401/403/404/500 adapter_error, 502/503/504
  adapter_unavailable, timeout timeout, connection errors
  adapter_unavailable;
- supports_compensation is False for EVERY action (guard G4 refuses
  upstream; compensate itself raises);
- ZERO automatic retry (E5): transport invoked exactly once;
- secret five-check with sentinel ``sentinel-thehive-secret-test``:
  request body / URL / detail / exception / logger — everything stays
  ***; the key rides ONLY in the Authorization header.

Default run: REAL EXTERNAL NETWORK = 0 — every HTTP exchange goes
through an injected transport double. The ONE test touching a real
TheHive instance carries @pytest.mark.external and is DESELECTED unless
the run opts in with `-m external`.
"""
import http.client
import json
import logging
import urllib.error
import urllib.request
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import Settings, settings
from app.core.database import Base
from app.models import DispatchAttempt
from app.services.executions import (
    THEHIVE_ACTIONS,
    ExecutorConfigError,
    ExecutionDispatch,
    TheHiveExecutor,
    create_executor,
)
from app.services.executions.durable_dispatch import DurableDispatchAttemptStore
from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.service import compensate_response, execute_response

# M4-G §2: these service-chain tests drive the REAL durable path — a RECOGNIZED
# adapter (thehive) with store=None is now refused before dispatch by the
# fail-closed gate. They inject the shared no-DB recording store double (a real
# independent-commit store cannot interleave with the in-memory StaticPool
# harness; file-backed durability lives in test_dispatch_attempt_durability.py).
from tests.test_dispatch_durable_integration import FakeStore

# User-specified sentinel key for the 3.2.5 five-check battery.
FAKE_SECRET = "sentinel-thehive-secret-test"

ESCALATE = "escalate_to_incident"
TARGET = "INC-2026-0142"


class _StubResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        pass


def _http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="http://stub/api/case",
        code=status,
        msg="stub",
        hdrs=None,
        fp=_StubResponse(status, body),
    )


class StubTransport:
    """Injected transport double — records every outbound request and
    plays back a scripted response (or raises a scripted exception)."""

    def __init__(self, *, status=200, body=None, payload=None, exc=None):
        if body is None and payload is not None:
            body = json.dumps(payload).encode("utf-8")
        self._status = status
        self._body = body or b""
        self._exc = exc
        self.calls: list[dict] = []

    def __call__(self, request, timeout=None):
        self.calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": {k.lower(): v for k, v in request.header_items()},
                "body": json.loads(request.data.decode("utf-8")),
                "timeout": timeout,
            }
        )
        if self._exc is not None:
            raise self._exc
        if self._status >= 400:
            raise _http_error(self._status, self._body)
        return _StubResponse(self._status, self._body)

    @property
    def last(self) -> dict:
        return self.calls[-1]


class _InterruptedReadResponse:
    """M4-F §3: a response whose BODY read is INTERRUPTED mid-stream. The
    request was already SENT (the case MAY exist) but the answer is lost — the
    exact "emitted but abandoned" uncertainty the durable attempt survives."""

    def __init__(self, exc, status=200):
        self.status = status
        self._exc = exc

    def read(self):
        raise self._exc

    def close(self) -> None:
        pass


class InterruptedReadTransport:
    """Injected transport that returns a response whose ``read()`` raises."""

    def __init__(self, exc, *, status=200):
        self._exc = exc
        self._status = status
        self.calls: list[str] = []

    def __call__(self, request, timeout=None):
        self.calls.append(request.full_url)
        return _InterruptedReadResponse(self._exc, self._status)


def _creds() -> AdapterCredentials:
    return AdapterCredentials(
        adapter="thehive", base_url="http://stub", api_key=FAKE_SECRET
    )


def _executor(transport, **kwargs) -> TheHiveExecutor:
    return TheHiveExecutor(
        _creds(), timeout=kwargs.pop("timeout", 1.0), transport=transport, **kwargs
    )


def _dispatch(target=TARGET, **overrides) -> ExecutionDispatch:
    payload = {
        "execution_id": uuid.uuid4(),
        "action": ESCALATE,
        "target": target,
        "approval_id": uuid.uuid4(),
    }
    payload.update(overrides)
    return ExecutionDispatch(**payload)


def _thehive_settings(**overrides) -> Settings:
    base = {
        "EXECUTION_ADAPTER": "thehive",
        "THEHIVE_BASE_URL": "http://stub",
        "THEHIVE_API_KEY": FAKE_SECRET,
    }
    base.update(overrides)
    return Settings(**base)


def _success_payload(case_id="case-1", *, case_number=1) -> dict:
    """A TheHive 4.1.24-1 v0 OutputCase success body (dto/v0/Case.scala).
    The real response emits "_id"/"id" — BOTH the STRING EntityId and the
    reconcilable resource reference — and "caseId", the Int human case
    NUMBER. It NEVER emits "case_id": that is SentinelFlow's internal
    reconcile key, which the adapter populates FROM "_id"."""
    return {"_id": case_id, "id": case_id, "caseId": case_number}


# --------------------------------------------------------------------------
# 1. Architecture (registry / name / supports / compensation policy)
# --------------------------------------------------------------------------
class TestArchitecture:
    def test_registry_builds_thehive_executor(self):
        executor = create_executor(_thehive_settings())
        assert isinstance(executor, TheHiveExecutor)

    def test_name_is_thehive_and_contract_is_response_executor(self):
        from app.services.executions.base import ResponseExecutor

        executor = _executor(StubTransport())
        assert executor.name == "thehive"
        assert isinstance(executor, ResponseExecutor)

    def test_supports_exactly_the_frozen_one(self):
        executor = _executor(StubTransport())
        assert THEHIVE_ACTIONS == frozenset({ESCALATE})
        assert executor.supports(ESCALATE) is True

    @pytest.mark.parametrize(
        "action",
        [
            "isolate_host",
            "disable_account",
            "block_source_ip",
            "trigger_workflow",
            "modify_risk_score",
            "close_incident",
            "monitor_only",
            "hunt_related_activity",
        ],
    )
    def test_every_other_action_stays_refused(self, action):
        # TheHive is a case provider: endpoint responses belong to Wazuh,
        # workflows to Shuffle, risk/closure to SentinelFlow internals,
        # hunt/monitor to the analysis layer.
        assert _executor(StubTransport()).supports(action) is False

    @pytest.mark.parametrize(
        "action",
        [
            ESCALATE,
            "isolate_host",
            "disable_account",
            "block_source_ip",
            "monitor_only",
        ],
    )
    def test_supports_compensation_false_for_every_action(self, action):
        # Frozen policy: TheHive never auto-closes cases — the case
        # lifecycle belongs to human investigation.
        assert _executor(StubTransport()).supports_compensation(action) is False

    def test_compensate_raises_even_when_guard_is_bypassed(self):
        with pytest.raises(ValueError, match="no compensation"):
            _executor(StubTransport()).compensate(_dispatch())

    def test_missing_credentials_refused_fail_closed(self):
        with pytest.raises(
            ExecutorConfigError, match="missing required configuration"
        ):
            create_executor(Settings(EXECUTION_ADAPTER="thehive"))

    def test_base_url_shape_gate_rejects_secret_in_url(self):
        with pytest.raises(ExecutorConfigError):
            create_executor(
                _thehive_settings(THEHIVE_BASE_URL=f"https://hive?token={FAKE_SECRET}")
            )

    def test_wrong_adapter_credentials_rejected(self):
        with pytest.raises(ExecutorConfigError, match="credentials for adapter"):
            TheHiveExecutor(
                AdapterCredentials("wazuh", "http://stub", api_key=FAKE_SECRET)
            )

    def test_timeout_must_be_positive(self):
        with pytest.raises(ExecutorConfigError, match="positive"):
            TheHiveExecutor(_creds(), timeout=0)


# --------------------------------------------------------------------------
# 2. HTTP contract (endpoint / body mapping / auth surface / timeout)
# --------------------------------------------------------------------------
class TestHttpContract:
    def test_url_is_the_fixed_case_endpoint(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        assert stub.last["url"] == "http://stub/api/case"

    def test_target_never_rides_the_url(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch(target="weird/../case"))
        assert TARGET not in stub.last["url"]
        assert stub.last["url"].endswith("/api/case")

    def test_method_is_post(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        assert stub.last["method"] == "POST"

    def test_body_matches_frozen_contract_exactly(self):
        # M2 §4: the body carries ONLY v0 InputCase-declared fields
        # (dto/v0/Case.scala:8). The correlation moved INTO tags (a declared
        # Set[String], persisted by CaseSrv.create + echoed in OutputCase);
        # severity is the Int 3 (High), never the string "high" (severity is
        # Option[Int] -> a string is a 400). Undeclared top-level keys are
        # silently dropped by FieldsParser, so none may be sent.
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch()
        _executor(stub).execute(dispatch)
        body = stub.last["body"]
        assert set(body.keys()) == {"title", "description", "severity", "tags"}
        assert body["title"] == f"SentinelFlow escalation: {TARGET}"
        assert body["severity"] == 3
        assert isinstance(body["severity"], int) and not isinstance(
            body["severity"], bool
        )
        assert set(body["tags"]) == {
            "sentinelflow",
            f"sentinelflow:execution:{dispatch.execution_id}",
            f"sentinelflow:approval:{dispatch.approval_id}",
        }
        assert isinstance(body["description"], str) and body["description"]

    def test_body_field_mapping_rules(self):
        # SentinelFlow execution facts -> TheHive case fields (M2 §4):
        # target -> title; severity -> Int 3 (High); execution_id +
        # approval_id + provenance -> tags (the ONLY authenticated,
        # persisted, read-back channel — undeclared top-level keys are
        # silently dropped by FieldsParser and must never be relied on).
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch(target="INC-77")
        _executor(stub).execute(dispatch)
        body = stub.last["body"]
        assert body["title"].startswith("SentinelFlow escalation: INC-77")
        assert body["severity"] == 3
        assert f"sentinelflow:execution:{dispatch.execution_id}" in body["tags"]
        assert f"sentinelflow:approval:{dispatch.approval_id}" in body["tags"]
        assert "sentinelflow" in body["tags"]
        assert body["description"]
        # The M1 undeclared top-level keys are GONE — FieldsParser dropped
        # them silently, so they were never persisted; sending them was a
        # silent-correlation-loss bug (M2 §4).
        assert "sentinelflow_execution_id" not in body
        assert "source" not in body
        assert "approval_id" not in body

    def test_correlation_tags_use_the_canonical_write_side_helpers(self):
        # The tags are produced by the SAME helpers the G5 read adapter
        # imports (single source of truth). A drift between the written and
        # re-verified correlation string would break independent read-back
        # verification, so lock the exact contract at the write side.
        from app.services.executions.thehive import (
            sentinelflow_approval_tag,
            sentinelflow_execution_tag,
        )

        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch()
        _executor(stub).execute(dispatch)
        tags = set(stub.last["body"]["tags"])
        assert sentinelflow_execution_tag(dispatch.execution_id) in tags
        assert sentinelflow_approval_tag(dispatch.approval_id) in tags

    def test_bearer_header_is_the_only_auth_surface(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        call = stub.last
        assert call["headers"]["authorization"] == f"Bearer {FAKE_SECRET}"
        assert FAKE_SECRET not in call["url"]
        assert FAKE_SECRET not in json.dumps(call["body"])

    def test_content_type_is_json(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        assert stub.last["headers"]["content-type"] == "application/json"

    def test_header_surface_is_exactly_two_keys(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        assert set(stub.last["headers"].keys()) == {"authorization", "content-type"}

    def test_timeout_is_passed_to_transport(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub, timeout=7.5).execute(_dispatch())
        assert stub.last["timeout"] == 7.5

    def test_registry_passes_thehive_timeout_setting(self):
        executor = create_executor(
            _thehive_settings(THEHIVE_TIMEOUT_SECONDS=12.5)
        )
        assert executor._timeout == 12.5

    def test_settings_default_timeout_is_30s(self):
        assert Settings().THEHIVE_TIMEOUT_SECONDS == 30.0

    def test_execution_id_never_rides_the_url(self):
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch()
        _executor(stub).execute(dispatch)
        assert str(dispatch.execution_id) not in stub.last["url"]


# --------------------------------------------------------------------------
# 3. Outcome matrix (status -> SentinelFlow decision)
# --------------------------------------------------------------------------
class TestOutcomeMatrix:
    @pytest.mark.parametrize("status", [200, 201])
    def test_created_case_is_succeeded(self, status):
        stub = StubTransport(
            status=status, payload=_success_payload("case-9", case_number=42)
        )
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "succeeded"
        # detail["case_id"] carries the STRING resource reference (_id) under
        # the frozen reconcile key; caseId (number) rides along for audit only.
        assert outcome.detail == {
            "provider": "thehive",
            "case_id": "case-9",
            "case_number": 42,
        }
        assert outcome.raw_response == {
            "_id": "case-9",
            "id": "case-9",
            "caseId": 42,
        }

    def test_202_is_failed_adapter_error_no_waiting_state(self):
        stub = StubTransport(status=202, payload={"accepted": True})
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_client_and_server_errors_are_adapter_error(self, status):
        stub = StubTransport(status=status, body=b'{"error": "boom"}')
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        # Failure details never carry the upstream body.
        assert "boom" not in json.dumps(outcome.detail)

    @pytest.mark.parametrize("status", [502, 503, 504])
    def test_upstream_unavailable_is_adapter_unavailable(self, status):
        stub = StubTransport(status=status, body=b"")
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_unavailable"

    def test_timeout_is_classified_timeout(self):
        stub = StubTransport(exc=TimeoutError())
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "timeout"

    @pytest.mark.parametrize("exc", [urllib.error.URLError("dns"), OSError("conn")])
    def test_connection_errors_are_adapter_unavailable(self, exc):
        stub = StubTransport(exc=exc)
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_unavailable"

    def test_unexpected_2xx_status_is_adapter_error(self):
        stub = StubTransport(status=204, body=b"")
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    def test_unsupported_action_raises_before_any_outbound_call(self):
        stub = StubTransport(payload=_success_payload())
        with pytest.raises(ValueError, match="does not support"):
            _executor(stub).execute(_dispatch(action="isolate_host"))
        assert stub.calls == []


# --------------------------------------------------------------------------
# 3b. M4-F §3 — response READ interruption (the request was SENT, the body was
#     lost): fail closed, NEVER infer success/failure of the external effect,
#     ZERO auto-retry; the committed pre-dispatch attempt survives for MANUAL
#     reconciliation (paired with §1 in TestDurableAttemptSurvivesFailures).
# --------------------------------------------------------------------------
class TestResponseReadInterruption:
    def test_incomplete_read_is_fail_closed_never_success(self):
        transport = InterruptedReadTransport(http.client.IncompleteRead(b""))
        outcome = _executor(transport).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_unavailable"
        assert len(transport.calls) == 1  # ZERO auto-retry

    def test_connection_reset_mid_body_is_fail_closed(self):
        transport = InterruptedReadTransport(ConnectionResetError("reset"))
        outcome = _executor(transport).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_unavailable"
        assert len(transport.calls) == 1

    def test_read_timeout_is_classified_timeout(self):
        transport = InterruptedReadTransport(TimeoutError())
        outcome = _executor(transport).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "timeout"
        assert len(transport.calls) == 1

    def test_a_secret_in_a_read_interruption_error_is_redacted(self, monkeypatch):
        sentinel = "SUPER_SECRET_WRITE_KEY_0123456789"
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", sentinel)
        transport = InterruptedReadTransport(
            OSError(f"connection reset while posting {sentinel}")
        )
        outcome = _executor(transport).execute(_dispatch())
        assert outcome.status == "failed"
        assert sentinel not in json.dumps(outcome.detail)


# --------------------------------------------------------------------------
# 4. Protocol violations (D9 — platform judges, adapter only raises)
# --------------------------------------------------------------------------
class TestProtocolViolation:
    @pytest.mark.parametrize(
        "payload",
        [
            {},  # empty answer
            {"success": True},  # success flag without a resource reference
            # ONLY the numeric case number — M1 §4: a lone caseId is NEVER a
            # string resource id and must NOT be accepted as the reference.
            {"caseId": 12},
            {"_id": "", "id": ""},  # empty string reference
            {"_id": None, "id": None},  # null reference
            {"_id": 123, "id": 123},  # illegal (non-string) reference
        ],
    )
    def test_success_without_string_resource_reference_is_a_violation(
        self, payload
    ):
        stub = StubTransport(payload=payload)
        with pytest.raises(
            ExecutorOutcomeViolation, match="resource reference"
        ):
            _executor(stub).execute(_dispatch())

    def test_non_object_body_is_a_violation(self):
        stub = StubTransport(body=json.dumps(["case-1"]).encode())
        with pytest.raises(ExecutorOutcomeViolation, match="non-object"):
            _executor(stub).execute(_dispatch())

    def test_non_json_body_is_a_violation(self):
        stub = StubTransport(body=b"not-json")
        with pytest.raises(ExecutorOutcomeViolation, match="non-JSON"):
            _executor(stub).execute(_dispatch())

    def test_violation_classification_is_platform_judged(self):
        stub = StubTransport(payload={"success": True})
        with pytest.raises(ExecutorOutcomeViolation) as exc_info:
            _executor(stub).execute(_dispatch())
        assert exc_info.value.classification == "protocol_violation"

    def test_202_with_case_id_still_fails(self):
        # Status beats body: "accepted" never becomes a success even
        # when the body already carries a case id.
        stub = StubTransport(status=202, payload=_success_payload())
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    def test_ambiguous_body_through_service_chain_lands_protocol_violation(
        self, db_session
    ):
        from tests.test_execution_service import seed_approved

        executor = _executor(StubTransport(payload={"success": True}))
        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            dispatch_attempt_store=FakeStore(),
        )
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "protocol_violation"


# --------------------------------------------------------------------------
# 5. Idempotency (409 semantics, execution_id contract)
# --------------------------------------------------------------------------
class TestIdempotency:
    @pytest.mark.parametrize(
        "body",
        [
            b'{"error": "case already exists"}',
            b'{"error": "duplicate case for execution"}',
        ],
    )
    def test_409_duplicate_marker_fails_closed_no_certified_idempotency(
        self, body
    ):
        # TheHive 4.1.24-1 v0 case creation has NO certified idempotency /
        # duplicate-recovery contract (CaseSrv.create auto-assigns the next
        # case number, never detects duplicates), so a 409 carries no
        # authoritative re-fetchable case reference. M1 §4: a 409 is NEVER
        # auto-success — a duplicate marker does not make it one.
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert "idempotent_duplicate" not in outcome.detail

    def test_409_with_same_execution_id_echo_still_fails_closed(self):
        # An echoed sentinelflow_execution_id in a 409 body is NOT a
        # certified TheHive case reference — no authoritative contract
        # recovers the EXISTING case's _id from a conflict, so this still
        # fails closed (M1 §4: no reliable recovery -> explicit error,
        # never auto-success).
        dispatch = _dispatch()
        body = json.dumps(
            {
                "error": "case already exists",
                "sentinelflow_execution_id": str(dispatch.execution_id),
            }
        ).encode()
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(dispatch)
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert "idempotent_duplicate" not in outcome.detail

    def test_duplicate_referencing_another_execution_id_fails(self):
        body = json.dumps(
            {
                "error": "case already exists",
                "execution_id": str(uuid.uuid4()),
            }
        ).encode()
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert "idempotent_duplicate" not in outcome.detail

    @pytest.mark.parametrize(
        "body",
        [
            b'{"error": "execution bound to a different incident"}',
            b'{"error": "execution bound to a different event"}',
        ],
    )
    def test_same_execution_different_event_fails_closed(self, body):
        # One execution_id must NEVER create more than one case.
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert "idempotent_duplicate" not in outcome.detail

    def test_409_without_any_marker_is_adapter_error(self):
        stub = StubTransport(status=409, body=b'{"error": "conflict"}')
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    def test_two_executions_two_outbound_calls(self):
        stub = StubTransport(payload=_success_payload())
        executor = _executor(stub)
        executor.execute(_dispatch())
        executor.execute(_dispatch())
        assert len(stub.calls) == 2

    def test_zero_retry_on_failure(self):
        stub = StubTransport(status=500, body=b"")
        _executor(stub).execute(_dispatch())
        assert len(stub.calls) == 1


# --------------------------------------------------------------------------
# 6. Secret boundary (five-check battery, sentinel key)
# --------------------------------------------------------------------------
class TestSecretBoundary:
    def test_secret_five_check_offline(self, caplog):
        stub = StubTransport(
            status=500, body=json.dumps({"error": FAKE_SECRET}).encode()
        )
        executor = _executor(stub)
        dispatch = _dispatch()
        outcome = executor.execute(dispatch)
        # 1. request body / 2. URL: secret rides ONLY in Authorization.
        assert FAKE_SECRET not in json.dumps(stub.last["body"])
        assert FAKE_SECRET not in stub.last["url"]
        assert stub.last["headers"]["authorization"] == f"Bearer {FAKE_SECRET}"
        # 3. detail: failure detail never carries the upstream body.
        assert FAKE_SECRET not in json.dumps(outcome.detail)
        # 4/5. exception + logger surfaces stay redacted (violation path).
        violating = _executor(StubTransport(payload={"error": FAKE_SECRET}))
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ExecutorOutcomeViolation) as exc_info:
                violating.execute(dispatch)
        assert FAKE_SECRET not in str(exc_info.value)
        assert FAKE_SECRET not in caplog.text

    def test_credentials_repr_masks_the_key(self):
        assert FAKE_SECRET not in repr(_creds())
        assert "***" in repr(_creds())

    def test_secret_never_lands_in_execution_log_detail(
        self, db_session, monkeypatch
    ):
        from tests.test_execution_service import seed_approved

        monkeypatch.setattr(settings, "THEHIVE_API_KEY", FAKE_SECRET)
        body = json.dumps(
            {"error": f"invalid credentials: {FAKE_SECRET}"}
        ).encode()
        executor = _executor(StubTransport(status=401, body=body))
        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            dispatch_attempt_store=FakeStore(),
        )
        db_session.commit()
        raw = "".join(str(row.detail) for row in result.rows)
        assert FAKE_SECRET not in raw
        assert result.final_decision == "failed"

    def test_config_errors_name_keys_never_values(self):
        with pytest.raises(ExecutorConfigError) as excinfo:
            create_executor(
                Settings(EXECUTION_ADAPTER="thehive", THEHIVE_API_KEY=FAKE_SECRET)
            )
        message = str(excinfo.value)
        assert FAKE_SECRET not in message
        assert "THEHIVE_BASE_URL" in message


# --------------------------------------------------------------------------
# 7. Security (API surface + forgery attempts)
# --------------------------------------------------------------------------
class TestSecurity:
    def test_api_target_mutation_is_refused_422(self, client, monkeypatch):
        from app.core.config import settings as global_settings

        monkeypatch.setattr(global_settings, "EXECUTION_TOKEN", FAKE_SECRET)
        response = client.post(
            "/api/v1/executions",
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(uuid.uuid4()),
                "operator": "ops-1",
                "target": "attacker-chosen-case",
            },
            headers={"Authorization": f"Bearer {FAKE_SECRET}"},
        )
        assert response.status_code == 422

    def test_dispatch_forgery_extra_fields_forbidden(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ExecutionDispatch(
                execution_id=uuid.uuid4(),
                action=ESCALATE,
                target=TARGET,
                approval_id=uuid.uuid4(),
                case_title="forged",
            )

    def test_token_injection_into_target_stays_inside_body_title(self):
        # The target only ever lands in the JSON-encoded title — never
        # in the URL, headers or query string.
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch(target="INC-1?token=evil")
        _executor(stub).execute(dispatch)
        assert "token=evil" not in stub.last["url"]
        assert "token=evil" not in json.dumps(stub.last["headers"])

    def test_secret_never_in_query_or_url_shape(self):
        stub = StubTransport(payload=_success_payload())
        _executor(stub).execute(_dispatch())
        assert "?" not in stub.last["url"]

    def test_thehive_module_imports_no_async_or_retry_machinery(self):
        import inspect

        import app.services.executions.thehive as module

        source = inspect.getsource(module)
        for banned in (
            "import threading",
            "import asyncio",
            "import queue",
            "from queue",
            "import requests",
            "import httpx",
        ):
            assert banned not in source, (
                f"thehive adapter must stay synchronous, found '{banned}'"
            )


# --------------------------------------------------------------------------
# 7b. M4-F §3 — no-redirect write transport (finding ②: the WRITE adapter must
#     refuse 3xx exactly like the READ adapter, M2-R §4, so the Authorization
#     Bearer key is NEVER forwarded to a cross-host redirect target and the real
#     request target stays the bound endpoint).
# --------------------------------------------------------------------------
class TestWriteNoRedirectCredentialLeak:
    def test_default_transport_is_not_bare_urlopen(self):
        # With NO injected transport the executor must NOT default to bare
        # ``urlopen`` (which follows a cross-host 3xx WITH the Bearer key). This
        # fails on the CURRENT code (``_transport is urllib.request.urlopen``).
        executor = TheHiveExecutor(_creds())
        assert executor._transport is not urllib.request.urlopen

    def test_default_opener_installs_the_no_redirect_handler(self):
        # The production write opener carries _NoRedirectHandler (default
        # verifying TLS handlers UNCHANGED — §3 forbids disabling TLS/URL checks).
        from app.services.executions.thehive import (
            _build_opener,
            _NoRedirectHandler,
        )

        opener = _build_opener()
        assert any(isinstance(h, _NoRedirectHandler) for h in opener.handlers)

    def test_redirect_request_returns_none_so_auth_is_never_forwarded(self):
        # Returning ``None`` makes urllib RAISE ``HTTPError`` for the 3xx instead
        # of re-issuing the POST (with the Bearer key) to another host; execute()
        # maps that to a fail-closed adapter_error, NEVER a cross-host leak.
        from app.services.executions.thehive import _NoRedirectHandler

        handler = _NoRedirectHandler()
        req = urllib.request.Request(
            "https://thehive.lab.local/api/case",
            headers={"Authorization": "Bearer WRITE_SECRET"},
            method="POST",
        )
        assert (
            handler.redirect_request(
                req,
                None,
                302,
                "Found",
                {"Location": "https://evil.example/steal"},
                "https://evil.example/steal",
            )
            is None
        )


# --------------------------------------------------------------------------
# 7c. M4-F §3 — target-binding consistency: the endpoint the durable binding
#     records and the target the executor ACTUALLY requests must be one and the
#     same, and a 3xx can never divert the write to an unbound host. These LOCK
#     the invariant the no-redirect opener (7b) makes robust; the base URL is a
#     CONFIG DECLARATION, never a certified instance/tenant identity (gate 5 stays
#     UNKNOWN).
# --------------------------------------------------------------------------
class TestWriteTargetBindingConsistency:
    def test_binding_endpoint_is_the_exact_request_origin(self):
        stub = StubTransport(payload=_success_payload())
        executor = _executor(stub)
        dispatch = _dispatch()
        facts = executor.dispatch_binding_facts(dispatch)
        executor.execute(dispatch)
        # The bound endpoint is the EXACT origin the POST targets — the request
        # URL is ``{endpoint}/api/case``, so the real target never diverges from
        # the durable binding.
        assert stub.last["url"] == facts["endpoint"] + "/api/case"
        assert stub.last["url"].startswith(facts["endpoint"])

    def test_binding_is_config_declaration_never_an_instance_identity(self):
        from app.services.executions.binding import VERSION_ASSERTION_CONFIG

        executor = _executor(StubTransport(payload=_success_payload()))
        facts = executor.dispatch_binding_facts(_dispatch())
        # §3: the version stays a config-declaration; instance/tenant stay None so
        # gate 5 STILL fails closed — a base URL is never passed off as an identity.
        assert facts["version_assertion_kind"] == VERSION_ASSERTION_CONFIG
        assert facts["target_instance"] is None
        assert facts["target_tenant"] is None

    def test_a_3xx_fails_closed_and_is_never_followed_to_another_host(self):
        # The no-redirect opener surfaces a 3xx as ``HTTPError`` (redirect_request
        # -> None); execute() maps it to a fail-closed adapter_error with ZERO
        # second call — the write is NEVER re-issued to the Location host, so the
        # target cannot diverge from the bound endpoint.
        stub = StubTransport(exc=_http_error(302, b""))
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert len(stub.calls) == 1


# --------------------------------------------------------------------------
# 8. End-to-end (full chain: Approval -> Guard -> Executor -> log)
# --------------------------------------------------------------------------
class TestEndToEnd:
    @staticmethod
    def _run(db_session, transport):
        from tests.test_execution_service import seed_approved

        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        return execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=_executor(transport),
            dispatch_attempt_store=FakeStore(),
        )

    def test_success_chain_writes_provider_thehive(self, db_session):
        result = self._run(
            db_session, StubTransport(status=201, payload=_success_payload("case-1"))
        )
        assert result.final_decision == "succeeded"
        assert result.chain == ("requested", "dispatched", "succeeded")
        # Platform appends raw_response — assert by subset.
        detail = result.rows[-1].detail
        assert detail["provider"] == "thehive"
        assert detail["case_id"] == "case-1"

    def test_timeout_chain_writes_failed_timeout(self, db_session):
        result = self._run(db_session, StubTransport(exc=TimeoutError()))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "timeout"

    def test_409_chain_writes_failed_no_certified_idempotency(self, db_session):
        result = self._run(
            db_session,
            StubTransport(status=409, body=b'{"error": "case already exists"}'),
        )
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "adapter_error"

    def test_foreign_execution_id_chain_writes_failed(self, db_session):
        body = json.dumps(
            {"error": "case already exists", "execution_id": str(uuid.uuid4())}
        ).encode()
        result = self._run(db_session, StubTransport(status=409, body=body))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "adapter_error"

    def test_guard_refuses_non_thehive_action_with_thehive_executor(
        self, db_session
    ):
        from tests.test_execution_service import seed_approved

        approval = seed_approved(
            db_session,
            recommendations=[{"action": "isolate_host", "target": "agent001",
                              "rationale": "lateral movement"}],
        )
        stub = StubTransport(payload=_success_payload())
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=_executor(stub),
        )
        assert result.final_decision == "guard_rejected"
        assert result.rows[-1].detail["code"] == "executor_unsupported"
        assert stub.calls == []

    def test_compensation_is_capability_refused_without_outbound(
        self, db_session
    ):
        from tests.test_execution_service import seed_approved

        stub = StubTransport(status=201, payload=_success_payload("case-2"))
        executor = _executor(stub)
        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            dispatch_attempt_store=FakeStore(),
        )
        assert forward.final_decision == "succeeded"
        compensation = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        # G4 refuses upstream: no second outbound call, capability miss.
        assert len(stub.calls) == 1
        assert compensation.final_decision == "compensation_failed"
        assert compensation.rows[-1].detail["classification"] == "capability_missing"

    def test_escalate_via_mock_executor_dry_run_chain(self, db_session):
        # The E1 expansion also works on the default adapter: mock
        # executes escalate, but never compensates it (E1 policy).
        from app.services.executions.mock import MockExecutor
        from tests.test_execution_service import seed_approved

        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert forward.final_decision == "succeeded"
        compensation = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=MockExecutor(),
        )
        assert compensation.final_decision == "compensation_failed"


# --------------------------------------------------------------------------
# 8b. M4-F §3 × §1 — EVERY TheHive failure classification preserves the
#     COMMITTED pre-dispatch attempt (real file-backed store, read back on an
#     INDEPENDENT connection), makes EXACTLY ONE external request (zero
#     auto-retry), and NEVER infers success from a lost/ambiguous answer.
# --------------------------------------------------------------------------
@pytest.fixture()
def durable_engine(tmp_path):
    """A FILE-backed engine (real, non-shared pool) for the durable store, so its
    independent commit is genuinely isolated from the in-memory caller session
    (constraint 2: no shared-connection artifact masks durability)."""
    db_path = tmp_path / "thehive_durable.db"
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


class TestDurableAttemptSurvivesFailures:
    @pytest.mark.parametrize(
        "transport_factory, classification",
        [
            (lambda: StubTransport(status=409, body=b'{"error":"exists"}'),
             "adapter_error"),
            (lambda: StubTransport(status=503, body=b""),
             "adapter_unavailable"),
            (lambda: StubTransport(exc=TimeoutError()), "timeout"),
            (lambda: InterruptedReadTransport(http.client.IncompleteRead(b"")),
             "adapter_unavailable"),
            (lambda: StubTransport(status=201, body=b"<html>not json</html>"),
             "protocol_violation"),
            (lambda: StubTransport(status=201, payload={"caseId": 42}),
             "protocol_violation"),
        ],
        ids=["409", "5xx", "timeout", "read-interrupted", "non-json",
             "missing-resource-id"],
    )
    def test_every_failure_preserves_the_committed_attempt_no_retry(
        self, db_session, durable_engine, transport_factory, classification
    ):
        from tests.test_execution_service import seed_approved

        transport = transport_factory()
        approval = seed_approved(
            db_session,
            recommendations=[{"action": ESCALATE, "target": TARGET,
                              "rationale": "confirmed compromise"}],
        )
        store = DurableDispatchAttemptStore(durable_engine)
        execution_id = uuid.uuid4()
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=execution_id,
            operator="ops-1",
            executor=TheHiveExecutor(_creds(), timeout=1.0, transport=transport),
            dispatch_attempt_store=store,
        )
        # NEVER a success inferred from a lost / ambiguous answer.
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == classification
        # ZERO auto-retry: exactly ONE external request was made.
        assert len(transport.calls) == 1
        # The COMMITTED pre-dispatch attempt SURVIVES on an independent connection
        # (§1) — the external effect is uncertain, so it stays a MANUAL
        # reconciliation candidate, never auto-retried or auto-resolved.
        with Session(durable_engine) as session:
            rows = session.scalars(
                select(DispatchAttempt).where(
                    DispatchAttempt.execution_id == execution_id
                )
            ).all()
        assert len(rows) == 1
        assert rows[0].execution_id == execution_id


# --------------------------------------------------------------------------
# 9. External (OPT-IN only — default run: 0 external requests)
# --------------------------------------------------------------------------
class TestRealTheHive:
    @pytest.mark.external
    def test_real_thehive_case_creation(self):
        import os

        base_url = os.environ.get("THEHIVE_BASE_URL", "")
        api_key = os.environ.get("THEHIVE_API_KEY", "")
        if not base_url or not api_key:
            pytest.skip("THEHIVE_BASE_URL / THEHIVE_API_KEY not configured")
        executor = TheHiveExecutor(
            AdapterCredentials("thehive", base_url.rstrip("/"), api_key=api_key)
        )
        outcome = executor.execute(_dispatch(target="sentinelflow-external-test"))
        assert outcome.status in ("succeeded", "failed")
