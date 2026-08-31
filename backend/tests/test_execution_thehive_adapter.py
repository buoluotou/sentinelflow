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
- succeeded requires 200/201 + case_id (a case creation without a case
  id is a protocol lie -> ExecutorOutcomeViolation -> D9);
- 202 -> failed adapter_error (no waiting state — 3.1 froze "no
  asynchronous execution facts");
- 409 duplicate -> succeeded idempotent_duplicate; 409 with a foreign
  execution_id or a different event -> failed fail-closed;
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
import json
import logging
import urllib.error
import uuid

import pytest

from app.core.config import Settings, settings
from app.services.executions import (
    THEHIVE_ACTIONS,
    ExecutorConfigError,
    ExecutionDispatch,
    TheHiveExecutor,
    create_executor,
)
from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.service import compensate_response, execute_response

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


def _success_payload(case_id="case-1") -> dict:
    return {"case_id": case_id}


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
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch()
        _executor(stub).execute(dispatch)
        body = stub.last["body"]
        assert set(body.keys()) == {
            "title",
            "description",
            "sentinelflow_execution_id",
            "source",
            "severity",
            "approval_id",
        }
        assert body["title"] == f"SentinelFlow escalation: {TARGET}"
        assert body["sentinelflow_execution_id"] == str(dispatch.execution_id)
        assert body["source"] == "sentinelflow"
        assert body["severity"] == "high"
        assert body["approval_id"] == str(dispatch.approval_id)
        assert isinstance(body["description"], str) and body["description"]

    def test_body_field_mapping_rules(self):
        # SentinelFlow execution facts -> TheHive case fields:
        # target -> title, execution_id + approval_id -> case body
        # (idempotency / audit / external tracking), source literal.
        stub = StubTransport(payload=_success_payload())
        dispatch = _dispatch(target="INC-77")
        _executor(stub).execute(dispatch)
        body = stub.last["body"]
        assert body["title"].startswith("SentinelFlow escalation: INC-77")
        assert body["sentinelflow_execution_id"] == str(dispatch.execution_id)
        assert body["approval_id"] == str(dispatch.approval_id)
        assert body["source"] == "sentinelflow"
        assert body["severity"] == "high"
        assert body["description"]

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
        stub = StubTransport(status=status, payload=_success_payload("case-9"))
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail == {"provider": "thehive", "case_id": "case-9"}
        assert outcome.raw_response == {"case_id": "case-9"}

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
# 4. Protocol violations (D9 — platform judges, adapter only raises)
# --------------------------------------------------------------------------
class TestProtocolViolation:
    @pytest.mark.parametrize(
        "payload",
        [
            {},  # empty answer
            {"success": True},  # success flag without a case id
            {"case_id": ""},  # empty case id
            {"case_id": None},  # null case id
        ],
    )
    def test_success_without_case_id_is_a_violation(self, payload):
        stub = StubTransport(payload=payload)
        with pytest.raises(ExecutorOutcomeViolation, match="case_id"):
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
    def test_same_execution_duplicate_is_succeeded_idempotent(self, body):
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail == {
            "provider": "thehive",
            "idempotent_duplicate": True,
        }

    def test_duplicate_with_same_execution_id_echo_is_still_idempotent(self):
        dispatch = _dispatch()
        body = json.dumps(
            {
                "error": "case already exists",
                "sentinelflow_execution_id": str(dispatch.execution_id),
            }
        ).encode()
        stub = StubTransport(status=409, body=body)
        outcome = _executor(stub).execute(dispatch)
        assert outcome.status == "succeeded"
        assert outcome.detail["idempotent_duplicate"] is True

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

    def test_duplicate_chain_writes_succeeded_idempotent(self, db_session):
        result = self._run(
            db_session,
            StubTransport(status=409, body=b'{"error": "case already exists"}'),
        )
        assert result.final_decision == "succeeded"
        assert result.rows[-1].detail["idempotent_duplicate"] is True

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
