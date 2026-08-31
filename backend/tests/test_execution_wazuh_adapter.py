"""Phase 3.2.4 — Wazuh Adapter regression.

Locks the complete offline chain:

    API -> Service -> Guard -> WazuhExecutor -> (stubbed) Wazuh API
    -> active response / endpoint action -> ExecutionOutcome -> D9
    protocol parser -> execution_log

Frozen responsibility (3.2.4 adjudication): Wazuh is an Endpoint
Security Response provider ONLY — quarantine / firewall block / account
disable via active-response commands. It NEVER writes the SentinelFlow
database, never touches Incident / EventRisk / Approval, never does
workflow orchestration (Shuffle) or case management (TheHive).

Request -> response -> decision -> execution_log. No agent polling, no
async callback, no task queue, no retry.

Discipline battery:
- succeeded requires 200/201 + success:true (synchronous confirmation);
- 202 / accepted-only -> failed adapter_error (no waiting state — 3.1
  froze "no asynchronous execution facts");
- 409 already executed / duplicate -> succeeded (idempotency hit), but
  the SAME execution_id bound to a DIFFERENT command stays a failure;
- classification table: 401/403/404/500 adapter_error, 502/503
  adapter_unavailable, timeout timeout, agent disconnected
  adapter_unavailable;
- protocol_violation judged ONLY by the platform parse (D9) — the
  adapter raises, never self-adjudicates;
- execution_id rides the BODY (arguments) — never the URL;
- ZERO automatic retry (E5): transport invoked exactly once;
- secret five-check with sentinel ``sentinel-wazuh-secret-test``:
  request / Authorization-header-only / URL / execution_log.detail /
  exception / logger — everything stays ***.

Default run: REAL EXTERNAL NETWORK = 0 — every HTTP exchange goes
through an injected transport double. The ONE test touching a real
Wazuh instance carries @pytest.mark.external and is DESELECTED unless
the run opts in with `-m external`.
"""
import json
import socket
import urllib.error
import uuid

import pytest

from app.core.config import Settings, settings
from app.services.executions import (
    WAZUH_ACTIONS,
    WAZUH_COMMANDS,
    WAZUH_REVERSE_COMMANDS,
    ExecutorConfigError,
    ExecutionDispatch,
    WazuhExecutor,
    create_executor,
)
from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.protocol import parse_execution_outcome
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.service import execute_response

# User-specified sentinel key for the 3.2.4 five-check battery.
FAKE_SECRET = "sentinel-wazuh-secret-test"
FAKE_USER = "sentinelflow-automation"


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
        url="http://stub/api/v1/agents/agent001/active-response",
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


def _basic_header() -> str:
    import base64

    token = base64.b64encode(f"{FAKE_USER}:{FAKE_SECRET}".encode()).decode("ascii")
    return f"Basic {token}"


def _creds() -> AdapterCredentials:
    return AdapterCredentials(
        adapter="wazuh", base_url="http://stub",
        username=FAKE_USER, password=FAKE_SECRET,
    )


def _executor(transport, **kwargs) -> WazuhExecutor:
    return WazuhExecutor(
        _creds(), timeout=kwargs.pop("timeout", 1.0), transport=transport, **kwargs
    )


def _dispatch(action="isolate_host", target="agent001") -> ExecutionDispatch:
    return ExecutionDispatch(
        execution_id=uuid.uuid4(),
        action=action,
        target=target,
        approval_id=uuid.uuid4(),
    )


def _wazuh_settings(**overrides) -> Settings:
    base = {
        "EXECUTION_ADAPTER": "wazuh",
        "WAZUH_BASE_URL": "http://stub",
        "WAZUH_API_USER": FAKE_USER,
        "WAZUH_API_PASSWORD": FAKE_SECRET,
    }
    base.update(overrides)
    return Settings(**base)


# --------------------------------------------------------------------------
# 1. Architecture (registry / name / supports / compensation)
# --------------------------------------------------------------------------
class TestArchitecture:
    def test_registry_builds_wazuh_executor(self):
        executor = create_executor(_wazuh_settings())
        assert isinstance(executor, WazuhExecutor)

    def test_name_is_wazuh_and_contract_is_response_executor(self):
        from app.services.executions.base import ResponseExecutor

        executor = _executor(StubTransport())
        assert executor.name == "wazuh"
        assert isinstance(executor, ResponseExecutor)

    def test_supports_exactly_the_frozen_three(self):
        executor = _executor(StubTransport())
        assert WAZUH_ACTIONS == frozenset(
            {"isolate_host", "disable_account", "block_source_ip"}
        )
        for action in WAZUH_ACTIONS:
            assert executor.supports(action) is True

    def test_thehive_and_analysis_actions_stay_frozen_out(self):
        executor = _executor(StubTransport())
        for action in ("escalate_to_incident", "hunt_related_activity",
                       "monitor_only", "trigger_workflow", "close_incident",
                       "modify_risk_score"):
            assert executor.supports(action) is False

    def test_compensation_follows_the_frozen_table(self):
        executor = _executor(StubTransport())
        assert executor.supports_compensation("isolate_host") is True
        assert executor.supports_compensation("block_source_ip") is True
        # Account recovery needs human confirmation — never simulated.
        assert executor.supports_compensation("disable_account") is False
        assert WAZUH_REVERSE_COMMANDS == {
            "isolate_host": "release-host",
            "block_source_ip": "unblock-source-ip",
        }

    def test_missing_credentials_refuse_construction(self):
        with pytest.raises(ExecutorConfigError, match="missing required configuration"):
            create_executor(Settings(EXECUTION_ADAPTER="wazuh"))

    def test_url_shape_gate_applies(self):
        with pytest.raises(ExecutorConfigError, match="query string"):
            create_executor(
                _wazuh_settings(WAZUH_BASE_URL=f"https://mgr?token={FAKE_SECRET}")
            )

    def test_wrong_adapter_credentials_rejected(self):
        with pytest.raises(ExecutorConfigError, match="credentials for adapter"):
            WazuhExecutor(
                AdapterCredentials("shuffle", "http://stub", api_key=FAKE_SECRET)
            )


# --------------------------------------------------------------------------
# 2. HTTP contract + outcome matrix
# --------------------------------------------------------------------------
class TestHttpContract:
    def test_url_is_agent_scoped_active_response(self):
        stub = StubTransport(payload={"success": True, "command_id": "c-1"})
        _executor(stub).execute(_dispatch(target="agent001"))
        assert stub.last["url"] == (
            "http://stub/api/v1/agents/agent001/active-response"
        )
        assert stub.last["method"] == "POST"

    def test_body_is_command_plus_execution_id_argument(self):
        stub = StubTransport(payload={"success": True, "command_id": "c-2"})
        dispatch = _dispatch(action="isolate_host", target="agent001")
        _executor(stub).execute(dispatch)
        assert stub.last["body"] == {
            "command": "quarantine-host",
            "arguments": [str(dispatch.execution_id)],
        }

    def test_authorization_is_basic_header_only(self):
        stub = StubTransport(payload={"success": True, "command_id": "c-3"})
        _executor(stub).execute(_dispatch())
        assert stub.last["headers"]["authorization"] == _basic_header()
        assert set(stub.last["headers"]) == {"authorization", "content-type"}
        # No credential material in URL or body.
        assert FAKE_SECRET not in stub.last["url"]
        assert FAKE_SECRET not in json.dumps(stub.last["body"])
        assert FAKE_USER not in stub.last["url"]
        assert "password" not in json.dumps(stub.last["body"]).lower()

    def test_action_to_command_mapping(self):
        assert WAZUH_COMMANDS == {
            "isolate_host": "quarantine-host",
            "disable_account": "disable-account",
            "block_source_ip": "block-source-ip",
        }
        for action, command in WAZUH_COMMANDS.items():
            stub = StubTransport(payload={"success": True, "command_id": "c"})
            _executor(stub).execute(_dispatch(action=action))
            assert stub.last["body"]["command"] == command

    def test_adapter_timeout_is_passed(self):
        stub = StubTransport(payload={"success": True, "command_id": "c-4"})
        _executor(stub, timeout=2.5).execute(_dispatch())
        assert stub.last["timeout"] == 2.5


class TestOutcomeMatrix:
    @pytest.mark.parametrize(
        "transport, expected_classification",
        [
            (StubTransport(exc=socket.timeout("boom")), "timeout"),
            (
                StubTransport(exc=urllib.error.URLError(ConnectionRefusedError())),
                "adapter_unavailable",
            ),
            (StubTransport(status=401, body=b"denied"), "adapter_error"),
            (StubTransport(status=403, body=b"forbidden"), "adapter_error"),
            (StubTransport(status=404, body=b"no agent"), "adapter_error"),
            (StubTransport(status=409, body=b"other conflict"), "adapter_error"),
            (StubTransport(status=500, body=b"boom"), "adapter_error"),
            (StubTransport(status=502, body=b"gateway"), "adapter_unavailable"),
            (StubTransport(status=503, body=b"down"), "adapter_unavailable"),
            (
                StubTransport(status=202, payload={"accepted": True}),
                "adapter_error",
            ),
            (
                StubTransport(status=400, payload={"error": "agent disconnected"}),
                "adapter_unavailable",
            ),
        ],
        ids=[
            "timeout", "connection-refused", "401", "403", "404",
            "409-no-duplicate-marker", "500", "502", "503", "202-accepted",
            "agent-disconnected",
        ],
    )
    def test_failure_classifications(self, transport, expected_classification):
        outcome = _executor(transport).execute(_dispatch())
        parse_execution_outcome(outcome)  # D9 accepts every self-report
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == expected_classification
        assert outcome.raw_response is None

    def test_200_success_is_succeeded_provider_wazuh(self):
        stub = StubTransport(payload={"success": True, "command_id": "abc"})
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["provider"] == "wazuh"
        assert outcome.detail["command"] == "quarantine-host"
        assert outcome.detail["command_id"] == "abc"
        parse_execution_outcome(outcome)  # D9 accepts

    def test_201_created_with_confirmation_is_succeeded(self):
        outcome = _executor(
            StubTransport(status=201, payload={"success": True})
        ).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["provider"] == "wazuh"

    def test_2xx_accepted_only_is_failed_not_succeeded(self):
        # accepted != completed — same rule as Shuffle.
        outcome = _executor(
            StubTransport(payload={"accepted": True, "command_id": "c-10"})
        ).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"


# --------------------------------------------------------------------------
# 3. Protocol violation (D9 — the adapter raises, the platform decides)
# --------------------------------------------------------------------------
class TestProtocolViolation:
    def test_non_json_is_protocol_violation(self):
        with pytest.raises(ExecutorOutcomeViolation, match="not valid JSON"):
            _executor(StubTransport(body=b"<html>oops</html>")).execute(_dispatch())

    def test_missing_success_field_is_protocol_violation(self):
        # e.g. {"status": "running"} — undecided states never succeed.
        with pytest.raises(ExecutorOutcomeViolation, match="explicit confirmation"):
            _executor(StubTransport(payload={"status": "running"})).execute(
                _dispatch()
            )

    def test_unknown_status_shape_is_protocol_violation(self):
        with pytest.raises(ExecutorOutcomeViolation, match="explicit confirmation"):
            _executor(StubTransport(payload={"status": "weird"})).execute(_dispatch())

    def test_fake_success_with_unknown_agent_status_is_protocol_violation(self):
        # {"success": true, "agent_status": "unknown"} — ambiguous agent
        # outcome: the adapter NEVER decides this itself.
        with pytest.raises(ExecutorOutcomeViolation, match="ambiguous agent_status"):
            _executor(
                StubTransport(payload={"success": True, "agent_status": "unknown"})
            ).execute(_dispatch())

    def test_wrong_type_success_is_protocol_violation(self):
        with pytest.raises(ExecutorOutcomeViolation, match="explicit confirmation"):
            _executor(StubTransport(payload={"success": "yes"})).execute(_dispatch())

    def test_non_dict_json_is_protocol_violation(self):
        with pytest.raises(ExecutorOutcomeViolation, match="not a JSON object"):
            _executor(StubTransport(payload=["success"])).execute(_dispatch())

    def test_ambiguous_agent_status_never_becomes_succeeded(self, db_session):
        # End-to-end: platform parse writes the protocol_violation verdict.
        from tests.test_execution_service import seed_approved

        executor = _executor(
            StubTransport(payload={"success": True, "agent_status": "unknown"})
        )
        approval = seed_approved(
            db_session,
            recommendations=[{"action": "isolate_host", "target": "agent001",
                              "rationale": "lateral"}],
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
# 4. Idempotency (execution_id contract, Shuffle parity)
# --------------------------------------------------------------------------
class TestIdempotency:
    @pytest.mark.parametrize(
        "body",
        [
            b'{"error": "already executed"}',
            b'{"error": "duplicate command"}',
            b'{"error": "command already exists"}',
        ],
        ids=["already-executed", "duplicate-command", "already-exists"],
    )
    def test_409_duplicate_translates_to_succeeded(self, body):
        outcome = _executor(StubTransport(status=409, body=body)).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["provider"] == "wazuh"
        assert outcome.detail["idempotent_duplicate"] is True

    def test_409_referencing_another_execution_id_is_fail_closed(self):
        body = json.dumps(
            {"error": "already executed", "execution_id": str(uuid.uuid4())}
        ).encode("utf-8")
        outcome = _executor(StubTransport(status=409, body=body)).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    def test_same_execution_id_different_command_must_fail(self):
        # isolate_host first, then block_source_ip replayed on the SAME
        # execution_id: overwrite attempts NEVER become idempotent hits.
        body = json.dumps(
            {"error": "execution id already used for a different command"}
        ).encode("utf-8")
        outcome = _executor(
            StubTransport(status=409, body=body)
        ).execute(_dispatch(action="block_source_ip", target="10.0.0.9"))
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"
        assert "idempotent_duplicate" not in outcome.detail

    def test_different_execution_id_is_a_fresh_outbound(self):
        stub = StubTransport(payload={"success": True, "command_id": "c"})
        executor = _executor(stub)
        executor.execute(_dispatch())
        executor.execute(_dispatch())
        assert len(stub.calls) == 2
        assert (
            stub.calls[0]["body"]["arguments"] != stub.calls[1]["body"]["arguments"]
        )

    def test_zero_automatic_retry_transport_called_exactly_once(self):
        stub = StubTransport(exc=socket.timeout("boom"))
        _executor(stub).execute(_dispatch())
        assert len(stub.calls) == 1


# --------------------------------------------------------------------------
# 5. Secret boundary — five-check with sentinel-wazuh-secret-test
# --------------------------------------------------------------------------
class TestSecretBoundary:
    def test_five_check_request_url_detail_exception_log(self):
        """① request body ② URL ③ execution_log-bound detail ④ exception
        string ⑤ logger — the sentinel secret survives nowhere."""
        import io
        import logging

        from app.services.executions.secrets import (
            SecretRedactionFilter,
            redact_text,
        )

        body = json.dumps(
            {"error": f"Authorization Basic user:{FAKE_SECRET}"}
        ).encode()
        stub = StubTransport(status=401, body=body)
        outcome = _executor(stub).execute(_dispatch())

        # 1. request — Authorization header ONLY, never body/URL
        assert stub.last["headers"]["authorization"] == _basic_header()
        assert FAKE_SECRET not in json.dumps(stub.last["body"])
        # 2. URL
        assert FAKE_SECRET not in stub.last["url"]
        assert "?" not in stub.last["url"]
        # 3. outcome detail (audit-bound)
        assert outcome.status == "failed"
        assert FAKE_SECRET not in str(outcome.detail)
        # 4. exception strings through the redaction gate
        try:
            raise ExecutorOutcomeViolation(f"stub said: {FAKE_SECRET}")
        except ExecutorOutcomeViolation as violation:
            assert FAKE_SECRET not in redact_text(str(violation), (FAKE_SECRET,))
        # 5. logger through the redaction filter
        logger = logging.getLogger(f"wazuh-{uuid.uuid4().hex}")
        logger.setLevel(logging.DEBUG)
        logger.addFilter(SecretRedactionFilter((FAKE_SECRET,)))
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.warning("wazuh rejected command: password=%s", FAKE_SECRET)
        assert FAKE_SECRET not in stream.getvalue()

    def test_credentials_repr_masks_password(self):
        creds = _creds()
        assert FAKE_SECRET not in repr(creds)
        assert FAKE_SECRET not in str(creds)

    def test_smuggled_secret_masked_in_execution_log(
        self, db_session, monkeypatch
    ):
        """End-to-end audit proof: a hostile Wazuh echoing the password
        in a failure body lands *** in execution_log.detail."""
        from app.core.config import settings as global_settings
        from tests.test_execution_service import seed_approved

        monkeypatch.setattr(global_settings, "WAZUH_API_PASSWORD", FAKE_SECRET)

        body = json.dumps(
            {"error": f"invalid credentials: {FAKE_SECRET}"}
        ).encode()
        executor = _executor(StubTransport(status=401, body=body))
        approval = seed_approved(
            db_session,
            recommendations=[{"action": "isolate_host", "target": "agent001",
                              "rationale": "lateral"}],
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


# --------------------------------------------------------------------------
# 6. Security (target mutation / fake agent id / token injection)
# --------------------------------------------------------------------------
class TestSecurity:
    @pytest.mark.parametrize(
        "hostile_target",
        ["agent/../admin", "agent?x=1", "agent/../../settings", "a b", ""],
        ids=["path-traversal", "query-injection", "deep-traversal",
             "whitespace", "empty"],
    )
    def test_fake_agent_id_never_reaches_transport(self, hostile_target):
        stub = StubTransport()
        with pytest.raises(ExecutorOutcomeViolation, match="safe agent identifier"):
            _executor(stub).execute(_dispatch(target=hostile_target))
        assert stub.calls == []  # refused BEFORE any outbound

    def test_api_rejects_client_supplied_target(self, client, monkeypatch):
        """Target mutation attack: POST /executions smuggling a target
        field. ExecuteRequest is extra='forbid' — 422, never executed."""
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", FAKE_SECRET)
        response = client.post(
            "/api/v1/executions",
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(uuid.uuid4()),
                "operator": "ops-1",
                "target": "agent666",
            },
            headers={"Authorization": f"Bearer {FAKE_SECRET}"},
        )
        assert response.status_code == 422

    def test_validated_target_is_the_only_agent_addressed(self):
        stub = StubTransport(payload={"success": True, "command_id": "c-1"})
        _executor(stub).execute(_dispatch(target="agent001"))
        assert stub.last["url"].endswith("/agents/agent001/active-response")
        assert FAKE_SECRET not in stub.last["url"]


# --------------------------------------------------------------------------
# 7. End-to-end (API -> Service -> Guard -> WazuhExecutor -> stub -> log)
# --------------------------------------------------------------------------
class TestEndToEnd:
    def _run(self, db_session, transport, action="isolate_host", target="agent001"):
        from tests.test_execution_service import seed_approved

        approval = seed_approved(
            db_session,
            recommendations=[{"action": action, "target": target,
                              "rationale": "lateral movement"}],
        )
        return execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=_executor(transport),
        )

    def test_success_chain_writes_provider_wazuh(self, db_session):
        result = self._run(
            db_session, StubTransport(payload={"success": True, "command_id": "cmd-1"})
        )
        assert result.final_decision == "succeeded"
        assert result.chain == ("requested", "dispatched", "succeeded")
        detail = result.rows[-1].detail
        assert detail["provider"] == "wazuh"
        assert detail["command"] == "quarantine-host"
        assert detail["command_id"] == "cmd-1"

    def test_timeout_chain_is_failed_timeout(self, db_session):
        result = self._run(db_session, StubTransport(exc=socket.timeout("boom")))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "timeout"

    def test_duplicate_chain_is_succeeded_idempotency_hit(self, db_session):
        result = self._run(
            db_session,
            StubTransport(status=409, body=b'{"error": "already executed"}'),
        )
        assert result.final_decision == "succeeded"
        assert result.rows[-1].detail["idempotent_duplicate"] is True

    def test_malformed_chain_is_platform_protocol_violation(self, db_session):
        result = self._run(db_session, StubTransport(body=b"not json"))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "protocol_violation"

    def test_compensation_sends_release_host(self, db_session):
        """Forward isolate_host then compensation: release-host against
        the SAME validated agent; compensation_succeeded terminal."""
        from tests.test_execution_service import seed_approved

        stub = StubTransport(payload={"success": True, "command_id": "cmd-2"})
        executor = _executor(stub)
        approval = seed_approved(
            db_session,
            recommendations=[{"action": "isolate_host", "target": "agent001",
                              "rationale": "lateral"}],
        )
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert forward.final_decision == "succeeded"
        from app.services.executions.service import compensate_response

        compensation = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert compensation.final_decision == "compensation_succeeded"
        assert stub.calls[-1]["url"] == (
            "http://stub/api/v1/agents/agent001/active-response"
        )
        assert stub.calls[-1]["body"]["command"] == "release-host"

    def test_block_compensation_sends_unblock(self, db_session):
        from tests.test_execution_service import seed_approved

        stub = StubTransport(payload={"success": True, "command_id": "cmd-3"})
        executor = _executor(stub)
        approval = seed_approved(
            db_session,
            recommendations=[{"action": "block_source_ip", "target": "agent002",
                              "rationale": "c2 beacon"}],
        )
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert forward.final_decision == "succeeded"
        from app.services.executions.service import compensate_response

        compensation = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert compensation.final_decision == "compensation_succeeded"
        assert stub.calls[-1]["body"]["command"] == "unblock-source-ip"

    def test_disable_account_compensation_refused_before_outbound(self, db_session):
        """Account recovery needs human confirmation — G4 ends the chain
        as compensation_failed (capability_missing) BEFORE any outbound."""
        from tests.test_execution_service import seed_approved

        stub = StubTransport(payload={"success": True, "command_id": "cmd-4"})
        executor = _executor(stub)
        approval = seed_approved(
            db_session,
            recommendations=[{"action": "disable_account", "target": "user-42",
                              "rationale": "compromised"}],
        )
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert forward.final_decision == "succeeded"
        from app.services.executions.service import compensate_response

        compensation = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert compensation.final_decision == "compensation_failed"
        assert compensation.rows[-1].detail["classification"] == "capability_missing"
        # Exactly ONE outbound ever happened — the forward command.
        assert len(stub.calls) == 1


# --------------------------------------------------------------------------
# 8. Real Wazuh (external marker — deselected by default)
# --------------------------------------------------------------------------
@pytest.mark.external
class TestRealWazuh:
    def test_real_active_response(self):
        """Talks to a REAL Wazuh manager. Runs ONLY with `-m external`
        and a complete WAZUH_* configuration; skips itself otherwise."""
        import os

        if not (
            os.environ.get("WAZUH_BASE_URL")
            and os.environ.get("WAZUH_API_USER")
            and os.environ.get("WAZUH_API_PASSWORD")
        ):
            pytest.skip("real Wazuh environment not configured")
        real_settings = Settings()
        executor = create_executor(real_settings)
        assert executor.name == "wazuh"
        outcome = parse_execution_outcome(executor.execute(_dispatch()))
        # Terminal fact only (D10): succeeded or failed, nothing else.
        assert outcome.status in ("succeeded", "failed")
        if outcome.status == "succeeded":
            assert outcome.detail["provider"] == "wazuh"
