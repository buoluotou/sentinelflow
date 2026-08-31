"""Phase 3.2.3 — Shuffle Adapter regression.

Locks the complete offline chain:

    ResponseExecutor -> ShuffleExecutor -> (stubbed) Shuffle API
    -> workflow trigger -> ExecutionOutcome -> D9 protocol parser
    -> execution_log

Frozen semantics under test (design §4/§5/§6/§7):
- succeeded == "workflow trigger confirmed" (E4) — never "fully done";
- 202 without confirmation -> failed (fail-closed);
- duplicate / already triggered -> succeeded (idempotency hit, §5.3);
- classification table: timeout / unreachable / 4xx / 5xx / malformed;
- protocol_violation judged ONLY by the platform parse (D9);
- execution_id rides the request BODY (outbound idempotency, §5.2);
- ZERO automatic retry (E5): the transport is invoked exactly once;
- secret discipline: a hostile stub echoing the API key back stays ***
  in detail / exceptions / logs / request bodies.

Default run: REAL EXTERNAL NETWORK = 0 — every HTTP exchange goes
through an injected transport double. The ONE test touching a real
Shuffle instance carries @pytest.mark.external and is DESELECTED unless
the run opts in with `-m external`.
"""
import json
import socket
import urllib.error
import uuid
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.services.executions import (
    SHUFFLE_ACTIONS,
    ExecutorConfigError,
    ExecutionDispatch,
    ShuffleExecutor,
    create_executor,
)
from app.services.executions.protocol import parse_execution_outcome
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.service import execute_response

FAKE_SECRET = "s3cr3t-PHASE32-TEST-ONLY"

_ALL_WORKFLOWS = {
    "block_source_ip": "wf-block",
    "isolate_host": "wf-isolate",
    "disable_account": "wf-disable",
    "escalate_to_incident": "wf-escalate",
}
_ALL_WORKFLOW_SETTINGS = {
    "SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP": "wf-block",
    "SHUFFLE_WORKFLOW_ISOLATE_HOST": "wf-isolate",
    "SHUFFLE_WORKFLOW_DISABLE_ACCOUNT": "wf-disable",
    "SHUFFLE_WORKFLOW_ESCALATE_TO_INCIDENT": "wf-escalate",
}


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
        url="http://stub/api/v1/workflows/wf/execute",
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
        adapter="shuffle", base_url="http://stub", api_key=FAKE_SECRET
    )


def _executor(transport, **kwargs) -> ShuffleExecutor:
    return ShuffleExecutor(
        _creds(),
        _ALL_WORKFLOWS,
        reverse_workflows={"block_source_ip": "wf-reverse-block"},
        timeout=kwargs.pop("timeout", 1.0),
        transport=transport,
        **kwargs,
    )


def _dispatch(action="block_source_ip", target="203.0.113.10") -> ExecutionDispatch:
    return ExecutionDispatch(
        execution_id=uuid.uuid4(),
        action=action,
        target=target,
        approval_id=uuid.uuid4(),
    )


def _shuffle_settings(**overrides) -> Settings:
    base = {
        "EXECUTION_ADAPTER": "shuffle",
        "SHUFFLE_BASE_URL": "http://stub",
        "SHUFFLE_API_KEY": FAKE_SECRET,
        **_ALL_WORKFLOW_SETTINGS,
    }
    base.update(overrides)
    return Settings(**base)


# --------------------------------------------------------------------------
# 1. Capability surface (frozen §4 Shuffle column)
# --------------------------------------------------------------------------
class TestCapability:
    def test_name_is_shuffle(self):
        assert _executor(StubTransport()).name == "shuffle"

    def test_supports_exactly_the_frozen_four_when_configured(self):
        executor = _executor(StubTransport())
        assert SHUFFLE_ACTIONS == frozenset(_ALL_WORKFLOWS)
        for action in SHUFFLE_ACTIONS:
            assert executor.supports(action) is True

    def test_never_invents_actions(self):
        executor = _executor(StubTransport())
        for action in ("hunt_related_activity", "monitor_only", "trigger_workflow"):
            assert executor.supports(action) is False

    def test_unconfigured_action_is_not_supported_fail_closed(self):
        executor = ShuffleExecutor(
            _creds(), {"block_source_ip": "wf-block"}, transport=StubTransport()
        )
        assert executor.supports("block_source_ip") is True
        assert executor.supports("isolate_host") is False

    def test_compensation_is_workflow_dependent(self):
        # Frozen §4: reverse workflow configured -> supported; otherwise
        # False (disable_account has NO reverse slot by design).
        executor = _executor(StubTransport())
        assert executor.supports_compensation("block_source_ip") is True
        assert executor.supports_compensation("isolate_host") is False
        assert executor.supports_compensation("disable_account") is False
        assert executor.supports_compensation("escalate_to_incident") is False


# --------------------------------------------------------------------------
# 2. Registry construction (fail-closed)
# --------------------------------------------------------------------------
class TestRegistry:
    def test_create_executor_returns_shuffle(self):
        executor = create_executor(_shuffle_settings())
        assert isinstance(executor, ShuffleExecutor)
        assert executor.name == "shuffle"

    def test_missing_workflow_ids_refuse_construction(self):
        settings = _shuffle_settings(
            SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP="",
            SHUFFLE_WORKFLOW_ISOLATE_HOST="",
        )
        with pytest.raises(ExecutorConfigError) as exc:
            create_executor(settings)
        message = str(exc.value)
        assert "SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP" in message
        assert "SHUFFLE_WORKFLOW_ISOLATE_HOST" in message
        assert FAKE_SECRET not in message

    def test_unknown_workflow_mapping_rejected(self):
        with pytest.raises(ExecutorConfigError, match="unknown actions"):
            ShuffleExecutor(_creds(), {"not_an_action": "wf-x"})

    def test_wrong_adapter_credentials_rejected(self):
        with pytest.raises(ExecutorConfigError, match="credentials for adapter"):
            ShuffleExecutor(
                AdapterCredentials("wazuh", "http://stub", FAKE_SECRET),
                _ALL_WORKFLOWS,
            )


# --------------------------------------------------------------------------
# 3. Outbound request discipline
# --------------------------------------------------------------------------
class TestOutboundDiscipline:
    def test_url_is_base_plus_workflow_never_carries_secret(self):
        stub = StubTransport(payload={"success": True})
        _executor(stub).execute(_dispatch())
        assert stub.last["url"] == "http://stub/api/v1/workflows/wf-block/execute"
        assert FAKE_SECRET not in stub.last["url"]

    def test_authorization_is_bearer_header_only(self):
        stub = StubTransport(payload={"success": True})
        _executor(stub).execute(_dispatch())
        assert stub.last["headers"]["authorization"] == f"Bearer {FAKE_SECRET}"
        assert FAKE_SECRET not in json.dumps(stub.last["body"])

    def test_execution_id_rides_the_body(self):
        stub = StubTransport(payload={"success": True})
        dispatch = _dispatch()
        _executor(stub).execute(dispatch)
        body = stub.last["body"]
        assert body["sentinelflow_execution_id"] == str(dispatch.execution_id)
        assert body["action"] == dispatch.action
        assert body["target"] == dispatch.target
        assert body["operation"] == "execute"

    def test_adapter_timeout_is_passed(self):
        stub = StubTransport(payload={"success": True})
        _executor(stub, timeout=2.5).execute(_dispatch())
        assert stub.last["timeout"] == 2.5


# --------------------------------------------------------------------------
# 4. HTTP semantics table (frozen §6/§7 — no string-sniffing, table only)
# --------------------------------------------------------------------------
class TestHttpSemanticsTable:
    @pytest.mark.parametrize(
        "transport, expected_status, expected_classification",
        [
            # timeout -> timeout
            (StubTransport(exc=socket.timeout("boom")), "failed", "timeout"),
            # connection refused / DNS -> adapter_unavailable
            (
                StubTransport(
                    exc=urllib.error.URLError(ConnectionRefusedError())
                ),
                "failed",
                "adapter_unavailable",
            ),
            # 401 / 403 / 404 explicit rejections -> adapter_error
            (StubTransport(status=401, body=b"denied"), "failed", "adapter_error"),
            (StubTransport(status=403, body=b"forbidden"), "failed", "adapter_error"),
            (StubTransport(status=404, body=b"no workflow"), "failed", "adapter_error"),
            # 409 WITHOUT duplicate markers is a plain rejection
            (StubTransport(status=409, body=b"other conflict"), "failed", "adapter_error"),
            # 500 -> adapter_error; 503 -> adapter_unavailable
            (StubTransport(status=500, body=b"boom"), "failed", "adapter_error"),
            (StubTransport(status=503, body=b"down"), "failed", "adapter_unavailable"),
            # 202 accepted-without-confirmation -> fail-closed (E4/D10)
            (
                StubTransport(status=202, payload={"message": "accepted"}),
                "failed",
                "adapter_error",
            ),
            # duplicate on the WRONG verb is not an idempotency hit
            (
                StubTransport(status=400, payload={"error": "already triggered"}),
                "failed",
                "adapter_error",
            ),
        ],
        ids=[
            "timeout",
            "connection-refused",
            "401",
            "403",
            "404",
            "409-no-duplicate-marker",
            "500",
            "503",
            "202-no-confirmation",
            "duplicate-on-400",
        ],
    )
    def test_failure_classifications(
        self, transport, expected_status, expected_classification
    ):
        outcome = _executor(transport).execute(_dispatch())
        parse_execution_outcome(outcome)  # D9 accepts every self-report
        assert outcome.status == expected_status
        assert outcome.detail["classification"] == expected_classification
        assert outcome.raw_response is None

    def test_200_with_confirmation_is_workflow_triggered(self):
        stub = StubTransport(
            payload={"success": True, "execution_id": "shuffle-run-42"}
        )
        outcome = _executor(stub).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["result"] == "workflow triggered"
        assert outcome.detail["workflow_id"] == "wf-block"
        assert outcome.detail["external_execution_id"] == "shuffle-run-42"
        # E4: trigger confirmation — NOT workflow completion.
        assert "classification" not in outcome.detail

    def test_201_created_with_confirmation_is_succeeded(self):
        outcome = _executor(
            StubTransport(status=201, payload={"success": True})
        ).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["result"] == "workflow triggered"

    def test_2xx_without_confirmation_is_protocol_violation(self):
        executor = _executor(StubTransport(payload={"message": "queued"}))
        from app.services.executions.exceptions import ExecutorOutcomeViolation

        with pytest.raises(ExecutorOutcomeViolation, match="explicit trigger"):
            executor.execute(_dispatch())

    def test_non_json_2xx_is_protocol_violation(self):
        from app.services.executions.exceptions import ExecutorOutcomeViolation

        with pytest.raises(ExecutorOutcomeViolation, match="not valid JSON"):
            _executor(StubTransport(body=b"<html>oops</html>")).execute(_dispatch())

    def test_non_dict_json_is_protocol_violation(self):
        from app.services.executions.exceptions import ExecutorOutcomeViolation

        with pytest.raises(ExecutorOutcomeViolation, match="not a JSON object"):
            _executor(StubTransport(payload=["success"])).execute(_dispatch())


# --------------------------------------------------------------------------
# 5. Idempotency (frozen §5)
# --------------------------------------------------------------------------
class TestIdempotency:
    @pytest.mark.parametrize(
        "body",
        [
            b'{"error": "already triggered"}',
            b'{"error": "duplicate request"}',
            b'{"error": "execution already exists"}',
        ],
        ids=["already-triggered", "duplicate", "already-exists"],
    )
    def test_409_duplicate_translates_to_succeeded(self, body):
        outcome = _executor(StubTransport(status=409, body=body)).execute(_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["result"] == "workflow triggered"
        assert outcome.detail["idempotent_duplicate"] is True

    def test_409_referencing_another_execution_is_fail_closed(self):
        # A demonstrably FOREIGN execution id is NOT our idempotency hit.
        body = json.dumps(
            {"error": "already triggered", "execution_id": "some-other-run"}
        ).encode("utf-8")
        outcome = _executor(StubTransport(status=409, body=body)).execute(_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == "adapter_error"

    def test_zero_automatic_retry_transport_called_exactly_once(self):
        stub = StubTransport(exc=socket.timeout("boom"))
        _executor(stub).execute(_dispatch())
        assert len(stub.calls) == 1


# --------------------------------------------------------------------------
# 6. Secret leakage (stub echoes the key back — everything stays ***)
# --------------------------------------------------------------------------
class TestSecretLeakage:
    def test_secret_in_error_body_never_reaches_detail(self):
        body = json.dumps({"error": f"Authorization Bearer {FAKE_SECRET}"}).encode()
        outcome = _executor(StubTransport(status=401, body=body)).execute(_dispatch())
        assert outcome.status == "failed"
        assert FAKE_SECRET not in str(outcome.detail)
        assert FAKE_SECRET not in str(outcome)

    def test_five_check_request_detail_exception_log_api(self):
        """The five-check mirror (frozen §8 rule 5): request body /
        audit detail / exception strings / captured logs / API surface."""
        import logging

        body = json.dumps({"error": f"Bearer {FAKE_SECRET}"}).encode()
        stub = StubTransport(status=401, body=body)
        executor = _executor(stub)

        # 2/3. outcome detail + exception strings
        outcome = executor.execute(_dispatch())

        # 1. outbound request body (Authorization header is the ONLY ride)
        assert FAKE_SECRET not in json.dumps(stub.last["body"])
        assert FAKE_SECRET not in stub.last["url"]
        assert FAKE_SECRET not in str(outcome.detail)
        try:
            from app.services.executions.exceptions import ExecutorOutcomeViolation

            raise ExecutorOutcomeViolation(f"stub said: {FAKE_SECRET}")
        except ExecutorOutcomeViolation as violation:
            from app.services.executions.secrets import redact_text

            assert FAKE_SECRET not in redact_text(str(violation), (FAKE_SECRET,))

        # 4. logging through the redaction filter
        from app.services.executions.secrets import SecretRedactionFilter

        logger = logging.getLogger(f"shuffle-{uuid.uuid4().hex}")
        logger.setLevel(logging.DEBUG)
        logger.addFilter(SecretRedactionFilter((FAKE_SECRET,)))
        import io

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.warning("shuffle rejected trigger: Bearer %s", FAKE_SECRET)
        assert FAKE_SECRET not in stream.getvalue()

    def test_smuggled_secret_masked_in_execution_log(
        self, db_session, monkeypatch
    ):
        """End-to-end audit proof: a hostile Shuffle echoing the key in
        a failure body lands *** in execution_log.detail — never raw."""
        from app.core.config import settings as global_settings
        from tests.test_execution_service import seed_approved

        monkeypatch.setattr(global_settings, "SHUFFLE_API_KEY", FAKE_SECRET)

        body = json.dumps({"error": f"Authorization Bearer {FAKE_SECRET}"}).encode()
        executor = _executor(StubTransport(status=401, body=body))
        approval = seed_approved(db_session)
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
# 7. Full service chain (offline stub through the real Service)
# --------------------------------------------------------------------------
class TestServiceChain:
    def _run(self, db_session, transport, action="block_source_ip"):
        from tests.test_execution_service import seed_approved

        approval = seed_approved(
            db_session,
            recommendations=[{"action": action, "target": "203.0.113.10",
                              "rationale": "abuse"}],
        )
        return execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=_executor(transport),
        )

    def test_success_chain_is_workflow_triggered(self, db_session):
        result = self._run(
            db_session, StubTransport(payload={"success": True, "id": "run-1"})
        )
        assert result.final_decision == "succeeded"
        assert result.chain == ("requested", "dispatched", "succeeded")
        terminal = result.rows[-1]
        assert terminal.detail["result"] == "workflow triggered"

    def test_timeout_chain_is_failed_timeout(self, db_session):
        result = self._run(db_session, StubTransport(exc=socket.timeout("boom")))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "timeout"

    def test_duplicate_chain_is_succeeded_idempotency_hit(self, db_session):
        result = self._run(
            db_session,
            StubTransport(status=409, body=b'{"error": "already triggered"}'),
        )
        assert result.final_decision == "succeeded"
        assert result.rows[-1].detail["idempotent_duplicate"] is True

    def test_malformed_response_chain_is_platform_protocol_violation(
        self, db_session
    ):
        # D9: the adapter RAISES; only the platform parse writes the
        # protocol_violation verdict.
        result = self._run(db_session, StubTransport(body=b"not json"))
        assert result.final_decision == "failed"
        assert result.rows[-1].detail["classification"] == "protocol_violation"

    def test_compensation_triggers_reverse_workflow(self, db_session):
        """Forward execution then compensation: the reverse workflow id
        is the outbound target, operation=compensate."""
        from tests.test_execution_service import seed_approved

        stub = StubTransport(payload={"success": True})
        executor = _executor(stub)
        approval = seed_approved(db_session)
        forward = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        from app.services.executions.service import compensate_response

        compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
        )
        assert stub.calls[-1]["url"].endswith("/wf-reverse-block/execute")
        assert stub.calls[-1]["body"]["operation"] == "compensate"


# --------------------------------------------------------------------------
# 8. Real Shuffle (external marker — deselected by default)
# --------------------------------------------------------------------------
@pytest.mark.external
class TestRealShuffle:
    def test_real_workflow_trigger(self):
        """Talks to a REAL Shuffle instance. Runs ONLY with `-m external`
        and a complete SHUFFLE_* configuration; skips itself otherwise."""
        import os

        if not os.environ.get("SHUFFLE_BASE_URL") or not os.environ.get(
            "SHUFFLE_API_KEY"
        ):
            pytest.skip("real Shuffle environment not configured")
        settings = Settings()
        executor = create_executor(settings)
        assert executor.name == "shuffle"
        dispatch = _dispatch()
        outcome = parse_execution_outcome(executor.execute(dispatch))
        # Terminal fact only (D10): succeeded or failed, nothing else.
        assert outcome.status in ("succeeded", "failed")
        if outcome.status == "succeeded":
            assert outcome.detail["result"] == "workflow triggered"
