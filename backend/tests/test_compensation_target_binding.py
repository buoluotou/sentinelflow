"""RC2-R §3.2/§3.3/§3.5/§3.6 — compensation TARGET BINDING (Shuffle + Wazuh).

WHAT THIS PROVES. The C-1 durable reservation guaranteed "commit before the
external reverse call". RC2-R closes the remaining gap: the durable binding
must also name the REAL reverse operation + the exact endpoint the wire call
will use, and the SEND must CONSUME that committed binding — never re-resolve
a different target from mutable configuration after the commit.

Layers:
- ``TestCompensationBindingSchema`` — v2 shape, the new
  ``reverse_operation_ref``, and the fail-closed legacy rule (a v1 detail is
  NEVER parsed as v2 / back-filled).
- ``TestShuffleCompensationBinding`` — bind-time facts, "actual call ==
  durable binding", and every drift gate (mapping drift, endpoint drift,
  missing ref, target mismatch) -> ExecutorConfigError with ZERO outbound.
- ``TestWazuhCompensationBinding`` — same matrix for the frozen
  action->command table (the bound ref is the REAL reverse command, never the
  original action).
- ``TestServiceBindingDiscipline`` — through ``compensate_response``:
  binding committed BEFORE outbound, commit failure -> zero outbound, drift
  -> terminal ``compensation_failed``/``binding_mismatch`` with zero outbound,
  missing facts -> terminal ``compensation_failed``/``binding_missing``,
  timeout -> exactly ONE call, no automatic retry, binding carries no secret.
- ``TestNoRedirectTransport`` — real local HTTP servers: a 3xx is refused,
  the redirect target receives NOTHING (Authorization never forwarded),
  exactly one request hits the first server, and the default transport is
  not bare ``urlopen`` (both adapters).

The pre-existing generic C-1 guarantees (caller rollback / crash survival,
duplicate reservation, real-PostgreSQL concurrency 9/9) stay covered by
``test_compensation_durable_integration.py`` and
``test_compensation_durable_postgres.py`` — this file adds the target-binding
half, not a replacement.
"""
import http.server
import json
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.services.executions import ExecutionDispatch
from app.services.executions.base import ResponseExecutor
from app.services.executions.compensation_binding import (
    COMPENSATION_BINDING_SCHEMA,
    COMPENSATION_REFERENCE_KEY,
    CompensationBinding,
    build_compensation_binding,
    parse_compensation_binding,
)
from app.services.executions.exceptions import (
    ExecutorConfigError,
    ExecutorOutcomeViolation,
)
from app.services.executions.models import ExecutionOutcome
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.service import (
    compensate_response,
    execute_response,
)
from app.services.executions.shuffle import ShuffleExecutor
from app.services.executions.transport import (
    NoRedirectHandler,
    build_no_redirect_opener,
)
from app.services.executions.wazuh import WazuhExecutor
from tests.test_dispatch_durable_integration import FakeStore

FAKE_SECRET = "rc2r-super-secret-token-value"
FAKE_USER = "rc2r-user"

_ALL_WORKFLOWS = {
    "block_source_ip": "wf-block",
    "isolate_host": "wf-isolate",
    "disable_account": "wf-disable",
    "escalate_to_incident": "wf-escalate",
}
_REVERSE_WORKFLOWS = {"block_source_ip": "wf-reverse-block"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class _StubResponse:
    def __init__(self, status=200, body=b""):
        self.status = status
        self._body = body

    def read(self):
        return self._body


class StubTransport:
    """Injected transport double: records every outbound request (and an
    optional shared event marker for ordering proofs) — plays back a scripted
    response or raises a scripted exception."""

    def __init__(self, *, status=200, payload=None, exc=None, events=None):
        self._status = status
        self._payload = payload
        self._exc = exc
        self._events = events
        self.calls: list[dict] = []

    def __call__(self, request, timeout=None):
        if self._events is not None:
            self._events.append("outbound")
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
        body = (
            json.dumps(self._payload).encode("utf-8")
            if self._payload is not None
            else b""
        )
        return _StubResponse(self._status, body)

    @property
    def last(self) -> dict:
        return self.calls[-1]


def _shuffle_creds(base_url="http://shuffle.lab.internal") -> AdapterCredentials:
    return AdapterCredentials(adapter="shuffle", base_url=base_url, api_key=FAKE_SECRET)


def _wazuh_creds(base_url="http://wazuh.lab.internal") -> AdapterCredentials:
    return AdapterCredentials(
        adapter="wazuh", base_url=base_url, username=FAKE_USER, password=FAKE_SECRET
    )


def _shuffle_executor(transport, *, base_url="http://shuffle.lab.internal",
                      reverse_workflows=None, **kwargs) -> ShuffleExecutor:
    return ShuffleExecutor(
        _shuffle_creds(base_url),
        _ALL_WORKFLOWS,
        reverse_workflows=(
            _REVERSE_WORKFLOWS if reverse_workflows is None else reverse_workflows
        ),
        timeout=1.0,
        transport=transport,
        **kwargs,
    )


def _wazuh_executor(transport, *, base_url="http://wazuh.lab.internal") -> WazuhExecutor:
    return WazuhExecutor(_wazuh_creds(base_url), timeout=1.0, transport=transport)


def _dispatch(action="block_source_ip", target="203.0.113.10") -> ExecutionDispatch:
    return ExecutionDispatch(
        execution_id=uuid.uuid4(),
        action=action,
        target=target,
        approval_id=uuid.uuid4(),
    )


def _binding_from_facts(
    executor, dispatch, *, ref=None, endpoint=None, target=None, adapter=None
) -> CompensationBinding:
    """Build a binding the way the SERVICE would, with optional overrides used
    to simulate drift / tampering / legacy shapes."""
    facts = executor.compensation_binding_facts(dispatch)
    if ref is not None:
        facts["reverse_operation_ref"] = ref
    if endpoint is not None:
        facts["endpoint"] = endpoint
    return build_compensation_binding(
        execution_id=uuid.uuid4(),
        original_execution_id=uuid.uuid4(),
        original_dispatch_attempt_id=None,
        approval_id=dispatch.approval_id,
        adapter=adapter or executor.name,
        action=dispatch.action,
        target=target if target is not None else dispatch.target,
        operator="ops-1",
        reason=None,
        original_outcome_state="succeeded",
        prepared_at=datetime.now(timezone.utc),
        dispatch_started_at=datetime.now(timezone.utc),
        contributor_facts=facts,
    )


class _AlwaysFailingExecutor(ResponseExecutor):
    """A contributor whose send boundary refuses (config drift simulation) —
    used to prove the Service maps it to ONE terminal row with zero outbound."""

    def __init__(self, events=None):
        self._events = events

    @property
    def name(self) -> str:
        return "mock"

    def supports(self, action: str) -> bool:
        return True

    def supports_compensation(self, action: str) -> bool:
        return True

    def compensation_binding_facts(self, dispatch):
        return {"reverse_operation_ref": "workflow:wf-1", "endpoint": "http://x/y"}

    def compensate_with_binding(self, dispatch, binding):
        self._events and self._events.append("compensate_with_binding")
        raise ExecutorConfigError("simulated drift at the send boundary")

    def execute(self, dispatch):
        return ExecutionOutcome(status="succeeded", detail={}, raw_response=None)

    def compensate(self, dispatch):  # pragma: no cover — protocol path chosen
        raise AssertionError("legacy compensate must not be used")


def _seed_and_forward(db_session, executor, *, action="block_source_ip",
                      target="203.0.113.10"):
    from tests.test_execution_service import seed_approved

    approval = seed_approved(
        db_session,
        recommendations=[{"action": action, "target": target, "rationale": "lab"}],
    )
    return execute_response(
        db_session,
        approval_id=approval.id,
        execution_id=uuid.uuid4(),
        operator="ops-1",
        executor=executor,
        dispatch_attempt_store=FakeStore(),
    )


# --------------------------------------------------------------------------
# 1. Binding schema (v2) + legacy rule
# --------------------------------------------------------------------------
class TestCompensationBindingSchema:
    def test_schema_is_v2(self):
        assert COMPENSATION_BINDING_SCHEMA == "sentinelflow.compensation_binding.v2"

    def test_reverse_operation_ref_round_trips(self):
        executor = _shuffle_executor(StubTransport())
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        detail = binding.to_detail()
        assert detail["reverse_operation_ref"] == "workflow:wf-reverse-block"
        parsed = parse_compensation_binding(detail)
        assert parsed is not None
        assert parsed.reverse_operation_ref == "workflow:wf-reverse-block"

    def test_v1_detail_is_never_parsed_or_backfilled(self):
        # A legacy v1 shape (no reverse_operation_ref) is NOT upgraded from
        # current config: the parser refuses it outright -> honest UNKNOWN.
        v1_detail = {
            "schema": "sentinelflow.compensation_binding.v1",
            "execution_id": str(uuid.uuid4()),
            "compensation_attempt_id": str(uuid.uuid4()),
            "original_execution_id": str(uuid.uuid4()),
            "approval_id": str(uuid.uuid4()),
            "adapter": "shuffle",
            "reverse_action": "block_source_ip",
            "target": "203.0.113.10",
            "prepared_at": "2026-09-11T00:00:00+00:00",
            "dispatch_started_at": "2026-09-11T00:00:00+00:00",
            "operator": "ops-1",
            "original_outcome_state": "succeeded",
        }
        assert parse_compensation_binding(v1_detail) is None


# --------------------------------------------------------------------------
# 2. Shuffle target binding
# --------------------------------------------------------------------------
class TestShuffleCompensationBinding:
    def test_bind_facts_name_the_real_reverse_workflow_and_endpoint(self):
        executor = _shuffle_executor(StubTransport())
        facts = executor.compensation_binding_facts(_dispatch())
        assert facts["reverse_operation_ref"] == "workflow:wf-reverse-block"
        assert (
            facts["endpoint"]
            == "http://shuffle.lab.internal/api/v1/workflows/wf-reverse-block/execute"
        )

    def test_actual_call_equals_durable_binding(self):
        stub = StubTransport(payload={"success": True, "execution_id": "ext-1"})
        executor = _shuffle_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        outcome = executor.compensate_with_binding(dispatch, binding)
        assert outcome.status == "succeeded"
        assert len(stub.calls) == 1
        # The wire call consumed the BOUND endpoint verbatim...
        assert stub.last["url"] == binding.endpoint
        # ...and the bound workflow id is the one in the URL.
        assert stub.last["url"].endswith(
            f"/api/v1/workflows/{binding.reverse_operation_ref.split(':', 1)[1]}/execute"
        )

    def test_missing_ref_refuses_with_zero_outbound(self):
        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch, ref="")
        with pytest.raises(ExecutorConfigError):
            executor.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_mapping_drift_refuses_with_zero_outbound(self):
        # The binding was committed for wf-reverse-block, but the CURRENT
        # reverse mapping for this action now points elsewhere -> refuse.
        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        drifted = _shuffle_executor(
            stub, reverse_workflows={"block_source_ip": "wf-reverse-2"}
        )
        with pytest.raises(ExecutorConfigError, match="drift"):
            drifted.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_endpoint_drift_refuses_with_zero_outbound(self):
        # Same workflow id, different base URL (rotated config between the
        # durable commit and the wire call) -> refuse.
        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        rotated = _shuffle_executor(stub, base_url="http://shuffle-2.lab.internal")
        with pytest.raises(ExecutorConfigError, match="drift"):
            rotated.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_target_or_adapter_mismatch_refuses(self):
        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        dispatch = _dispatch()
        wrong_target = _binding_from_facts(executor, dispatch, target="other")
        with pytest.raises(ExecutorConfigError, match="target"):
            executor.compensate_with_binding(dispatch, wrong_target)
        wrong_adapter = _binding_from_facts(executor, dispatch, adapter="wazuh")
        with pytest.raises(ExecutorConfigError, match="adapter"):
            executor.compensate_with_binding(dispatch, wrong_adapter)
        assert stub.calls == []

    def test_binding_contains_no_secret(self):
        executor = _shuffle_executor(StubTransport())
        binding = _binding_from_facts(executor, _dispatch())
        assert FAKE_SECRET not in json.dumps(binding.to_detail())


# --------------------------------------------------------------------------
# 3. Wazuh target binding
# --------------------------------------------------------------------------
class TestWazuhCompensationBinding:
    def test_bind_facts_name_the_real_reverse_command_and_endpoint(self):
        executor = _wazuh_executor(StubTransport())
        facts = executor.compensation_binding_facts(_dispatch())
        # The REAL reverse operation — NOT the original action.
        assert facts["reverse_operation_ref"] == "command:unblock-source-ip"
        assert facts["reverse_operation_ref"] != "block_source_ip"
        assert (
            facts["endpoint"]
            == "http://wazuh.lab.internal/api/v1/agents/203.0.113.10/active-response"
        )

    def test_release_host_mapping(self):
        executor = _wazuh_executor(StubTransport())
        facts = executor.compensation_binding_facts(
            _dispatch(action="isolate_host", target="agent001")
        )
        assert facts["reverse_operation_ref"] == "command:release-host"
        assert facts["endpoint"].endswith("/api/v1/agents/agent001/active-response")

    def test_actual_payload_equals_durable_binding(self):
        stub = StubTransport(payload={"success": True, "command_id": "cmd-1"})
        executor = _wazuh_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        outcome = executor.compensate_with_binding(dispatch, binding)
        assert outcome.status == "succeeded"
        assert len(stub.calls) == 1
        assert stub.last["url"] == binding.endpoint
        assert (
            stub.last["body"]["command"]
            == binding.reverse_operation_ref.split(":", 1)[1]
        )

    def test_mapping_drift_refuses_with_zero_outbound(self):
        # Binding says command:release-host but the dispatch action is
        # block_source_ip (whose frozen reverse is unblock-source-ip).
        stub = StubTransport(payload={"success": True})
        executor = _wazuh_executor(stub)
        dispatch = _dispatch(action="block_source_ip")
        binding = _binding_from_facts(executor, dispatch, ref="command:release-host")
        with pytest.raises(ExecutorConfigError, match="drift"):
            executor.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_unbound_or_uncertified_command_refuses(self):
        stub = StubTransport(payload={"success": True})
        executor = _wazuh_executor(stub)
        dispatch = _dispatch()
        for bad_ref in ("", "command:", "command:rm-rf", "block_source_ip"):
            binding = _binding_from_facts(executor, dispatch, ref=bad_ref)
            with pytest.raises(ExecutorConfigError):
                executor.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_endpoint_drift_refuses_with_zero_outbound(self):
        stub = StubTransport(payload={"success": True})
        executor = _wazuh_executor(stub)
        dispatch = _dispatch()
        binding = _binding_from_facts(executor, dispatch)
        rotated = _wazuh_executor(stub, base_url="http://wazuh-2.lab.internal")
        with pytest.raises(ExecutorConfigError, match="drift"):
            rotated.compensate_with_binding(dispatch, binding)
        assert stub.calls == []

    def test_binding_contains_no_secret(self):
        executor = _wazuh_executor(StubTransport())
        binding = _binding_from_facts(executor, _dispatch())
        assert FAKE_SECRET not in json.dumps(binding.to_detail())


# --------------------------------------------------------------------------
# 4. Service discipline (through compensate_response)
# --------------------------------------------------------------------------
class TestServiceBindingDiscipline:
    def test_binding_committed_before_outbound(self, db_session):
        events: list[str] = []
        stub = StubTransport(payload={"success": True}, events=events)
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        events.clear()  # observe the compensation phase only
        store = FakeStore(events=events)
        compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            compensation_attempt_store=store,
        )
        assert events == ["record", "outbound"], (
            "the durable binding must be committed BEFORE the external call"
        )
        assert len(store.recorded) == 1
        assert store.recorded[0].reverse_operation_ref == "workflow:wf-reverse-block"

    def test_binding_commit_failure_means_zero_outbound(self, db_session):
        events: list[str] = []
        stub = StubTransport(payload={"success": True}, events=events)
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        calls_after_forward = len(stub.calls)
        events.clear()
        store = FakeStore(
            events=events, raise_exc=SQLAlchemyError("durable commit failed")
        )
        with pytest.raises(SQLAlchemyError):
            compensate_response(
                db_session,
                compensates_execution_id=forward.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                compensation_attempt_store=store,
            )
        assert events == ["record"]
        assert len(stub.calls) == calls_after_forward  # zero compensation outbound

    def test_send_boundary_drift_ends_the_chain_with_zero_outbound(self, db_session):
        events: list[str] = []
        stub = StubTransport(payload={"success": True}, events=events)
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        calls_after_forward = len(stub.calls)
        events.clear()
        drifting = _AlwaysFailingExecutor(events=events)
        result = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=drifting,
            compensation_attempt_store=FakeStore(events=events),
        )
        assert result.final_decision == "compensation_failed"
        assert len(stub.calls) == calls_after_forward
        assert events == ["record", "compensate_with_binding"]

    def test_missing_facts_end_the_chain_before_any_binding(self, db_session):
        # A shuffle executor WITHOUT a reverse workflow: the service refuses
        # before the durable commit and the adapter is never called.
        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        calls_after_forward = len(stub.calls)
        no_reverse = _shuffle_executor(stub, reverse_workflows={})
        store = FakeStore()
        result = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=no_reverse,
            compensation_attempt_store=store,
        )
        assert result.final_decision == "compensation_failed"
        assert store.recorded == []
        assert len(stub.calls) == calls_after_forward  # zero compensation outbound

    def test_timeout_makes_exactly_one_call_no_retry(self, db_session):
        stub = StubTransport(exc=TimeoutError("lab timeout"))
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        store = FakeStore()
        result = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            compensation_attempt_store=store,
        )
        assert result.final_decision == "compensation_failed"
        # exactly ONE outbound attempt for the compensation phase (the forward
        # phase made one too) — zero automatic retry.
        assert len(stub.calls) == 2
        # the durable attempt survives for manual reconciliation
        assert len(store.recorded) == 1

    def test_duplicate_compensation_does_not_reach_the_external_second_time(
        self, db_session
    ):
        from app.services.executions.service import ExecutionAlreadyCompensated

        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            compensation_attempt_store=FakeStore(),
        )
        calls_after_first = len(stub.calls)
        with pytest.raises(ExecutionAlreadyCompensated):
            compensate_response(
                db_session,
                compensates_execution_id=forward.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                compensation_attempt_store=FakeStore(),
            )
        assert len(stub.calls) == calls_after_first  # no second external call

    def test_terminal_row_references_the_committed_attempt(self, db_session):
        from app.models import ExecutionLog

        stub = StubTransport(payload={"success": True})
        executor = _shuffle_executor(stub)
        forward = _seed_and_forward(db_session, executor)
        store = FakeStore()
        result = compensate_response(
            db_session,
            compensates_execution_id=forward.execution_id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=executor,
            compensation_attempt_store=store,
        )
        terminal = (
            db_session.query(ExecutionLog)
            .filter(ExecutionLog.execution_id == result.execution_id)
            .filter(ExecutionLog.decision == "compensation_succeeded")
            .one()
        )
        assert (
            terminal.detail[COMPENSATION_REFERENCE_KEY]
            == store.recorded[0].compensation_attempt_id
        )


# --------------------------------------------------------------------------
# 5. No-redirect transport (real local HTTP servers)
# --------------------------------------------------------------------------
class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    """POST stub: records the request, answers with a scripted status +
    optional Location header."""

    def do_POST(self):  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.requests.append(
            {"path": self.path, "headers": dict(self.headers)}
        )
        self.send_response(self.server.scripted_status)
        if self.server.scripted_location:
            self.send_header("Location", self.server.scripted_location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # silence the test output
        pass


class _LocalStubServer:
    def __init__(self, *, status=302, location=None):
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        self._httpd.requests = []
        self._httpd.scripted_status = status
        self._httpd.scripted_location = location
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    @property
    def requests(self) -> list:
        return self._httpd.requests

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


class TestNoRedirectTransport:
    def test_handler_declines_every_redirect(self):
        handler = NoRedirectHandler()
        assert handler.redirect_request(None, None, 302, "Found", None, "http://x") is None

    def test_default_transports_are_not_bare_urlopen(self):
        for executor in (_shuffle_executor(None), _wazuh_executor(None)):
            transport = executor._transport
            assert transport is not urllib.request.urlopen
            # a bound method of a real opener (default handlers + no-redirect)
            owner = getattr(transport, "__self__", None)
            assert isinstance(owner, urllib.request.OpenerDirector)
            assert any(
                isinstance(handler, NoRedirectHandler)
                for handler in owner.handlers
            )

    def test_shuffle_same_host_redirect_is_refused_with_one_request(self):
        server = _LocalStubServer(status=302, location="/evil")
        try:
            executor = _shuffle_executor(None, base_url=server.base_url)
            outcome = executor.compensate(_dispatch())
            assert outcome.status == "failed"
            assert outcome.detail["classification"] == "adapter_error"
            assert len(server.requests) == 1  # never re-issued
            assert server.requests[0]["path"].endswith("/execute")
        finally:
            server.stop()

    def test_shuffle_cross_host_redirect_never_reaches_the_second_host(self):
        target = _LocalStubServer(status=200)
        try:
            attacker = _LocalStubServer(
                status=302, location=f"{target.base_url}/steal"
            )
            try:
                executor = _shuffle_executor(None, base_url=attacker.base_url)
                outcome = executor.compensate(_dispatch())
                assert outcome.status == "failed"
                assert len(attacker.requests) == 1
                # The Authorization header was NEVER forwarded to the second
                # host: it received zero requests.
                assert target.requests == []
            finally:
                attacker.stop()
        finally:
            target.stop()

    def test_wazuh_cross_host_redirect_never_reaches_the_second_host(self):
        target = _LocalStubServer(status=200)
        try:
            attacker = _LocalStubServer(
                status=302, location=f"{target.base_url}/steal"
            )
            try:
                executor = _wazuh_executor(None, base_url=attacker.base_url)
                outcome = executor.compensate(_dispatch())
                assert outcome.status == "failed"
                assert outcome.detail["classification"] == "adapter_error"
                assert len(attacker.requests) == 1
                assert target.requests == []
            finally:
                attacker.stop()
        finally:
            target.stop()

    def test_wazuh_redirect_is_refused_and_never_retried(self):
        server = _LocalStubServer(status=301, location="/elsewhere")
        try:
            executor = _wazuh_executor(None, base_url=server.base_url)
            outcome = executor.compensate(_dispatch())
            assert outcome.status == "failed"
            assert len(server.requests) == 1
        finally:
            server.stop()

    def test_service_path_also_uses_the_no_redirect_transport(self, db_session):
        # A contributor on the SERVICE path consumes the bound endpoint and the
        # default (no-redirect) transport — a redirecting bound target fails
        # closed with exactly one request and a failed terminal.
        server = _LocalStubServer(status=302, location="/evil")
        try:
            executor = _shuffle_executor(None, base_url=server.base_url)
            forward = _seed_and_forward(db_session, executor)
            requests_after_forward = len(server.requests)
            store = FakeStore()
            result = compensate_response(
                db_session,
                compensates_execution_id=forward.execution_id,
                execution_id=uuid.uuid4(),
                operator="ops-1",
                executor=executor,
                compensation_attempt_store=store,
            )
            assert result.final_decision == "compensation_failed"
            # exactly ONE compensation attempt hit the wire (the redirect was
            # refused, never re-issued) — on top of the forward attempt.
            assert len(server.requests) == requests_after_forward + 1
            assert len(store.recorded) == 1
        finally:
            server.stop()
