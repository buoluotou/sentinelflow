"""Shuffle adapter for workflow orchestration.

SentinelFlow only triggers an already-configured Shuffle workflow; all
orchestration logic lives in Shuffle itself. No fan-out, no polling, no
webhooks, no background tasks and no automatic retry.

Semantics:
succeeded == "workflow trigger confirmed"
It does not mean "workflow fully completed" — internal workflow results
stay in Shuffle's own execution history. A 202 (accepted without
confirmation) is never succeeded: it is recorded as failed +
adapter_error, because a trigger that was not confirmed synchronously
cannot be treated as an executed response.

HTTP discipline:
- the credential rides only the ``Authorization: Bearer`` header via
``AdapterCredentials.auth_headers()`` — never the URL, query string or
body;
- ``SHUFFLE_BASE_URL`` is the only base URL the adapter targets;
- every trigger body carries ``sentinelflow_execution_id`` as the
outbound idempotency key;
- external duplicate signals (409 / "already triggered") translate to
``succeeded``: the trigger for that execution already happened, so it
is an idempotency hit rather than a failure;
- failure bodies never enter detail — the status plus a sanitized
one-liner only, so a hostile or error body cannot smuggle credentials
into the audit trail.

Malformed external responses raise ExecutorOutcomeViolation; the
``protocol_violation`` classification is decided by the platform's
response parse, never self-declared by the adapter.

Two properties on the reverse path:
- the adapter implements ``CompensationBindingContributor``: the reverse
target (``workflow:<id>`` plus the exact ``/execute`` endpoint) is bound
at bind time and consumed at send time, so the wire call can never
diverge from the durable binding (a config drift refuses fail-closed
with no outbound request);
- the production transport is a no-redirect opener (a 3xx is refused by
``HTTPError``, so the Authorization header is never forwarded
cross-host and the request never leaves the bound endpoint).
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional

from app.services.executions.base import ResponseExecutor
from app.services.executions.compensation_binding import (
    CompensationBinding,
    CompensationBindingContributor,  # noqa: F401 — protocol marker (isinstance)
)
from app.services.executions.exceptions import (
    ExecutorConfigError,
    ExecutorOutcomeViolation,
)
from app.services.executions.models import ExecutionDispatch, ExecutionOutcome
from app.services.executions.secrets import (
    AdapterCredentials,
    current_secret_values,
    redact_text,
    validate_base_url,
)
from app.services.executions.transport import build_no_redirect_opener

# Exactly the four actions this adapter supports.
# ``trigger_workflow`` is not an action: which workflow runs is a
# deployment mapping, never a client-controlled word.
SHUFFLE_ACTIONS = frozenset(
    {"block_source_ip", "isolate_host", "disable_account", "escalate_to_incident"}
)

# Action -> Settings key holding the target workflow id. Each
# executable action maps to exactly one workflow, so an action has a
# single outbound target.
SHUFFLE_WORKFLOW_SETTINGS = {
    "block_source_ip": "SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP",
    "isolate_host": "SHUFFLE_WORKFLOW_ISOLATE_HOST",
    "disable_account": "SHUFFLE_WORKFLOW_DISABLE_ACCOUNT",
    "escalate_to_incident": "SHUFFLE_WORKFLOW_ESCALATE_TO_INCIDENT",
}

# Optional reverse workflows. block / isolate are workflow-dependent:
# compensation is available only when a reverse workflow is explicitly
# configured. disable_account is assumed irreversible and has no reverse
# slot, and escalate_to_incident has no Shuffle compensation at all.
SHUFFLE_REVERSE_WORKFLOW_SETTINGS = {
    "block_source_ip": "SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP",
    "isolate_host": "SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST",
}

# External duplicate signals — body substrings that mark an idempotency
# hit to translate into ``succeeded``.
_DUPLICATE_MARKERS = ("duplicate", "already triggered", "already exists")

# Keys a Shuffle trigger confirmation may carry the external execution
# id under (first match wins; absent ids are legal).
_EXTERNAL_ID_KEYS = ("execution_id", "workflow_execution_id", "id")


def workflow_map_from_settings(settings_obj) -> dict[str, str]:
    """Resolve action -> workflow id from Settings; refuse fail-closed on
any missing or blank id. Errors name the settings keys only, never
their values."""
    workflows: dict[str, str] = {}
    missing: list[str] = []
    for action, setting_name in SHUFFLE_WORKFLOW_SETTINGS.items():
        workflow_id = str(getattr(settings_obj, setting_name, "") or "").strip()
        if not workflow_id:
            missing.append(setting_name)
        else:
            workflows[action] = workflow_id
    if missing:
        raise ExecutorConfigError(
            "Shuffle adapter is missing workflow configuration: "
            f"{', '.join(missing)} (key names only — values are never "
            "reported). Refusing to run fail-closed."
        )
    return workflows


def reverse_workflow_map_from_settings(settings_obj) -> dict[str, str]:
    """Resolve action -> reverse workflow id; an unconfigured reverse slot
stays absent, so ``supports_compensation()`` is False for it."""
    reverse: dict[str, str] = {}
    for action, setting_name in SHUFFLE_REVERSE_WORKFLOW_SETTINGS.items():
        workflow_id = str(getattr(settings_obj, setting_name, "") or "").strip()
        if workflow_id:
            reverse[action] = workflow_id
    return reverse


class ShuffleExecutor(ResponseExecutor):
    """Shuffle adapter that only triggers workflows (synchronous terminal
states only).

``transport`` is the deployment seam for tests: a callable
``transport(request, timeout=...) -> response`` where response has
``status``/``read()`` — matching ``urllib.request.urlopen`` shape.
Production uses a no-redirect opener (a 3xx is refused, so the
``Authorization`` header is never forwarded cross-host and the request
target stays the bound endpoint). There is no retry layer around it:
the transport is invoked exactly once per call.
"""

    def __init__(
        self,
        credentials: AdapterCredentials,
        workflows: Mapping[str, str],
        *,
        reverse_workflows: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        transport: Callable | None = None,
    ):
        unknown = set(workflows) - SHUFFLE_ACTIONS
        if unknown:
            raise ExecutorConfigError(
                f"Shuffle workflow mapping contains unknown actions: "
                f"{sorted(unknown)}"
            )
        if credentials.adapter != "shuffle":
            raise ExecutorConfigError(
                f"ShuffleExecutor received credentials for adapter "
                f"'{credentials.adapter}'"
            )
        # Defense-in-depth: re-validate the base URL at construction.
        validate_base_url("shuffle", credentials.base_url)
        if timeout <= 0:
            raise ExecutorConfigError("Shuffle timeout must be positive")
        self._credentials = credentials
        self._workflows = dict(workflows)
        self._reverse_workflows = dict(reverse_workflows or {})
        self._timeout = timeout
        # Refuse redirects by default — never a bare urlopen.
        self._transport = transport or build_no_redirect_opener().open

    @property
    def name(self) -> str:
        return "shuffle"

    def supports(self, action: str) -> bool:
        # Capability = the supported actions intersected with the
        # configured workflows. An action with no configured workflow id is
        # not supported, so it is rejected up front rather than at send
        # time.
        return action in SHUFFLE_ACTIONS and action in self._workflows

    def supports_compensation(self, action: str) -> bool:
        # Workflow-dependent: True only when a reverse workflow is
        # explicitly configured for this action.
        return action in self._reverse_workflows

    #
    # Execute / compensate — one shared trigger path, zero retry
    #
    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        workflow_id = self._required_workflow(
            dispatch.action, self._workflows, reverse=False
        )
        return self._trigger(
            dispatch,
            operation="execute",
            workflow_id=workflow_id,
            endpoint=self._execution_endpoint(workflow_id),
        )

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        workflow_id = self._required_workflow(
            dispatch.action, self._reverse_workflows, reverse=True
        )
        return self._trigger(
            dispatch,
            operation="compensate",
            workflow_id=workflow_id,
            endpoint=self._execution_endpoint(workflow_id),
        )

    #
    # Compensation target binding (server-side facts only)
    #
    def compensation_binding_facts(self, dispatch: ExecutionDispatch) -> dict[str, Any]:
        """Bind time: the reverse workflow id and the exact endpoint the
wire call will use. Assembled from server-side configuration only
(the reverse mapping plus the validated base URL), never from a
request body field, so the target cannot be chosen by the caller.
A missing reverse configuration refuses before any outbound
request."""
        workflow_id = self._reverse_workflows.get(dispatch.action)
        if not workflow_id:
            raise ExecutorConfigError(
                "shuffle adapter has no reverse workflow configured for "
                f"action '{dispatch.action}' — refusing to bind a reverse "
                "target (zero outbound)"
            )
        return {
            "reverse_operation_ref": f"workflow:{workflow_id}",
            "endpoint": self._execution_endpoint(workflow_id),
        }

    def compensate_with_binding(
        self, dispatch: ExecutionDispatch, binding: CompensationBinding
    ) -> ExecutionOutcome:
        """Send time: consume the committed binding. The outbound request
uses the bound workflow id and endpoint, never a re-read of mutable
settings. Any drift between the binding and the current server-side
configuration refuses fail-closed with no outbound request: the
transport is never invoked."""
        ref = binding.reverse_operation_ref or ""
        prefix = "workflow:"
        workflow_id = ref[len(prefix):] if ref.startswith(prefix) else ""
        if not workflow_id:
            raise ExecutorConfigError(
                "compensation binding carries no shuffle workflow reference "
                "(reverse_operation_ref) — refusing fail-closed before any "
                "outbound"
            )
        if binding.adapter != self.name:
            raise ExecutorConfigError(
                "compensation binding adapter does not match this executor — "
                "refusing fail-closed before any outbound"
            )
        if binding.target != dispatch.target:
            raise ExecutorConfigError(
                "compensation binding target does not match the dispatch "
                "target — refusing fail-closed before any outbound"
            )
        # Drift gates: the bound id must still be the configured reverse
        # mapping for this action, and the bound endpoint must still be the
        # one the current base URL derives. Either mismatch means the
        # configuration changed between the durable commit and the wire
        # call, so there is no outbound request. A different workflow id is
        # never resolved and sent.
        if self._reverse_workflows.get(dispatch.action) != workflow_id:
            raise ExecutorConfigError(
                "compensation binding workflow id does not match the current "
                "reverse mapping (config drift refused); zero outbound"
            )
        if binding.endpoint != self._execution_endpoint(workflow_id):
            raise ExecutorConfigError(
                "compensation binding endpoint does not match the configured "
                "shuffle target (config drift refused); zero outbound"
            )
        return self._trigger(
            dispatch,
            operation="compensate",
            workflow_id=workflow_id,
            endpoint=binding.endpoint,
        )

    def _execution_endpoint(self, workflow_id: str) -> str:
        """The only endpoint shape this adapter targets."""
        return f"{self._credentials.base_url}/api/v1/workflows/{workflow_id}/execute"

    @staticmethod
    def _required_workflow(
        action: str, mapping: Mapping[str, str], *, reverse: bool
    ) -> str:
        workflow_id = mapping.get(action)
        if workflow_id is None:
            raise ValueError(
                f"shuffle adapter has no {'reverse ' if reverse else ''}"
                f"workflow configured for action '{action}'"
            )
        return workflow_id

    def _trigger(
        self,
        dispatch: ExecutionDispatch,
        *,
        operation: str,
        workflow_id: str,
        endpoint: str,
    ) -> ExecutionOutcome:
        # Outbound idempotency: the platform's execution_id rides in the
        # body, never in the URL.
        payload = {
            "sentinelflow_execution_id": str(dispatch.execution_id),
            "operation": operation,
            "action": dispatch.action,
            "target": dispatch.target,
            "approval_id": str(dispatch.approval_id),
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                **self._credentials.auth_headers(),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            response = self._transport(request, timeout=self._timeout)
        except TimeoutError:
            # socket.timeout is a TimeoutError alias — one classification.
            return self._failure("timeout", "shuffle trigger timed out")
        except urllib.error.HTTPError as error:
            return self._on_http_error(error, dispatch)
        except (urllib.error.URLError, OSError):
            return self._failure(
                "adapter_unavailable", "shuffle is unreachable (connection failed)"
            )

        status = getattr(response, "status", None)
        if status == 202:
            # Accepted without synchronous confirmation is never
            # succeeded: fail-closed, because the trigger state is unknown.
            return self._failure(
                "adapter_error",
                "shuffle accepted the trigger (202) without synchronous "
                "confirmation; fail-closed",
            )
        if status not in (200, 201):
            return self._failure(
                "adapter_error", f"shuffle trigger returned HTTP {status}"
            )
        body = self._read_json_body(response)
        if not isinstance(body, dict):
            raise ExecutorOutcomeViolation(
                "Shuffle trigger confirmation is not a JSON object — "
                "cannot confirm workflow trigger"
            )
        if body.get("success") is not True:
            # An explicit trigger confirmation is mandatory: a 2xx without
            # it is a response the platform cannot trust.
            raise ExecutorOutcomeViolation(
                "Shuffle returned 2xx without explicit trigger "
                "confirmation ('success' true missing)"
            )
        external_id = next(
            (body[key] for key in _EXTERNAL_ID_KEYS if body.get(key)), None
        )
        detail: dict = {
            "result": "workflow triggered",  # pinned audit semantics
            "workflow_id": workflow_id,
            "operation": operation,
        }
        if external_id is not None:
            detail["external_execution_id"] = external_id
        return ExecutionOutcome(
            status="succeeded", detail=detail, raw_response=body
        )

    #
    # Error translation (status -> classification mapping)
    #
    def _on_http_error(
        self, error: urllib.error.HTTPError, dispatch: ExecutionDispatch
    ) -> ExecutionOutcome:
        status = error.code
        try:
            body = error.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 — an unreadable body is not fatal
            body = ""
        lowered = body.lower()
        if status == 409 and any(marker in lowered for marker in _DUPLICATE_MARKERS):
            # An external duplicate is an idempotency hit: the trigger for
            # this execution_id already happened. The hit is ours by
            # construction, because the platform's partial unique indexes
            # make a second outbound with the same execution_id impossible
            # and ids are never reused across intents. If the 409 body
            # references a different external execution id, it is not our
            # hit, so the call fails closed instead.
            foreign_reference = False
            try:
                conflict_body = json.loads(body)
            except ValueError:
                conflict_body = None
            if isinstance(conflict_body, dict):
                foreign_reference = any(
                    conflict_body.get(key)
                    and str(dispatch.execution_id) != str(conflict_body[key])
                    for key in _EXTERNAL_ID_KEYS
                )
            if not foreign_reference:
                return ExecutionOutcome(
                    status="succeeded",
                    detail={
                        "result": "workflow triggered",
                        "idempotent_duplicate": True,
                    },
                    raw_response=None,
                )
        classification = "adapter_unavailable" if status in (502, 503, 504) else "adapter_error"
        reason = self._sanitize(f"shuffle trigger rejected with HTTP {status}")
        return self._failure(classification, reason)

    def _read_json_body(self, response) -> dict:
        try:
            raw = response.read()
        except Exception as exc:  # noqa: BLE001
            raise ExecutorOutcomeViolation(
                f"Shuffle response body unreadable: {type(exc).__name__}"
            ) from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ExecutorOutcomeViolation(
                "Shuffle trigger response is not valid JSON — cannot "
                "confirm workflow trigger"
            )

    def _failure(self, classification: str, reason: str) -> ExecutionOutcome:
        return ExecutionOutcome(
            status="failed",
            detail={"classification": classification, "reason": self._sanitize(reason)},
            raw_response=None,
        )

    @staticmethod
    def _sanitize(text: str) -> str:
        """Adapter-side strings are redacted here as well, so they are
already clean before the service's audit gate sees them."""
        return redact_text(text, current_secret_values())
