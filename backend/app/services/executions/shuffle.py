"""Shuffle adapter — Workflow Orchestration (Phase 3.2.3, frozen §2/§4/§7).

The first REAL external adapter. SentinelFlow only ever TRIGGERS an
already-configured Shuffle workflow; all orchestration logic lives in
Shuffle itself (frozen §2). No fan-out, no polling, no webhooks, no
background tasks, zero automatic retry (E5).

Frozen semantics (design §7, E4):
    succeeded == "workflow trigger confirmed"
NOT "workflow fully completed" — internal workflow results stay in
Shuffle's own execution history. 202 / accepted-without-confirmation is
NEVER succeeded (fail-closed); it lands failed + adapter_error.

HTTP discipline (3.2.2 Secret Boundary):
- Authorization rides EXCLUSIVELY in the ``Authorization: Bearer``
  header via ``AdapterCredentials.auth_headers()`` — never URL, query
  string or body;
- ``SHUFFLE_BASE_URL`` is the ONE AND ONLY base URL;
- outbound idempotency key (frozen §5): every trigger body carries
  ``sentinelflow_execution_id``;
- external duplicate signals (409 / "already triggered") translate to
  ``succeeded`` — an idempotency HIT, not a failure (frozen §5 rule 3);
- failure bodies NEVER enter detail — status + sanitized one-liner
  only, so a hostile/error body cannot smuggle credentials into audit.

Malformed external responses raise ExecutorOutcomeViolation; the
platform parse (D9) judges ``protocol_violation`` — the adapter never
self-declares it.

RC2-R §3.2/§3.5. Two closures on the reverse path:
- the adapter implements ``CompensationBindingContributor``: the reverse
  target (``workflow:<id>`` + the exact ``/execute`` endpoint) is bound at
  BIND time and CONSUMED at SEND time, so the wire call can never diverge
  from the durable binding (a config drift refuses fail-closed, zero
  outbound);
- the production transport is a NO-REDIRECT opener (a 3xx is refused by
  ``HTTPError`` — the Authorization header is never forwarded cross-host
  and the request never leaves the bound endpoint).
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

#: Frozen §4 Shuffle column — exactly the four ✅ cells, nothing else.
#: ``trigger_workflow`` is NOT an action (E2 rejected it): workflow
#: selection is a DEPLOYMENT mapping, never a client-controlled word.
SHUFFLE_ACTIONS = frozenset(
    {"block_source_ip", "isolate_host", "disable_account", "escalate_to_incident"}
)

#: Action -> Settings key holding the target workflow id (frozen E3 flat
#: env model). Each executable action maps to EXACTLY ONE workflow —
#: Single-Active-Adapter, one outbound target per action.
SHUFFLE_WORKFLOW_SETTINGS = {
    "block_source_ip": "SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP",
    "isolate_host": "SHUFFLE_WORKFLOW_ISOLATE_HOST",
    "disable_account": "SHUFFLE_WORKFLOW_DISABLE_ACCOUNT",
    "escalate_to_incident": "SHUFFLE_WORKFLOW_ESCALATE_TO_INCIDENT",
}

#: Optional REVERSE workflows (frozen §4 compensation column).
#: block / isolate are workflow-dependent (default ✅ WHEN a reverse
#: workflow is configured); disable_account is irreversibility-assumed
#: (⚠️ default ❌) and deliberately has NO reverse slot; escalate has no
#: Shuffle compensation at all (§4).
SHUFFLE_REVERSE_WORKFLOW_SETTINGS = {
    "block_source_ip": "SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP",
    "isolate_host": "SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST",
}

#: External duplicate signals (frozen §5 rule 3) — body substrings that
#: mark an idempotency HIT to translate into succeeded.
_DUPLICATE_MARKERS = ("duplicate", "already triggered", "already exists")

#: Keys a Shuffle trigger confirmation may carry the external execution
#: id under (first match wins; absent ids are legal).
_EXTERNAL_ID_KEYS = ("execution_id", "workflow_execution_id", "id")


def workflow_map_from_settings(settings_obj) -> dict[str, str]:
    """Resolve action -> workflow id from Settings; fail-closed on any
    missing/blank id (key NAMES only in errors, never values)."""
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
    """Resolve action -> REVERSE workflow id; unconfigured reverse slots
    stay absent -> supports_compensation() is False for them."""
    reverse: dict[str, str] = {}
    for action, setting_name in SHUFFLE_REVERSE_WORKFLOW_SETTINGS.items():
        workflow_id = str(getattr(settings_obj, setting_name, "") or "").strip()
        if workflow_id:
            reverse[action] = workflow_id
    return reverse


class ShuffleExecutor(ResponseExecutor):
    """Trigger-only Shuffle adapter (synchronous terminal states only).

    ``transport`` is the deployment seam for tests: a callable
    ``transport(request, timeout=...) -> response`` where response has
    ``status``/``read()`` — matching ``urllib.request.urlopen`` shape.
    Production uses a NO-REDIRECT opener (RC2-R §3.5: a 3xx is refused, so
    the ``Authorization`` header is never forwarded cross-host and the real
    request target stays the bound endpoint); there is NO retry layer
    around it (E5 — the transport is invoked exactly once per call).
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
        # RC2-R §3.5: refuse redirects by default — never bare urlopen.
        self._transport = transport or build_no_redirect_opener().open

    @property
    def name(self) -> str:
        return "shuffle"

    def supports(self, action: str) -> bool:
        # Capability = frozen mapping ∩ configured workflows. An action
        # without a configured workflow id is NOT supported (fail-closed
        # G4 rejection beats a boot-time surprise).
        return action in SHUFFLE_ACTIONS and action in self._workflows

    def supports_compensation(self, action: str) -> bool:
        # Frozen §4: workflow-dependent — True only when a reverse
        # workflow is explicitly configured for this action.
        return action in self._reverse_workflows

    # ------------------------------------------------------------------
    # Execute / compensate — one shared trigger path, zero retry
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # RC2-R §3.1/§3.2 — compensation target binding (server-side facts only)
    # ------------------------------------------------------------------
    def compensation_binding_facts(self, dispatch: ExecutionDispatch) -> dict[str, Any]:
        """BIND time: the reverse workflow id + the exact endpoint the wire
        call will use. Assembled from SERVER-SIDE configuration only (the
        reverse mapping + the validated base URL) — never a request body
        field. A missing reverse configuration refuses before any outbound."""
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
        """SEND time: CONSUME the committed binding — the outbound request
        uses the BOUND workflow id + endpoint, never a re-read of mutable
        settings. Any drift between the binding and the current server-side
        configuration refuses FAIL-CLOSED with ZERO outbound (the transport is
        never invoked)."""
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
        # DRIFT GATES (RC2-R §3.2): the bound id must still be the configured
        # reverse mapping for this action, and the bound endpoint must still be
        # what the CURRENT base URL derives. Either mismatch = configuration
        # changed between the durable commit and the wire call -> zero outbound.
        # The adapter NEVER resolves a different workflow id and sends it.
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
        """The ONE endpoint shape this adapter ever targets."""
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
        # Outbound idempotency (frozen §5 rule 2): the platform's
        # execution_id rides in the BODY, never in the URL.
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
            # Frozen §7: accepted WITHOUT synchronous confirmation is
            # NEVER succeeded — fail-closed.
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
            # Explicit trigger confirmation is mandatory (frozen §7):
            # 2xx without it is a structure the platform cannot trust.
            raise ExecutorOutcomeViolation(
                "Shuffle returned 2xx without explicit trigger "
                "confirmation ('success' true missing)"
            )
        external_id = next(
            (body[key] for key in _EXTERNAL_ID_KEYS if body.get(key)), None
        )
        detail: dict = {
            "result": "workflow triggered",  # E4 pinned audit semantics
            "workflow_id": workflow_id,
            "operation": operation,
        }
        if external_id is not None:
            detail["external_execution_id"] = external_id
        return ExecutionOutcome(
            status="succeeded", detail=detail, raw_response=body
        )

    # ------------------------------------------------------------------
    # Error translation (frozen §6 mapping table)
    # ------------------------------------------------------------------
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
            # Frozen §5 rule 3: external duplicate == idempotency HIT —
            # the trigger for THIS execution_id already happened. The hit
            # is ours by construction: the platform's partial unique
            # indexes make a second outbound with the same execution_id
            # impossible, and we never reuse ids across intents. If the
            # 409 body demonstrably references a DIFFERENT external
            # execution id, fail-closed instead (it is not our hit).
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
        """Belt-and-braces: adapter-side strings pass the *** gate too,
        before the service's audit gate ever sees them."""
        return redact_text(text, current_secret_values())
