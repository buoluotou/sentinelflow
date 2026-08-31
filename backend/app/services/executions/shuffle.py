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
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Callable, Mapping, Optional

from app.services.executions.base import ResponseExecutor
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
    Production uses the default urllib opener; there is NO retry layer
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
        self._transport = transport or urllib.request.urlopen

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
        return self._trigger(dispatch, operation="execute")

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        return self._trigger(dispatch, operation="compensate")

    def _trigger(self, dispatch: ExecutionDispatch, *, operation: str) -> ExecutionOutcome:
        mapping = self._workflows if operation == "execute" else self._reverse_workflows
        workflow_id = mapping.get(dispatch.action)
        if workflow_id is None:
            raise ValueError(
                f"shuffle adapter has no {'reverse ' if operation == 'compensate' else ''}"
                f"workflow configured for action '{dispatch.action}'"
            )
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
            f"{self._credentials.base_url}/api/v1/workflows/{workflow_id}/execute",
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
