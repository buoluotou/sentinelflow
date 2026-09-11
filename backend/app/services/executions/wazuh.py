"""Wazuh adapter — Endpoint Security Response (Phase 3.2.4).

The second REAL external adapter. Wazuh's frozen responsibility is
ENDPOINT SECURITY RESPONSE ONLY: active-response commands against
agents (quarantine / firewall block / account disable). It is NOT a
workflow orchestrator (Shuffle), NOT a case system (TheHive), NOT the
analysis layer. Wazuh NEVER writes to the SentinelFlow database, never
touches Incident / EventRisk / Approval — the only fact it produces is
one ExecutionOutcome flowing through D9 into execution_log.

Frozen capability (3.2.4 adjudication):
    isolate_host     ✅  active response quarantine
    disable_account  ✅  user disable
    block_source_ip  ✅  firewall block
    escalate_to_incident ❌ (TheHive)   hunt_related_activity ❌ (TheHive)
    monitor_only ❌ (analysis layer)

Frozen compensation:
    isolate_host    -> release_host       ✅
    block_source_ip -> unblock_source_ip  ✅
    disable_account -> ❌ account recovery needs human confirmation —
                       NEVER simulated.

Frozen semantics: request -> response -> decision -> execution_log.
succeeded requires an explicit synchronous confirmation (200/201 +
``success: true``); 202 / accepted-only is NEVER succeeded (fail-
closed, no waiting state — 3.1 froze "no asynchronous execution
facts"). Duplicate signals on 409 translate to succeeded (idempotency
hit). Zero automatic retry (E5). Malformed or ambiguous confirmations
raise ExecutorOutcomeViolation — protocol_violation is adjudicated by
the platform parse ONLY (D9). Credentials: WAZUH_API_USER /
WAZUH_API_PASSWORD -> Basic Authorization header via the 3.2.2 Secret
Boundary; the secret never rides URL / query / body / detail.

RC2-R §3.3/§3.5. Two closures on the reverse path:
- the adapter implements ``CompensationBindingContributor``: the reverse
  target (``command:<cmd>`` + the exact active-response endpoint) is bound
  at BIND time and CONSUMED at SEND time, so the wire call can never
  diverge from the durable binding (a mapping/config drift refuses
  fail-closed, zero outbound). ``block_source_ip`` is NEVER recorded as the
  reverse operation itself — the bound ref is the real reverse command
  (``command:unblock-source-ip`` / ``command:release-host``);
- the production transport is a NO-REDIRECT opener (a 3xx is refused by
  ``HTTPError`` — the Authorization header is never forwarded cross-host
  and the request never leaves the bound endpoint).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable

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

#: 3.2.4 adjudication — exactly these three endpoint capabilities.
#: escalate / hunt belong to TheHive; monitor_only to the analysis
#: layer; none of them may ever be invented here.
WAZUH_ACTIONS = frozenset({"isolate_host", "disable_account", "block_source_ip"})

#: Action -> active-response command (forward direction).
WAZUH_COMMANDS = {
    "isolate_host": "quarantine-host",
    "disable_account": "disable-account",
    "block_source_ip": "block-source-ip",
}

#: Reverse commands (frozen compensation table). disable_account is
#: DELIBERATELY absent — account recovery needs human confirmation; the
#: adapter never simulates a compensation Wazuh does not provide.
WAZUH_REVERSE_COMMANDS = {
    "isolate_host": "release-host",
    "block_source_ip": "unblock-source-ip",
}

#: The CERTIFIED reverse-command set (RC2-R §3.3): a durable binding's
#: ``command:`` reference is accepted only when it names one of these.
WAZUH_CERTIFIED_REVERSE_COMMANDS = frozenset(WAZUH_REVERSE_COMMANDS.values())

#: External duplicate signals (frozen §5) — idempotency HITs for the
#: SAME execution_id -> command pair.
_DUPLICATE_MARKERS = ("already executed", "duplicate", "already exists")

#: Conflict signals that betray a REUSE attempt: the same execution_id
#: bound to a DIFFERENT command must stay a hard failure — never
#: translate to an idempotent hit, never overwrite.
_MISMATCH_MARKERS = ("different action", "different command", "action mismatch",
                     "already used for")

#: Agent reachability signals inside an HTTP error body.
_OFFLINE_MARKERS = ("disconnected", "offline", "unreachable")

#: Keys a 409 body may carry the platform execution id under. A value
#: different from ours proves the conflict belongs to ANOTHER execution
#: — fail closed, never claim a foreign hit.
_EXECUTION_ID_KEYS = ("sentinelflow_execution_id", "execution_id")

#: agent_status values that still count as an unambiguous synchronous
#: confirmation. Anything else (e.g. "unknown", "running") leaves the
#: fact undecided — D9 territory, never adapter discretion.
_CONFIRMED_AGENT_STATUSES = frozenset(
    {"completed", "confirmed", "done", "success", "ok"}
)

#: A dispatch target rides the URL path as the agent id; only this
#: shape is legal. Anything else is a path-injection attempt — refused
#: BEFORE any outbound (D9 adjudicates as protocol_violation).
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class WazuhExecutor(ResponseExecutor):
    """Endpoint-response Wazuh adapter (synchronous terminal states).

    ``transport`` is the deployment seam for tests: a callable
    ``transport(request, timeout=...) -> response`` where response has
    ``status``/``read()`` — matching ``urllib.request.urlopen`` shape.
    Production uses a NO-REDIRECT opener (RC2-R §3.5: a 3xx is refused, so
    the ``Authorization`` header is never forwarded cross-host and the real
    request target stays the bound endpoint); there is NO retry layer,
    NO polling and NO callback surface around it (E5 — the transport is
    invoked exactly once per call).
    """

    def __init__(
        self,
        credentials: AdapterCredentials,
        *,
        timeout: float = 30.0,
        transport: Callable | None = None,
    ):
        if credentials.adapter != "wazuh":
            raise ExecutorConfigError(
                f"WazuhExecutor received credentials for adapter "
                f"'{credentials.adapter}'"
            )
        # Defense-in-depth: re-validate the base URL at construction.
        validate_base_url("wazuh", credentials.base_url)
        if timeout <= 0:
            raise ExecutorConfigError("Wazuh timeout must be positive")
        self._credentials = credentials
        self._timeout = timeout
        # RC2-R §3.5: refuse redirects by default — never bare urlopen.
        self._transport = transport or build_no_redirect_opener().open

    @property
    def name(self) -> str:
        return "wazuh"

    def supports(self, action: str) -> bool:
        return action in WAZUH_ACTIONS

    def supports_compensation(self, action: str) -> bool:
        # isolate / block have real reverse commands; disable_account
        # stays False — never simulate what Wazuh does not provide.
        return action in WAZUH_REVERSE_COMMANDS

    # ------------------------------------------------------------------
    # Execute / compensate — one shared send path, zero retry
    # ------------------------------------------------------------------
    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        command = WAZUH_COMMANDS.get(dispatch.action)
        if command is None:
            raise ValueError(
                f"wazuh adapter has no command for action '{dispatch.action}'"
            )
        return self._send(dispatch, command=command)

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        reverse = self._reverse_command(dispatch.action)
        return self._send(dispatch, command=reverse)

    # ------------------------------------------------------------------
    # RC2-R §3.1/§3.3 — compensation target binding (server-side facts only)
    # ------------------------------------------------------------------
    def compensation_binding_facts(self, dispatch: ExecutionDispatch) -> dict[str, Any]:
        """BIND time: the REAL reverse command + the exact active-response
        endpoint the wire call will use. Assembled from the frozen server-side
        action->command table + the validated base URL — never a request body
        field, and never the original action masquerading as the reverse
        operation. A missing reverse command or an unsafe target refuses
        before any outbound."""
        reverse = WAZUH_REVERSE_COMMANDS.get(dispatch.action)
        if reverse is None:
            raise ExecutorConfigError(
                "wazuh adapter has no reverse command for "
                f"'{dispatch.action}' — refusing to bind a reverse target "
                "(zero outbound)"
            )
        target = dispatch.target or ""
        if not _SAFE_TARGET.fullmatch(target):
            raise ExecutorConfigError(
                "wazuh dispatch target is not a safe agent identifier — "
                "refusing to bind a reverse target (zero outbound)"
            )
        return {
            "reverse_operation_ref": f"command:{reverse}",
            "endpoint": self._active_response_endpoint(target),
        }

    def compensate_with_binding(
        self, dispatch: ExecutionDispatch, binding: CompensationBinding
    ) -> ExecutionOutcome:
        """SEND time: CONSUME the committed binding — the outbound payload
        carries the BOUND command and targets the BOUND endpoint, never a
        re-read of mutable settings. Any drift between the binding and the
        current server-side mapping/configuration refuses FAIL-CLOSED with
        ZERO outbound (the transport is never invoked)."""
        ref = binding.reverse_operation_ref or ""
        prefix = "command:"
        command = ref[len(prefix):] if ref.startswith(prefix) else ""
        if command not in WAZUH_CERTIFIED_REVERSE_COMMANDS:
            raise ExecutorConfigError(
                "compensation binding carries no certified wazuh reverse "
                "command (reverse_operation_ref) — refusing fail-closed "
                "before any outbound"
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
        target = dispatch.target or ""
        if not _SAFE_TARGET.fullmatch(target):
            raise ExecutorOutcomeViolation(
                "wazuh dispatch target is not a safe agent identifier "
                "(path-injection shape refused before outbound)"
            )
        # DRIFT GATES (RC2-R §3.3): the bound command must still be the frozen
        # table's reverse for this action, and the bound endpoint must still be
        # what the CURRENT base URL + target derive. Either mismatch =
        # mapping/configuration changed between the durable commit and the wire
        # call -> zero outbound. The adapter NEVER resolves a different
        # command and sends it.
        if WAZUH_REVERSE_COMMANDS.get(dispatch.action) != command:
            raise ExecutorConfigError(
                "compensation binding reverse command does not match the "
                "frozen action->command table (mapping drift refused); "
                "zero outbound"
            )
        if binding.endpoint != self._active_response_endpoint(target):
            raise ExecutorConfigError(
                "compensation binding endpoint does not match the configured "
                "wazuh target (config drift refused); zero outbound"
            )
        return self._send(dispatch, command=command, endpoint=binding.endpoint)

    @staticmethod
    def _reverse_command(action: str) -> str:
        reverse = WAZUH_REVERSE_COMMANDS.get(action)
        if reverse is None:
            raise ValueError(
                f"wazuh adapter has no reverse command for '{action}'"
            )
        return reverse

    def _active_response_endpoint(self, target: str) -> str:
        """The ONE endpoint shape this adapter ever targets."""
        return f"{self._credentials.base_url}/api/v1/agents/{target}/active-response"

    def _send(
        self,
        dispatch: ExecutionDispatch,
        *,
        command: str,
        endpoint: str | None = None,
    ) -> ExecutionOutcome:
        # The dispatch target IS the agent id (validated upstream:
        # Approval -> recommendation snapshot -> Service binding). The
        # adapter re-validates its shape because it rides the URL path —
        # a hostile target never reaches transport.
        target = dispatch.target or ""
        if not _SAFE_TARGET.fullmatch(target):
            raise ExecutorOutcomeViolation(
                "wazuh dispatch target is not a safe agent identifier "
                "(path-injection shape refused before outbound)"
            )
        # Outbound idempotency (frozen §5): the platform execution_id
        # rides the BODY (inside arguments) — never the URL.
        payload = {
            "command": command,
            "arguments": [str(dispatch.execution_id)],
        }
        request = urllib.request.Request(
            endpoint or self._active_response_endpoint(target),
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
            return self._failure("timeout", "wazuh active response timed out")
        except urllib.error.HTTPError as error:
            return self._on_http_error(error, dispatch)
        except (urllib.error.URLError, OSError):
            return self._failure(
                "adapter_unavailable", "wazuh is unreachable (connection failed)"
            )

        status = getattr(response, "status", None)
        if status == 202:
            # accepted != completed — NEVER succeeded, NEVER a waiting
            # state (3.1 froze: no asynchronous execution facts).
            return self._failure(
                "adapter_error",
                "wazuh accepted the command (202) without synchronous "
                "confirmation; fail-closed",
            )
        if status not in (200, 201):
            return self._failure(
                "adapter_error", f"wazuh active response returned HTTP {status}"
            )
        body = self._read_json_body(response)
        if not isinstance(body, dict):
            raise ExecutorOutcomeViolation(
                "Wazuh confirmation is not a JSON object — cannot "
                "confirm active response"
            )
        if body.get("accepted") is True and body.get("success") is not True:
            # Asynchronous acceptance is NOT completion (Shuffle parity).
            return self._failure(
                "adapter_error",
                "wazuh accepted the command asynchronously without "
                "synchronous confirmation; fail-closed",
            )
        if body.get("success") is not True:
            # Explicit confirmation is mandatory: 2xx without it (e.g.
            # {"status": "running"}) is a structure the platform cannot
            # trust — D9 adjudicates.
            raise ExecutorOutcomeViolation(
                "Wazuh returned 2xx without explicit confirmation "
                "('success' true missing)"
            )
        agent_status = body.get("agent_status")
        if agent_status is not None and (
            not isinstance(agent_status, str)
            or agent_status.lower() not in _CONFIRMED_AGENT_STATUSES
        ):
            # {"success": true, "agent_status": "unknown"} — the agent
            # outcome is ambiguous; the adapter never decides this.
            raise ExecutorOutcomeViolation(
                "Wazuh confirmation carries an ambiguous agent_status — "
                "cannot confirm active response"
            )
        detail: dict = {"provider": "wazuh", "command": command}
        command_id = body.get("command_id")
        if command_id:
            detail["command_id"] = command_id
        return ExecutionOutcome(
            status="succeeded", detail=detail, raw_response=body
        )

    # ------------------------------------------------------------------
    # Error translation (frozen mapping table)
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
        if status == 409:
            hit = self._conflict_outcome(lowered, body, dispatch)
            if hit is not None:
                return hit
        if any(marker in lowered for marker in _OFFLINE_MARKERS):
            # Agent offline / disconnected — the endpoint cannot act.
            return self._failure(
                "adapter_unavailable", "wazuh reports the agent is unreachable"
            )
        classification = (
            "adapter_unavailable" if status in (502, 503, 504) else "adapter_error"
        )
        reason = self._sanitize(f"wazuh active response rejected with HTTP {status}")
        return self._failure(classification, reason)

    def _conflict_outcome(
        self, lowered: str, body: str, dispatch: ExecutionDispatch
    ) -> ExecutionOutcome | None:
        """409 adjudication. Returns an outcome when the conflict is
        conclusive (idempotent hit OR hard refusal); None when the
        status-code table decides."""
        if any(marker in lowered for marker in _MISMATCH_MARKERS):
            # Same execution_id re-sent with a DIFFERENT command: an
            # overwrite attempt — hard failure, never an idempotent hit.
            return self._failure(
                "adapter_error",
                "wazuh reports this execution_id is already bound to a "
                "different command (overwrite refused)",
            )
        if not any(marker in lowered for marker in _DUPLICATE_MARKERS):
            return None
        try:
            conflict_body = json.loads(body)
        except ValueError:
            conflict_body = None
        if isinstance(conflict_body, dict):
            foreign_reference = any(
                conflict_body.get(key)
                and str(dispatch.execution_id) != str(conflict_body[key])
                for key in _EXECUTION_ID_KEYS
            )
            if foreign_reference:
                # The conflict belongs to ANOTHER execution — claiming
                # it would forge an idempotency hit. Fail closed.
                return self._failure(
                    "adapter_error",
                    "wazuh 409 references a foreign execution_id "
                    "(idempotency hit refused)",
                )
        # Duplicate signal for THIS execution_id -> idempotency HIT.
        return ExecutionOutcome(
            status="succeeded",
            detail={"provider": "wazuh", "idempotent_duplicate": True},
            raw_response=None,
        )

    def _read_json_body(self, response) -> dict:
        try:
            raw = response.read()
        except Exception as exc:  # noqa: BLE001
            raise ExecutorOutcomeViolation(
                f"Wazuh response body unreadable: {type(exc).__name__}"
            ) from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ExecutorOutcomeViolation(
                "Wazuh response is not valid JSON — cannot confirm "
                "active response"
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
