"""TheHive adapter — case creation provider (Phase 3.2.5, frozen spec §6).

TheHive is SentinelFlow's Case Management / Investigation system. It is
NOT a response engine: this adapter's single job is turning an approved
``escalate_to_incident`` decision into a TheHive case, after which human
investigators take over. Frozen control flow:

    SentinelFlow decision -> TheHive case creation -> human investigation

never ``SentinelFlow -> TheHive -> automatic investigation / automatic
closure``. This keeps the 3.1 platform chain untouched: the adapter only
translates an approved ExecutionDispatch into one outbound Case API call
and parses the answer into an ExecutionOutcome.

Frozen facts (distinct from 3.2.3/3.2.4 by design — not copied):

- Vocabulary: supports() answers True ONLY for escalate_to_incident.
  Endpoint response (isolate / disable / block), workflow triggering,
  risk-score modification, incident closure and monitor_only are all
  rejected — the guard remains the upstream gate.
- Compensation: supports_compensation() is False for EVERY action. Case
  lifecycle belongs to the investigation; SentinelFlow never auto-closes
  a case (no create_case -> close_case reversal exists).
- HTTP contract: POST {base_url}/api/case with a body carrying title,
  description, sentinelflow_execution_id, source, severity and
  approval_id. The execution id is the idempotency / audit / external
  tracking key.
- Result mapping: 200/201 + case_id -> succeeded
  (detail {"provider": "thehive", "case_id": ...}); 202 or a 2xx body
  without a case_id NEVER succeeds (case creation without a case id is
  a lie); 409 duplicate -> succeeded idempotent_duplicate; 409 with a
  foreign execution id or a different event -> failed fail-closed;
  401/403/404/500 -> adapter_error; 502/503/504 -> adapter_unavailable;
  timeout -> timeout; connection/OS errors -> adapter_unavailable.
- Ambiguous answers ({} / {"success": true} without case_id / non-dict
  bodies) raise ExecutorOutcomeViolation: the adapter never self-judges
  — platform parse produces protocol_violation (D9).
- Zero retry, zero polling, zero async callbacks (user directive): one
  request, one response, one decision, one execution_log row.

Secret boundary: credentials arrive ONLY via AdapterCredentials
(.env -> Settings -> AdapterCredentials) and ride ONLY in the
Authorization header. Every exception message is sanitized against
current_secret_values() — a secret must never surface in a detail, a
log line or a raised message.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable

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

#: The ONE action TheHive executes (3.2.5 E1 capability expansion):
#: escalating a SentinelFlow incident into a TheHive case.
THEHIVE_ACTIONS = frozenset({"escalate_to_incident"})

#: Marker words a TheHive 409 body uses for a genuine duplicate-case answer.
_DUPLICATE_MARKERS = ("already exists", "duplicate")

#: Marker words betraying a 409 that is NOT a same-action duplicate —
#: an attacker/collision attempting to bind THIS execution_id to a
#: DIFFERENT event/incident must fail closed, never masquerade as an
#: idempotent hit.
_MISMATCH_MARKERS = ("different incident", "different event", "different action")

#: Body keys that may expose an EXTERNAL execution id in a 409 body —
#: its presence means the case belongs to another SentinelFlow
#: execution (or an attacker guessing ids): refuse, never impersonate.
_EXECUTION_ID_KEYS = ("sentinelflow_execution_id", "execution_id")


class TheHiveExecutor(ResponseExecutor):
    """Case creation over the TheHive Case API (synchronous, no retry).

    Constructor arguments:
      credentials -- AdapterCredentials for THEHIVE_BASE_URL /
          THEHIVE_API_KEY (Bearer), already validated by the registry.
      timeout -- seconds for the single outbound call.
      transport -- the deployment seam for tests: a callable
          ``transport(request, timeout=...) -> response`` where response
          has ``status``/``read()`` — matching ``urllib.request.urlopen``
          shape. Production uses the default urllib opener; there is NO
          retry layer, NO polling and NO callback surface around it.
    """

    def __init__(
        self,
        credentials: AdapterCredentials,
        *,
        timeout: float = 30.0,
        transport: Callable | None = None,
    ):
        if credentials.adapter != "thehive":
            raise ExecutorConfigError(
                "thehive executor requires credentials for adapter "
                f"'thehive', got credentials for adapter "
                f"'{credentials.adapter}'"
            )
        # Defense-in-depth: re-validate the base URL at construction.
        validate_base_url("thehive", credentials.base_url)
        if timeout <= 0:
            raise ExecutorConfigError(
                "THEHIVE_TIMEOUT_SECONDS must be a positive number"
            )
        self._credentials = credentials
        self._timeout = float(timeout)
        self._transport = transport or urllib.request.urlopen

    # -- contract ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "thehive"

    def supports(self, action: str) -> bool:
        return action in THEHIVE_ACTIONS

    def supports_compensation(self, action: str) -> bool:
        # Frozen policy: TheHive never auto-closes cases — the case
        # lifecycle belongs to human investigation, so no action has a
        # machine reversal here.
        return False

    # -- execute -----------------------------------------------------------

    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Create a TheHive case for the approved escalation.

        Case mapping (frozen): execution target -> title, approval +
        provenance facts -> description, execution_id + approval_id ride
        in the body as the idempotency/audit keys, source is the fixed
        literal "sentinelflow", severity is the fixed escalation default
        "high" (the dispatch DTO carries no richer incident facts — the
        adapter never invents them).
        """
        if not self.supports(dispatch.action):
            raise ValueError(
                f"thehive adapter does not support action '{dispatch.action}'"
            )
        body = {
            "title": f"SentinelFlow escalation: {dispatch.target}",
            "description": (
                "Approved SentinelFlow escalation via the controlled "
                "response execution chain. Case creation is the complete "
                "machine scope; investigation stays human-led."
            ),
            "sentinelflow_execution_id": str(dispatch.execution_id),
            "source": "sentinelflow",
            "severity": "high",
            "approval_id": str(dispatch.approval_id),
        }
        url = f"{self._credentials.base_url}/api/case"
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                **self._credentials.auth_headers(),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            response = self._transport(request, timeout=self._timeout)
        except TimeoutError:
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "timeout",
                    "error": self._sanitize(
                        f"thehive case creation timed out after "
                        f"{self._timeout:g}s"
                    ),
                },
                raw_response=None,
            )
        except urllib.error.HTTPError as exc:
            return self._on_http_error(exc, dispatch)
        except (urllib.error.URLError, OSError) as exc:
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_unavailable",
                    "error": self._sanitize(f"thehive connection failed: {exc}"),
                },
                raw_response=None,
            )

        status = getattr(response, "status", None)
        payload_text = response.read().decode("utf-8", errors="replace")
        if status == 202:
            # "Accepted but not executed" is not a success in the frozen
            # 3.2 semantics — no waiting state exists in the outcome
            # vocabulary, so the answer is a failed adapter_error.
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_error",
                    "error": (
                        "thehive returned 202 accepted without creating "
                        "the case; no waiting state exists in the outcome "
                        "vocabulary"
                    ),
                },
                raw_response=None,
            )
        if status not in (200, 201):
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_error",
                    "error": f"thehive returned unexpected status {status}",
                },
                raw_response=None,
            )
        try:
            payload = json.loads(payload_text)
        except ValueError:
            raise ExecutorOutcomeViolation(
                "thehive case creation returned a non-JSON body on "
                f"status {status}"
            )
        if not isinstance(payload, dict):
            raise ExecutorOutcomeViolation(
                "thehive case creation returned a non-object body on "
                f"status {status}"
            )
        case_id = payload.get("case_id")
        if not case_id:
            # A case creation without a case id is a protocol lie — the
            # adapter never self-completes it; the platform parser owns
            # the protocol_violation verdict (D9).
            raise ExecutorOutcomeViolation(
                "thehive case creation succeeded without a case_id "
                "(ambiguous case response)"
            )
        return ExecutionOutcome(
            status="succeeded",
            detail={"provider": "thehive", "case_id": str(case_id)},
            raw_response=payload,
        )

    # -- compensate --------------------------------------------------------

    def compensate(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        if not self.supports_compensation(dispatch.action):
            raise ValueError(
                "thehive adapter provides no compensation — the case "
                "lifecycle belongs to human investigation and cases are "
                "never auto-closed"
            )
        raise ValueError(
            "thehive adapter has no compensable actions"
        )  # unreachable: capability guard refuses upstream

    # -- internals ----------------------------------------------------------

    def _on_http_error(
        self, exc: urllib.error.HTTPError, dispatch: ExecutionDispatch
    ) -> ExecutionOutcome:
        """Map HTTP errors. Only the 409 body is parsed (idempotency);
        every other body is NEVER carried into the detail."""
        status = exc.code
        if status == 409:
            return self._conflict_outcome(exc, dispatch)
        if status in (502, 503, 504):
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_unavailable",
                    "error": f"thehive upstream unavailable (HTTP {status})",
                },
                raw_response=None,
            )
        return ExecutionOutcome(
            status="failed",
            detail={
                "classification": "adapter_error",
                "error": f"thehive returned HTTP {status}",
            },
            raw_response=None,
        )

    def _conflict_outcome(
        self, exc: urllib.error.HTTPError, dispatch: ExecutionDispatch
    ) -> ExecutionOutcome:
        """409 handling: same-action duplicate -> succeeded
        idempotent_duplicate; everything else (foreign execution id,
        different event, unparseable body) -> failed adapter_error."""
        body_text = exc.read().decode("utf-8", errors="replace")
        lowered = body_text.lower()
        if any(marker in lowered for marker in _MISMATCH_MARKERS):
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_error",
                    "error": (
                        "thehive 409 conflict: this execution_id is bound "
                        "to a different event; one execution_id must never "
                        "create more than one case"
                    ),
                },
                raw_response=None,
            )
        if any(marker in lowered for marker in _DUPLICATE_MARKERS):
            try:
                payload = json.loads(body_text)
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                for key in _EXECUTION_ID_KEYS:
                    external_id = payload.get(key)
                    if external_id and str(external_id) != str(
                        dispatch.execution_id
                    ):
                        return ExecutionOutcome(
                            status="failed",
                            detail={
                                "classification": "adapter_error",
                                "error": (
                                    "thehive 409 conflict references a "
                                    "different execution_id; refusing to "
                                    "claim another execution's case"
                                ),
                            },
                            raw_response=None,
                        )
            return ExecutionOutcome(
                status="succeeded",
                detail={"provider": "thehive", "idempotent_duplicate": True},
                raw_response=payload if isinstance(payload, dict) else None,
            )
        return ExecutionOutcome(
            status="failed",
            detail={
                "classification": "adapter_error",
                "error": "thehive returned HTTP 409 without an idempotency "
                "marker",
            },
            raw_response=None,
        )

    def _sanitize(self, text: str) -> str:
        """Strip any secret value from a message before it can surface in
        a detail or a raised exception (3.2.2 boundary)."""
        return redact_text(text, current_secret_values())
