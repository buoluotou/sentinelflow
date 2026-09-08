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
- HTTP contract: POST {base_url}/api/case with a body carrying ONLY
  fields the v0 InputCase DTO declares (dto/v0/Case.scala:8): title,
  description, severity (Int — 3 == High on the certified 1-4 scale) and
  tags. SentinelFlow's execution / approval correlation + provenance ride
  in ``tags`` (a declared Set[String], persisted by CaseSrv.create and
  echoed back in OutputCase.tags), NOT as undeclared top-level keys —
  FieldsParser silently drops undeclared fields, so the M1 body's
  ``sentinelflow_execution_id`` / ``source`` / ``approval_id`` never
  reached the case (M2 §4 fix). The execution tag is the correlation +
  independent read-back verification handle (G5), never an idempotency key
  (409 has no certified duplicate contract).
- Result mapping (TheHive 4.1.24-1 v0 certified contract — G3/G5 doc
  §3/§4): 201 + OutputCase{_id, id, caseId, ...} -> succeeded. ``_id`` ==
  ``id`` == EntityId.toString is the STRING resource reference (the handle
  GET /api/case/{id} re-fetches); ``caseId`` == number is the Int human
  case number, kept for audit ONLY and NEVER used as the reference. The
  response has NO ``case_id`` key: detail carries SentinelFlow's frozen
  reconcile key ``case_id`` = the ``_id`` string (+ ``case_number`` audit).
  202 or a 2xx body without a valid string _id/id NEVER succeeds (a case
  creation without a resource reference is a lie); 409 -> failed
  fail-closed (case creation has NO certified idempotency/duplicate
  contract — CaseSrv.create auto-assigns the next number); 401/403/404/
  500 -> adapter_error; 502/503/504 -> adapter_unavailable; timeout ->
  timeout; connection/OS errors -> adapter_unavailable.
- Ambiguous answers ({} / {"success": true} / only a numeric caseId / an
  empty or non-string _id/id / non-dict bodies) raise
  ExecutorOutcomeViolation: the adapter never self-judges — platform parse
  produces protocol_violation (D9).
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

#: TheHive 4.1.24-1 v0 case creation has NO certified idempotency /
#: duplicate-recovery contract (CaseSrv.create auto-assigns the next case
#: number and never detects duplicates — G3/G5 doc §5), so a 409 carries no
#: authoritative re-fetchable case reference and is NEVER auto-success:
#: every 409 fails closed (M1 §4). No marker vocabulary is consulted.

#: TheHive v0 case severity is an Int on the certified 1-4 scale
#: (frontend Constants.js Severity.keys: Low=1, Medium=2, High=3,
#: Critical=4; CaseUpdateCtrl default = 2/Medium). The frozen escalation
#: intent is "high" -> 3. InputCase.severity is Option[Int]
#: (v0/Case.scala:11), so a STRING "high" is a 400 AttributeCheckingError
#: (M2 §4 fix).
THEHIVE_SEVERITY_HIGH = 3

#: Provenance + correlation tag vocabulary for SentinelFlow-created cases.
#: These ride in InputCase.tags (a DECLARED Set[String], v0/Case.scala:14,
#: persisted by CaseSrv.create:99 and echoed back in OutputCase.tags), NOT
#: as undeclared top-level body keys that FieldsParser silently drops. The
#: write adapter owns this contract; the G5 read adapter imports the SAME
#: helpers so the correlation written at create time is the exact string
#: re-verified at read time (single source of truth, never drifted).
SENTINELFLOW_TAG = "sentinelflow"
SENTINELFLOW_EXECUTION_TAG_PREFIX = "sentinelflow:execution:"
SENTINELFLOW_APPROVAL_TAG_PREFIX = "sentinelflow:approval:"


def sentinelflow_execution_tag(execution_id: object) -> str:
    """Canonical correlation tag binding a created TheHive case to the
    SentinelFlow execution that created it. Single source of truth shared
    by the write (execute) and read (G5 reconcile) sides."""
    return f"{SENTINELFLOW_EXECUTION_TAG_PREFIX}{execution_id}"


def sentinelflow_approval_tag(approval_id: object) -> str:
    """Canonical correlation tag binding a created case to its approval."""
    return f"{SENTINELFLOW_APPROVAL_TAG_PREFIX}{approval_id}"


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

        Case mapping (frozen): execution target -> title; a fixed
        provenance description; severity -> the Int 3 (High) escalation
        default (InputCase.severity is Option[Int]); execution_id +
        approval_id + the "sentinelflow" provenance marker -> tags (the
        ONLY authenticated, persisted, read-back channel — the dispatch
        DTO carries no richer incident facts, so the adapter never
        invents them). The execution tag is the G5 correlation /
        independent verification handle, never an idempotency key.
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
            # v0 InputCase.severity is Option[Int] (3 == High); a string
            # "high" is a 400. Correlation rides in tags (declared,
            # persisted, echoed) — never as undeclared top-level keys.
            "severity": THEHIVE_SEVERITY_HIGH,
            "tags": [
                SENTINELFLOW_TAG,
                sentinelflow_execution_tag(dispatch.execution_id),
                sentinelflow_approval_tag(dispatch.approval_id),
            ],
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
            return self._on_http_error(exc)
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
        # TheHive 4.1.24-1 v0 emits an OutputCase (dto/v0/Case.scala):
        # "_id" and "id" are BOTH the string EntityId (Conversion.scala
        # caseOutput: id = _id.toString, _id = _id.toString) and the
        # reconcilable resource reference — the handle GET /api/case/{id}
        # re-fetches (CaseCtrlTest: EntityIdOrName(outputCase._id)). The
        # response NEVER carries "case_id". "caseId" is the Int human case
        # NUMBER, a distinct semantic that is NEVER the string resource id
        # (M1 §4).
        resource_id = payload.get("_id")
        if not isinstance(resource_id, str) or not resource_id:
            # The renderer guarantees _id == id, so fall back to "id" only
            # as a defensive read of the SAME string resource reference.
            resource_id = payload.get("id")
        if not isinstance(resource_id, str) or not resource_id:
            # A case creation without a string resource reference is a
            # protocol lie — a lone numeric caseId is NOT a substitute. The
            # adapter never self-completes it; the platform parser owns the
            # protocol_violation verdict (D9).
            raise ExecutorOutcomeViolation(
                "thehive case creation succeeded without a string resource "
                "reference (_id/id absent, empty or non-string; the numeric "
                "caseId is never a substitute)"
            )
        # SentinelFlow's frozen reconcile key (_EXTERNAL_REFERENCE_KEYS
        # ["thehive"]) carries the STRING resource reference so the Manual
        # Reconcile read path re-fetches the exact case; caseId (number)
        # rides along for human audit ONLY, and only when TheHive supplied a
        # genuine int (never a bool, never invented).
        detail: dict[str, object] = {
            "provider": "thehive",
            "case_id": resource_id,
        }
        case_number = payload.get("caseId")
        if isinstance(case_number, int) and not isinstance(case_number, bool):
            detail["case_number"] = case_number
        return ExecutionOutcome(
            status="succeeded",
            detail=detail,
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

    def _on_http_error(self, exc: urllib.error.HTTPError) -> ExecutionOutcome:
        """Map HTTP errors. NO error body is parsed or carried into the
        detail — the 409 body is no longer inspected because every 409
        fails closed (see below)."""
        status = exc.code
        if status == 409:
            # TheHive 4.1.24-1 v0 case creation has NO certified idempotency
            # / duplicate-recovery contract (CaseSrv.create auto-assigns the
            # next case number, never detects duplicates — G3/G5 doc §5), so
            # a 409 carries no authoritative re-fetchable case reference.
            # Per M1 §4 a 409 is NEVER auto-success: without a certified way
            # to recover, correlate and verify an EXISTING case reference it
            # fails closed. The body is NOT parsed (no marker vocabulary) and
            # is NEVER carried into the detail.
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_error",
                    "error": (
                        "thehive returned HTTP 409 conflict; case creation "
                        "has no certified idempotent-recovery contract, so a "
                        "conflict is never claimed as success (fail-closed)"
                    ),
                },
                raw_response=None,
            )
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

    def _sanitize(self, text: str) -> str:
        """Strip any secret value from a message before it can surface in
        a detail or a raised exception (3.2.2 boundary)."""
        return redact_text(text, current_secret_values())
