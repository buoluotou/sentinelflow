"""TheHive adapter — case creation provider.

TheHive is SentinelFlow's Case Management / Investigation system. It is
not a response engine: this adapter's single job is turning an approved
``escalate_to_incident`` decision into a TheHive case, after which human
investigators take over. Control flow is strictly:

SentinelFlow decision -> TheHive case creation -> human investigation

never ``SentinelFlow -> TheHive -> automatic investigation / automatic
closure``. The adapter only translates an approved ExecutionDispatch into
one outbound Case API call and parses the answer into an
ExecutionOutcome.

Contract facts:

- Vocabulary: supports() answers True only for escalate_to_incident.
Endpoint response (isolate / disable / block), workflow triggering,
risk-score modification, incident closure and monitor_only are all
rejected — the capability guard is the upstream gate.
- Compensation: supports_compensation() is False for every action. Case
lifecycle belongs to the investigation; SentinelFlow never auto-closes
a case (no create_case -> close_case reversal exists).
- HTTP contract: POST {base_url}/api/case with a body carrying only
fields the v0 InputCase DTO declares (dto/v0/Case.scala:8): title,
description, severity (Int — 3 == High on the 1-4 scale) and tags.
SentinelFlow's execution / approval correlation + provenance ride in
``tags`` (a declared Set[String], persisted by CaseSrv.create and
echoed back in OutputCase.tags), not as undeclared top-level keys —
FieldsParser silently drops undeclared fields, so a body carrying
``sentinelflow_execution_id`` / ``source`` / ``approval_id`` at the top
level never reaches the case. The execution tag is the correlation +
independent read-back verification handle, never an idempotency key
(409 has no certified duplicate contract).
- Result mapping (TheHive 4.1.24-1 v0 contract): 201 + OutputCase{_id,
id, caseId, ...} -> succeeded. ``_id`` == ``id`` == EntityId.toString is
the string resource reference (the handle GET /api/case/{id}
re-fetches); ``caseId`` == number is the Int human case number, kept for
audit only and never used as the reference. The response has no
``case_id`` key: detail carries SentinelFlow's reconcile key
``case_id`` = the ``_id`` string (+ ``case_number`` audit). 202 or a 2xx
body without a valid string _id/id never succeeds: without a resource
reference there is nothing to reconcile against. 409 -> failed
fail-closed (case creation has no certified idempotency/duplicate
contract — CaseSrv.create auto-assigns the next number); 401/403/404/
500 -> adapter_error; 502/503/504 -> adapter_unavailable; timeout ->
timeout; connection/OS errors -> adapter_unavailable.
- Ambiguous answers ({} / {"success": true} / only a numeric caseId / an
empty or non-string _id/id / non-dict bodies) raise
ExecutorOutcomeViolation: the adapter never self-judges — platform parse
produces protocol_violation.
- No retry, no polling, no async callbacks: one request, one response,
one decision, one execution_log row.

Secret boundary: credentials arrive only via AdapterCredentials
(.env -> Settings -> AdapterCredentials) and ride only in the
Authorization header. Every exception message is sanitized against
current_secret_values() — a secret must never surface in a detail, a
log line or a raised message.
"""
from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from typing import Callable

from app.core.config import settings
from app.services.executions.base import ResponseExecutor
from app.services.executions.binding import VERSION_ASSERTION_CONFIG
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

# The only action TheHive executes: escalating a SentinelFlow incident
# into a TheHive case.
THEHIVE_ACTIONS = frozenset({"escalate_to_incident"})

# TheHive 4.1.24-1 v0 case creation has no idempotency / duplicate-recovery
# contract (CaseSrv.create auto-assigns the next case number and never
# detects duplicates), so a 409 carries no authoritative re-fetchable case
# reference and is never auto-success: every 409 fails closed. No marker
# vocabulary is consulted.

# TheHive v0 case severity is an Int on the 1-4 scale
# (frontend Constants.js Severity.keys: Low=1, Medium=2, High=3,
# Critical=4; CaseUpdateCtrl default = 2/Medium). The escalation intent
# "high" maps to 3. InputCase.severity is Option[Int] (v0/Case.scala:11),
# so sending the string "high" is a 400 AttributeCheckingError.
THEHIVE_SEVERITY_HIGH = 3

# Provenance + correlation tag vocabulary for SentinelFlow-created cases.
# These ride in InputCase.tags (a declared Set[String], v0/Case.scala:14,
# persisted by CaseSrv.create:99 and echoed back in OutputCase.tags), not
# as undeclared top-level body keys that FieldsParser silently drops. The
# write adapter owns this contract; the reconcile read adapter imports the
# same helpers so the correlation written at create time is the exact
# string re-verified at read time (single source of truth, never drifted).
SENTINELFLOW_TAG = "sentinelflow"
SENTINELFLOW_EXECUTION_TAG_PREFIX = "sentinelflow:execution:"
SENTINELFLOW_APPROVAL_TAG_PREFIX = "sentinelflow:approval:"


def sentinelflow_execution_tag(execution_id: object) -> str:
    """Canonical correlation tag binding a created TheHive case to the
SentinelFlow execution that created it. Single source of truth shared
by the write (execute) and read (reconcile) sides."""
    return f"{SENTINELFLOW_EXECUTION_TAG_PREFIX}{execution_id}"


def sentinelflow_approval_tag(approval_id: object) -> str:
    """Canonical correlation tag binding a created case to its approval."""
    return f"{SENTINELFLOW_APPROVAL_TAG_PREFIX}{approval_id}"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any HTTP redirect on the case-creation POST, so the
write side matches the read side.

``urllib.request.urlopen`` follows 3xx automatically and forwards the
``Authorization`` header to the redirect target, including a cross-host
one. For a credential-bearing ``POST /api/case`` that is both a leak
(CWE-522: a compromised or misconfigured proxy could 302 the write to an
attacker host and harvest the Bearer key) and a target-binding violation:
the durable pre-dispatch binding records ``{base_url}/api/case`` as the
endpoint, so silently following a 3xx would make the real target diverge
from the bound one. A case creation must resolve directly on the declared
endpoint, so any redirect is treated as a transport anomaly: returning
``None`` makes urllib raise ``HTTPError`` for the 3xx, which ``execute()``
maps to a fail-closed ``adapter_error`` — not a cross-host credential
leak, not a write to an unbound target, not a fabricated success.

This only declines redirects. TLS certificate verification and base-URL
validation are unchanged (connectivity is never restored by disabling TLS
or relaxing URL checks); ``build_opener`` still installs the default
verifying ``HTTPSHandler``.
"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    """The production write opener: default handlers (verifying TLS) with the
redirect handler replaced by ``_NoRedirectHandler``. ``.open(request,
timeout=...)`` matches the ``urlopen`` call shape ``execute()`` uses."""
    return urllib.request.build_opener(_NoRedirectHandler)


class TheHiveExecutor(ResponseExecutor):
    """Case creation over the TheHive Case API (synchronous, no retry).

Constructor arguments:
credentials -- AdapterCredentials for THEHIVE_BASE_URL /
THEHIVE_API_KEY (Bearer), already validated by the registry.
timeout -- seconds for the single outbound call.
transport -- the deployment seam for tests: a callable
``transport(request, timeout=...) -> response`` where response
has ``status``/``read()`` — matching ``urllib.request.urlopen``
shape. Production uses a no-redirect urllib opener: a 3xx is
refused, so the ``Authorization`` header is never forwarded to a
cross-host redirect target and the real request target stays the
bound endpoint. There is no retry layer, no polling and no callback
surface around it.
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
        # The production default is a no-redirect opener, never bare
        # ``urlopen``: a case-creation POST must resolve directly on the bound
        # endpoint, and a 3xx must not carry the Bearer key to another host nor
        # silently divert the write from the recorded target binding.
        self._transport = transport or _build_opener().open

    # contract ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "thehive"

    def supports(self, action: str) -> bool:
        return action in THEHIVE_ACTIONS

    def supports_compensation(self, action: str) -> bool:
        # TheHive never auto-closes cases: the case lifecycle belongs to human
        # investigation, so no action has a machine reversal here.
        return False

    # forward dispatch binding contributor ------------------------------

    def dispatch_binding_facts(self, dispatch: ExecutionDispatch) -> dict:
        """Contribute the adapter-specific target identity to the pre-dispatch
binding as a declaration rather than a verified identity:

endpoint -- the validated, secret-free base URL the ``POST /api/case``
targets: a config declaration of where the request was sent, not a
certified instance identity (a base URL is never passed off as one).
version_evidence_ref / version_assertion_kind -- the operator's configured
``THEHIVE_EXPECTED_VERSION`` marked ``config-declaration``: a version
config is not a liveness proof, so nothing here claims the remote
server actually runs it.
target_instance / target_tenant -- ``None`` (unknown). TheHive 4.1.24-1 has
no authoritative dispatch-time instance / tenant source (the write
config carries a base URL, not a certified instance identity, and the
``OutputCase`` has no organisation), so these stay ``None`` and the
binding check still fails closed: the binding stays forward-ready
rather than manufacturing an identity that does not exist.

No secret: the base URL is validated secret-free (``validate_base_url``) and
every field still passes the ``redact_detail`` gate at the single ``_append``
write point. ``dispatch`` is accepted for protocol generality (a multi-action
adapter's endpoint may depend on it); TheHive's single ``escalate_to_incident``
action always targets ``{base_url}/api/case``, so the endpoint is the base URL.
"""
        expected_version = str(
            getattr(settings, "THEHIVE_EXPECTED_VERSION", "") or ""
        ).strip()
        return {
            "endpoint": self._credentials.base_url,
            "version_evidence_ref": expected_version or None,
            "version_assertion_kind": VERSION_ASSERTION_CONFIG,
            "target_instance": None,
            "target_tenant": None,
        }

    # execute -----------------------------------------------------------

    def execute(self, dispatch: ExecutionDispatch) -> ExecutionOutcome:
        """Create a TheHive case for the approved escalation.

Case mapping: execution target -> title; a fixed provenance
description; severity -> the Int 3 (High) escalation default
(InputCase.severity is Option[Int]); execution_id + approval_id +
the "sentinelflow" provenance marker -> tags (the only
authenticated, persisted, read-back channel — the dispatch DTO
carries no richer incident facts, so the adapter never invents
them). The execution tag is the correlation / independent
verification handle, never an idempotency key.
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
        try:
            payload_bytes = response.read()
        except TimeoutError:
            # A timeout during the body read is the same uncertainty as a connect
            # timeout: the request was sent, the case may exist, the answer is
            # lost. Fail closed as timeout, never a success, no retry.
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "timeout",
                    "error": self._sanitize(
                        f"thehive case creation timed out reading the "
                        f"response after {self._timeout:g}s"
                    ),
                },
                raw_response=None,
            )
        except (OSError, http.client.HTTPException) as exc:
            # The request was sent (the case may exist) but the response body was
            # interrupted mid-stream (IncompleteRead / ConnectionReset / OS
            # error): the outcome is unknown, so this is never a success and never
            # a claim the effect failed. Fail closed as adapter_unavailable; the
            # committed pre-dispatch attempt survives for manual reconciliation,
            # with no auto-retry. The error text is sanitized against live secrets.
            return ExecutionOutcome(
                status="failed",
                detail={
                    "classification": "adapter_unavailable",
                    "error": self._sanitize(
                        f"thehive response read interrupted: {exc}"
                    ),
                },
                raw_response=None,
            )
        payload_text = payload_bytes.decode("utf-8", errors="replace")
        if status == 202:
            # "Accepted but not executed" is not a success: no waiting state
            # exists in the outcome vocabulary, so the answer is a failed
            # adapter_error.
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
        # "_id" and "id" are both the string EntityId (Conversion.scala
        # caseOutput: id = _id.toString, _id = _id.toString) and the
        # reconcilable resource reference — the handle GET /api/case/{id}
        # re-fetches (CaseCtrlTest: EntityIdOrName(outputCase._id)). The
        # response never carries "case_id". "caseId" is the Int human case
        # number, a distinct semantic that is never the string resource id.
        resource_id = payload.get("_id")
        if not isinstance(resource_id, str) or not resource_id:
            # The renderer guarantees _id == id, so fall back to "id" only
            # as a defensive read of the same string resource reference.
            resource_id = payload.get("id")
        if not isinstance(resource_id, str) or not resource_id:
            # A case creation without a string resource reference gives
            # nothing to reconcile — a lone numeric caseId is not a
            # substitute. The adapter never self-completes it; the platform
            # parser owns the protocol_violation verdict.
            raise ExecutorOutcomeViolation(
                "thehive case creation succeeded without a string resource "
                "reference (_id/id absent, empty or non-string; the numeric "
                "caseId is never a substitute)"
            )
        # SentinelFlow's reconcile key (_EXTERNAL_REFERENCE_KEYS["thehive"])
        # carries the string resource reference so the manual reconcile read
        # path re-fetches the exact case; caseId (number) rides along for human
        # audit only, and only when TheHive supplied a real int (never a bool,
        # never invented).
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

    # compensate --------------------------------------------------------

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

    # internals ----------------------------------------------------------

    def _on_http_error(self, exc: urllib.error.HTTPError) -> ExecutionOutcome:
        """Map HTTP errors. No error body is parsed or carried into the
detail — the 409 body is not inspected because every 409 fails
closed (see below)."""
        status = exc.code
        if status == 409:
            # TheHive 4.1.24-1 v0 case creation has no idempotency /
            # duplicate-recovery contract (CaseSrv.create auto-assigns the
            # next case number, never detects duplicates), so a 409 carries no
            # authoritative re-fetchable case reference. A 409 is never
            # auto-success: without a contract to recover, correlate and verify
            # an existing case reference it fails closed. The body is not
            # parsed (no marker vocabulary) and is never carried into the
            # detail.
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
a detail or a raised exception."""
        return redact_text(text, current_secret_values())
