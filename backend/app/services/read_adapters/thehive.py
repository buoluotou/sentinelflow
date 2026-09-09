"""TheHive READ adapter (Phase 3.4.5-M2 §5) — the case-CREATION effect verifier.

The READ-side counterpart of ``app.services.executions.thehive.TheHiveExecutor``
(the WRITE side that creates the case). Where the executor turns an approved
``escalate_to_incident`` decision into ONE ``POST /api/case``, this adapter
answers exactly one question for the Manual Reconcile pipeline::

    "Does the case this execution created STILL exist, is it provably THE case
     THIS execution created, and when was it created?"

It is a ``ReadAdapter`` (3.4.5-A1 contract): ``read`` is the SOLE verb. It
structurally CANNOT execute / compensate / dispatch / create_case / close_case —
those verbs do not exist on this contract. It performs a single ``GET`` and NEVER
mutates the external world (read / query ONLY), NEVER retries, NEVER polls.

WHERE THIS LIVES — AND WHY (evidence-driven placement). The 3.4.5-A1 read
CONTRACT (``app/services/manual_reconcile/read/``) is a SEALED PURE package:
``test_adapter_read_contract.py`` AST-audits its ENTIRE import surface
(``_READ_PKG.rglob("*.py")``) and forbids HTTP / DB / ``app.services.executions``
/ ``app.services.outcomes`` / fastapi / pydantic, plus a runtime subprocess
import check. A concrete reader that issues a real ``GET`` CANNOT live inside
that package without breaking the sealed purity tests. So this adapter lives in a
SEPARATE ``app/services/read_adapters/`` package — physically isolated from BOTH
the sealed read-contract package AND the write-adapters package
(``app/services/executions/``), exactly as design §21 requires Read and Write to
stay separated. It IMPORTS the A1 contract shapes (``ReadAdapter`` /
``AdapterReadRequest`` / ``AdapterReadResult``) and the read-side exception family
(``ReadTransportError``) — the dependency direction is one-way (concrete reader ->
pure contract), never the reverse.

THE CERTIFIED READ CONTRACT (TheHive 4.1.24-1 = git ``b6649bb``, ScalliGraph
``2c2a7a4``; M2 §2 source forensics — SOURCE-certified, real-Lab runtime evidence
GAPPED / LAB BLOCKED):

  - ``GET /api/case/{id}`` resolves ``id`` through ``EntityIdOrName``: a ``~``
    prefix means "by EntityId". SentinelFlow persists the OutputCase ``_id``
    (== ``id`` == ``EntityId.toString``) as the STRING resource reference
    (``_EXTERNAL_REFERENCE_KEYS["thehive"] = "case_id"``), so the read re-fetches
    the exact vertex the write created — NEVER the numeric ``caseId`` (the human
    case number, audit-only).
  - ``OutputCase._id`` / ``id`` are Strings; ``createdAt`` is a ``Date``
    serialized as epoch MILLISECONDS (ScalliGraph ``Mapping.scala``:
    ``case d: Date => JsNumber(d.getTime)``); ``tags`` is the ``Set[String]``
    echoed back from ``CaseSrv.create`` (which persists ``InputCase.tags``).
  - error -> HTTP: 401 ``AuthenticationError``, 403 ``AuthorizationError``, 404
    ``NotFoundError`` — and ``NotFoundError`` covers BOTH a genuinely absent case
    AND a tenant-invisible one (``visible`` -> 404), so a 404 is deliberately
    AMBIGUOUS between "deleted" and "cross-tenant invisible".

THE VERIFICATION CONJUNCTION (M2 §5 — the crux; a bare HTTP 200 / resource
existence NEVER maps to ``confirmed_success``). ``read`` returns the synthesized
creation-effect word ``case_created`` ONLY when ALL THREE hold at once:

  1. IDENTITY — the fetched resource's string ``_id`` (fallback ``id``) EQUALS
     ``request.external_reference``. A different case, a numeric-only ``caseId``,
     or an absent/empty/non-string id is NEVER this execution's effect.
  2. CORRELATION — the resource's ``tags`` carry THIS execution's correlation tag
     ``sentinelflow:execution:{execution_id}`` (the EXACT string the write side
     persisted, imported from ``executions.thehive`` so the two sides can never
     drift). Without it the case is not provably THIS execution's creation — it
     could be a same-id case from another tenant / history, or a case whose tag
     was stripped after create.
  3. CREATION EFFECT (design §5.2 gate 3 — MANDATORY; M2-R §3 unifies the code to
     the frozen design, which already listed a missing ``createdAt`` as
     ``case_unverified``) — ``createdAt`` supplies the authoritative creation
     timestamp (-> ``observed_at``, the EXTERNAL creation time, never a server
     observation time). An absent / invalid / absurd ``createdAt`` now FAILS the
     gate -> ``case_unverified`` (reason ``missing_created_at``): without an
     authenticated creation time the read cannot independently prove THIS execution
     created THIS case (identity + a re-attachable tag are not enough — a historical
     or cross-instance same-id case must not verify).

Any 200 that FAILS the conjunction yields ``case_unverified`` — a word that is
NOT in the 3.4.3-B thehive vocabulary, so the mapping REFUSES it
(``UnrecognizedExternalState`` -> the router's 422, ZERO Outcome Facts). The
adapter NEVER guesses, NEVER downgrades an unverified read to ``unknown``, and
NEVER fabricates a correlation.

ERROR DISCRIMINATION (M2 §5 — 401 / 403 / 404 / timeout / deleted / tenant-
invisible are READ FAILURES, never effect verdicts). A transport-level failure
raises ``ReadTransportError`` with a SAFE STATIC ``category``; the A2-D pipeline
converts it to ``reconciliation_failed`` (ONE fact) — NEVER ``confirmed_failure``
(the case may have been created then deleted, or be cross-tenant invisible; a
failed READ cannot prove the CREATION failed):

  - 401 -> ``authentication_failure``;  403 -> ``authorization_failure``;
  - 404 -> ``not_found`` (absent OR tenant-invisible — deliberately merged, the
    TheHive security design does not distinguish them, and NEITHER is proof the
    creation failed);
  - 502/503/504 -> ``adapter_unavailable``;  other 5xx -> ``transport_error``;
  - ``TimeoutError`` -> ``timeout``;  ``URLError`` / ``OSError`` ->
    ``connection_failure``.

``case Resolved`` / task ``Completed`` / a Cortex job finishing / a human
investigation conclusion are NEVER read as this action's effect: the ONLY word
this adapter can emit for a verified effect is ``case_created`` (the creation),
and it maps NO native TheHive lifecycle state ("case created != case resolved",
design §8).

SECRET HYGIENE (3.2.2 boundary, mirrors the write adapter): credentials arrive
ONLY via ``AdapterCredentials`` and ride ONLY in the ``Authorization`` header;
every raised message is sanitized against ``current_secret_values()``; NO error
body is parsed or carried; ``raw_evidence`` holds ONLY non-secret diagnostic
fields (resource id, case number, correlation flag) and is itself NEVER persisted
(``manual_persist`` drops it). The reference is URL-encoded (``quote(...,
safe="")``) so a hostile reference cannot traverse the path — ``~`` is in
urllib's always-safe set, so the EntityId prefix survives unencoded.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Callable

from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.secrets import (
    AdapterCredentials,
    current_secret_values,
    redact_text,
    validate_base_url,
)
from app.services.executions.thehive import sentinelflow_execution_tag
from app.services.manual_reconcile.exceptions import ReadTransportError
from app.services.manual_reconcile.read.base import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
)

#: The synthesized case-CREATION effect word — the ONLY external_state this
#: adapter emits for a VERIFIED creation, produced ONLY on the full identity +
#: correlation + creation conjunction (never on a bare 200). It is a
#: SentinelFlow-synthesized creation-effect signal, NOT a native TheHive lifecycle
#: state. M2 §5 added it to the 3.4.3-B thehive vocabulary; M2-R §2 REMOVED it
#: again (fail-closed) because that vocabulary is PATH-AGNOSTIC and the frozen
#: 2-param mapping contract cannot express source isolation — so the word is now
#: REFUSED at the mapping layer on EVERY path (zero fact), including this trusted
#: reader's, until a source-isolation channel is approved (see the M2-R Amendment).
#: The reader still EMITS it (isolation-tested); the mapping just does not yet
#: ACCEPT it from any source.
CASE_CREATED = "case_created"

#: Emitted when a read SUCCEEDS at transport level (HTTP 200) but the identity /
#: correlation conjunction is NOT established (a different case, a missing or
#: mismatched ``_id``, no execution correlation tag, a malformed body). This word
#: is DELIBERATELY ABSENT from the thehive vocabulary, so the mapping REFUSES it
#: (``UnrecognizedExternalState`` -> 422, ZERO facts) — an unverified read is
#: NEVER laundered into ``confirmed_success`` and NEVER guessed to ``unknown``.
CASE_UNVERIFIED = "case_unverified"

#: The EXACT TheHive version this reader's read semantics are SOURCE-certified
#: against (TheHive 4.1.24-1 = git ``b6649bb`` / ScalliGraph ``2c2a7a4``). M2-R §4:
#: the factory authorizes a reader ONLY when ``THEHIVE_EXPECTED_VERSION`` equals
#: this string — an unset or mismatched expectation fails CLOSED, so 4.1.24-1
#: read semantics (``GET /api/case/{id}``, ``EntityIdOrName``, epoch-millis
#: ``createdAt``, ``OutputCase._id``) can never be silently applied to a different
#: server version by a one-line wiring. This is a CONFIGURATION assertion gate, not
#: a live probe: the factory issues NO HTTP at build time (a pinned invariant), so
#: the operator binds the certified version explicitly and a real Lab re-certifies
#: it against the running server before the router is ever wired.
CERTIFIED_THEHIVE_VERSION = "4.1.24-1"


def _tags_carry_execution(tags: object, execution_id: object) -> bool:
    """Whether the case's ``tags`` carry THIS execution's correlation tag.

    ``OutputCase.tags`` is a ``Set[String]`` rendered as a JSON array, so the
    normal shape is a list of strings; a bare string and other iterables are
    accepted defensively. The comparison is EXACT (== the canonical
    ``sentinelflow_execution_tag(execution_id)``) — never a prefix / substring /
    case-folded match, so a sibling execution's tag can never be mistaken for
    this one.
    """
    expected = sentinelflow_execution_tag(execution_id)
    if isinstance(tags, str):
        return tags == expected
    if isinstance(tags, Iterable):
        return any(isinstance(tag, str) and tag == expected for tag in tags)
    return False


def _created_at_to_datetime(value: object) -> datetime | None:
    """Convert an ``OutputCase.createdAt`` (epoch MILLISECONDS) to an aware UTC
    datetime, or ``None`` when it is absent / malformed / absurd.

    ScalliGraph serializes a ``Date`` as ``JsNumber(d.getTime)`` (milliseconds).
    A ``bool`` is NOT a timestamp (``isinstance(True, int)`` is True in Python, so
    it is excluded explicitly). ``datetime.fromtimestamp`` can raise on an
    out-of-range value; any failure yields ``None`` so the platform supplies a
    SERVER-OBSERVATION time and ``validate_observation`` stays the final gate
    (this adapter never enforces the future-skew bound itself).
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _unverified(reason: str, status: object = None) -> AdapterReadResult:
    """A REFUSED-shaped success read: ``case_unverified`` (absent from the
    vocabulary -> 422 / zero fact), ``observed_at=None``, and a NON-SECRET
    diagnostic ``raw_evidence`` (``manual_persist`` never persists it)."""
    evidence: dict[str, object] = {"reason": reason, "correlation": "unverified"}
    if status is not None:
        evidence["status"] = status
    return AdapterReadResult(
        external_state=CASE_UNVERIFIED, observed_at=None, raw_evidence=evidence
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """M2-R §4: REFUSE to follow ANY HTTP redirect on the case read.

    ``urllib.request.urlopen`` follows 3xx automatically and — critically —
    FORWARDS the ``Authorization`` header to the redirect target, INCLUDING a
    CROSS-HOST one. For a credential-bearing read that is a leak (CWE-522): a
    compromised or misconfigured proxy could 302 the ``GET`` to an attacker host
    and harvest the Bearer key. A case ``GET`` must resolve DIRECTLY on the
    certified instance, so any redirect is treated as a transport anomaly:
    returning ``None`` makes urllib raise ``HTTPError`` for the 3xx, which
    ``read()`` already maps to ``ReadTransportError`` (-> ``reconciliation_failed``)
    — fail-closed, NEVER a cross-host credential leak, NEVER a fabricated verdict.

    This ONLY declines redirects. TLS certificate verification and base-URL
    validation are UNCHANGED (§4 forbids solving connectivity by disabling TLS or
    relaxing URL checks); ``build_opener`` still installs the default verifying
    ``HTTPSHandler``.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    """The production read opener: default handlers (verifying TLS) with the
    redirect handler REPLACED by ``_NoRedirectHandler``. ``.open(request,
    timeout=...)`` matches the ``urlopen`` call shape the reader uses."""
    return urllib.request.build_opener(_NoRedirectHandler)


class TheHiveReadAdapter(ReadAdapter):
    """Case-CREATION effect verifier over the TheHive Case API (one ``GET``, no
    retry).

    Constructor arguments (mirror ``TheHiveExecutor``):
      credentials -- ``AdapterCredentials`` for THEHIVE_BASE_URL /
          THEHIVE_API_KEY (Bearer), already validated by the factory.
      timeout -- seconds for the single outbound ``GET``.
      transport -- the deployment/test seam: a callable
          ``transport(request, timeout=...) -> response`` where response has
          ``status`` / ``read()`` — matching ``urllib.request.urlopen``.
          Production uses a NO-REDIRECT urllib opener (M2-R §4: a 3xx is refused,
          so the ``Authorization`` header is NEVER forwarded to a cross-host
          redirect target); there is NO retry layer, NO polling and NO callback
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
                "thehive read adapter requires credentials for adapter "
                f"'thehive', got credentials for adapter "
                f"'{credentials.adapter}'"
            )
        # Defense-in-depth: re-validate the base URL at construction (the factory
        # already validated it via credentials_from_settings).
        validate_base_url("thehive", credentials.base_url)
        if timeout <= 0:
            raise ExecutorConfigError(
                "THEHIVE_TIMEOUT_SECONDS must be a positive number"
            )
        self._credentials = credentials
        self._timeout = float(timeout)
        # M2-R §4: the production default is a NO-REDIRECT opener, never bare
        # ``urlopen`` — a case ``GET`` must resolve directly on the certified
        # instance, and a 3xx must NOT carry the Bearer key to another host.
        self._transport = transport or _build_opener().open

    # -- contract ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "thehive"

    # -- read --------------------------------------------------------------

    def read(self, request: AdapterReadRequest) -> AdapterReadResult:
        """One ``GET /api/case/{reference}`` -> the verified creation effect.

        Returns ``case_created`` ONLY on the full identity + correlation +
        creation conjunction; ``case_unverified`` (refused downstream) when a 200
        fails it; raises ``ReadTransportError`` (-> ``reconciliation_failed``) on
        any transport failure. NEVER ``confirmed_failure``, NEVER a mutation,
        NEVER a retry.
        """
        reference = request.external_reference
        if not isinstance(reference, str) or not reference:
            # Defensive: the pipeline guarantees a non-empty str reference
            # (MissingExternalReference fires earlier), but a reader must never
            # fabricate one — an absent/empty/non-string reference is unverified.
            return _unverified("missing_reference")

        # URL-encode the reference so a hostile value cannot traverse the path
        # ("~" — the EntityIdOrName id-prefix — is in urllib's always-safe set,
        # so it survives unencoded and still resolves by EntityId).
        safe_reference = urllib.parse.quote(reference, safe="")
        url = f"{self._credentials.base_url}/api/case/{safe_reference}"
        http_request = urllib.request.Request(
            url, headers=self._credentials.auth_headers(), method="GET"
        )
        try:
            response = self._transport(http_request, timeout=self._timeout)
        except TimeoutError as exc:
            raise ReadTransportError(
                self._sanitize(
                    f"thehive case read timed out after {self._timeout:g}s"
                ),
                category="timeout",
            ) from exc
        except urllib.error.HTTPError as exc:
            raise self._on_http_error(exc) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ReadTransportError(
                self._sanitize(f"thehive case read connection failed: {exc}"),
                category="connection_failure",
            ) from exc

        status = getattr(response, "status", None)
        if status != 200:
            # urllib raises HTTPError for 4xx/5xx, so a NON-raising non-200 is an
            # unexpected transport shape (an odd 2xx, or a stub returning one).
            # It is a read UNCERTAINTY, never a confirmed effect.
            raise ReadTransportError(
                self._sanitize(
                    f"thehive case read returned unexpected status {status}"
                ),
                category="transport_error",
            )

        payload_text = response.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(payload_text)
        except ValueError:
            return _unverified("non_json_body", status)
        if not isinstance(payload, dict):
            return _unverified("non_object_body", status)
        return self._verify(request, payload, status)

    # -- internals ---------------------------------------------------------

    def _verify(
        self, request: AdapterReadRequest, payload: dict, status: object
    ) -> AdapterReadResult:
        """Apply the identity + correlation + creation conjunction (M2 §5)."""
        # 1. IDENTITY — the string resource id must EQUAL the persisted
        #    reference. OutputCase guarantees _id == id, so "id" is a defensive
        #    fallback for the SAME string; the numeric caseId is NEVER a
        #    substitute (M1 §4).
        resource_id = payload.get("_id")
        if not isinstance(resource_id, str) or not resource_id:
            resource_id = payload.get("id")
        if not isinstance(resource_id, str) or not resource_id:
            return _unverified("no_string_resource_id", status)
        if resource_id != request.external_reference:
            # A DIFFERENT case answered (or the reference is stale) — never this
            # execution's effect. Cross-tenant / historical same-number cases are
            # rejected here, not confirmed.
            return _unverified("resource_id_mismatch", status)

        # 2. CORRELATION — the case must carry THIS execution's tag. Without it
        #    the resource is not provably the one THIS execution created.
        if not _tags_carry_execution(payload.get("tags"), request.execution_id):
            return _unverified("missing_execution_correlation_tag", status)

        # 3. CREATION EFFECT (design §5.2 gate 3 — MANDATORY; M2-R §3 unifies the
        #    code to the frozen design). createdAt is the authoritative creation
        #    time (epoch millis -> observed_at). A MISSING / INVALID / absurd
        #    createdAt yields None, which NO LONGER verifies: without an
        #    authenticated creation time the read cannot independently prove "THIS
        #    execution created THIS case" (a same-id case from history, or one whose
        #    correlation tag was re-attached, would otherwise pass on identity +
        #    correlation alone — the reviewer's ten-year-old-re-tagged-case probe).
        #    Third AND gate: absent it -> case_unverified (reason=missing_created_at,
        #    matching design §5.2), REFUSED downstream, ZERO fact. observed_at (the
        #    EXTERNAL creation time) stays deliberately distinct from a SERVER
        #    observation time — the reader never substitutes "now" for the historical
        #    creation time and never lets an absent/early time gain a sorting
        #    advantage. The stricter createdAt-vs-DISPATCH-time / instance / tenant
        #    correlation needs the immutable dispatch record carried on the frozen
        #    AdapterReadRequest DTO -> deferred to the M2-R Amendment (§3 stop).
        observed_at = _created_at_to_datetime(payload.get("createdAt"))
        if observed_at is None:
            return _unverified("missing_created_at", status)
        case_number = payload.get("caseId")
        evidence: dict[str, object] = {
            "resource_id": resource_id,
            "status": status,
            "correlation": "execution_tag_present",
            "created_at_present": True,
        }
        if isinstance(case_number, int) and not isinstance(case_number, bool):
            # audit-only human case number; NEVER the reference, NEVER required.
            evidence["case_number"] = case_number
        return AdapterReadResult(
            external_state=CASE_CREATED,
            observed_at=observed_at,
            raw_evidence=evidence,
        )

    def _on_http_error(self, exc: urllib.error.HTTPError) -> ReadTransportError:
        """Map an HTTP error to a ``ReadTransportError`` with a SAFE STATIC
        category (M2 §5 discrimination). NO error body is parsed or carried — a
        401/403/404/5xx is a READ FAILURE (-> ``reconciliation_failed``), NEVER
        ``confirmed_failure`` and NEVER a fabricated effect. A 404 deliberately
        merges "absent" and "tenant-invisible" (the TheHive ``visible`` design):
        neither proves the creation failed."""
        status = exc.code
        if status == 401:
            category = "authentication_failure"
        elif status == 403:
            category = "authorization_failure"
        elif status == 404:
            category = "not_found"
        elif status in (502, 503, 504):
            category = "adapter_unavailable"
        else:
            category = "transport_error"
        return ReadTransportError(
            self._sanitize(f"thehive case read failed with HTTP {status}"),
            category=category,
        )

    def _sanitize(self, text: str) -> str:
        """Strip any secret value from a message before it can surface in a
        raised exception (3.2.2 boundary, mirrors the write adapter)."""
        return redact_text(text, current_secret_values())
