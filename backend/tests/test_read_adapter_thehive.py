"""TheHiveReadAdapter isolation tests.

Scope: what this file establishes, and what it does not. The TheHive read contract
is certified against the read semantics of TheHive 4.1.24-1, but no TheHive
runtime exists on this host (no container runtime / virtualization / sufficient
memory). The reader is therefore exercised through an injected stub transport (no
network) at four levels, with the live read left as a deselected, env-gated skip:

  1. UNIT — ``TheHiveReadAdapter.read()`` against a ``StubTransport``: the verified
     creation conjunction (``case_created``), every unverified refusal
     (``case_unverified``), the 401/403/404/timeout/connection/5xx discrimination
     (each a ``ReadTransportError`` with a static safe category, never
     ``confirmed_failure``), URL / reference safety, and secret hygiene.
  2. MAPPING — the thehive vocabulary is empty (fail-closed), so both reader words
     tie into the single path-agnostic ``normalize_external_state`` map as refused
     (``UnrecognizedExternalState``): ``case_created`` (which the reader still emits
     on a verified read) and ``case_unverified`` are refused alike, because the
     fixed two-parameter contract cannot tell a trusted-reader signal from a
     webhook-forged string. The synthesis word stays unmapped, so no path launders
     a single-source string into success.
  3. SERVICE — the real pipeline (correlate -> read -> validate -> map) driven by an
     explicitly injected reader (the registry constructor takes the reader). With
     the empty vocabulary the map refuses the reader's ``case_created`` -> zero
     Outcome Fact (the read-failure ``reconciliation_failed`` path is unchanged).
     This injection-based isolation chain is not a complete HTTP E2E and does not
     claim a confirmed outcome.
  4. FACTORY — ``create_read_adapter_registry`` registers the reader only when the
     three authorization gates all pass (a well-formed base URL + an independent
     read-only key, never the create-capable write key + an exact certified-version
     match), fails closed on any missing / mismatched gate, tolerates a
     malformed URL, issues no HTTP at build time, and never mutates the empty
     ``default_read_adapter_registry()``. The reader's production transport is
     a no-redirect opener, so a cross-host 3xx can never carry the ``Authorization``
     header.

The live ``GET`` is ``TestRealLabRead`` — behind ``@pytest.mark.external``
(deselected unless ``-m external``) and a live-Lab env guard, so it skips rather
than faking a result. No default ``pytest`` run here touches a real system.

Invariants: ``read`` is the sole verb (no execute / compensate / dispatch / create
/ close); one read attempt, no retry / poll / compensation; the numeric ``caseId``
is never the reference; identity + correlation + creation (a valid ``createdAt``)
must all hold for the reader to emit ``case_created`` — the creation-time gate is
mandatory, so a missing/invalid ``createdAt`` yields ``case_unverified`` — and the
empty vocabulary then refuses ``case_created`` at the fail-closed mapping (zero
fact); a failed read is ``reconciliation_failed``, never ``confirmed_failure``;
credentials ride only in the ``Authorization`` header and never surface in a
message, a fact, or ``raw_evidence``.
"""
import io
import json
import os
import urllib.error
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)
from app.schemas.reconcile import MANUAL_RECONCILE_SOURCE, ManualReconcileResponse
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.secrets import AdapterCredentials
from app.services.executions.thehive import sentinelflow_execution_tag
from app.services.manual_reconcile import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterRegistry,
    ReadTransportError,
    UnsupportedAdapterRead,
    default_read_adapter_registry,
)
from app.services.outcomes.manual_reconcile import reconcile_execution
from app.services.outcomes.reconciliation import (
    ADAPTER_STATE_VOCABULARIES,
    UnrecognizedExternalState,
    normalize_external_state,
)
from app.services.read_adapters.registry import create_read_adapter_registry
from app.services.read_adapters.thehive import (
    CASE_CREATED,
    CASE_UNVERIFIED,
    CERTIFIED_THEHIVE_VERSION,
    TheHiveReadAdapter,
    _build_opener,
    _NoRedirectHandler,
)

#
# constants + stub transport (the isolation seam — no network, ever)
#
# An obviously-fake loopback-style Lab base URL + key, never a real secret; used
# only so the hygiene tests can assert these exact values never leak.
LAB_BASE_URL = "https://thehive.lab.local"
LAB_API_KEY = "LAB_THEHIVE_KEY_DO_NOT_USE"

# A secret that only ever lives inside a stubbed HTTP error body — the reader must
# never read an error body, so this must never surface in a raised message.
SECRET_BODY = b'{"message":"SUPER_SECRET_BODY","x":"AKIAIOSFODNN7EXAMPLE"}'

# Fixed clock for seeding the dispatch chain (execution_log.created_at).
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

# A realistic EntityIdOrName string reference (OutputCase ``_id`` == ``id``); the
# ``~`` id-prefix is in urllib's always-safe set, so it survives URL-encoding.
REFERENCE = "~42"

# The authenticated human recorder identity for service-level calls.
OPERATOR = "recon-op"


class _StubResponse:
    """Mimics the subset of ``http.client.HTTPResponse`` the reader touches:
    ``.status`` and ``.read()`` -> bytes."""

    def __init__(self, status, body):
        self.status = status
        if isinstance(body, bytes):
            self._body = body
        else:
            self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


class StubTransport:
    """Mimics ``urllib.request.urlopen``: records every ``(request, timeout)``,
    then returns a canned response or raises a canned exception. Every offline test
    drives the reader through it — no socket is ever opened."""

    def __init__(self, *, status=200, body=None, exc=None):
        self._status = status
        self._body = body if body is not None else {}
        self._exc = exc
        self.calls: list[tuple] = []

    def __call__(self, request, timeout=None):
        self.calls.append((request, timeout))
        if self._exc is not None:
            raise self._exc
        return _StubResponse(self._status, self._body)

    @property
    def call_count(self):
        return len(self.calls)

    @property
    def last_request(self):
        return self.calls[-1][0]

    @property
    def last_timeout(self):
        return self.calls[-1][1]


def _creds(base_url=LAB_BASE_URL, api_key=LAB_API_KEY):
    return AdapterCredentials(adapter="thehive", base_url=base_url, api_key=api_key)


def _reader(transport, *, timeout=30.0, creds=None):
    return TheHiveReadAdapter(creds or _creds(), timeout=timeout, transport=transport)


def _request(execution_id, reference=REFERENCE, adapter="thehive"):
    return AdapterReadRequest(
        execution_id=execution_id, adapter=adapter, external_reference=reference
    )


def _recent_created_ms(minutes_ago=5):
    return int(
        (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).timestamp() * 1000
    )


def _case_body(
    execution_id,
    *,
    reference=REFERENCE,
    created_ms=None,
    case_number=42,
    extra_tags=None,
    include_id=True,
):
    """A realistic OutputCase v0 body (TheHive 4.1.24-1): ``_id`` ==
    ``id`` (String), ``createdAt`` (epoch millis), ``tags`` (the ``Set[String]``
    ``CaseSrv.create`` persists + echoes), ``caseId`` (the human case number,
    audit-only — never the reference)."""
    tags = [sentinelflow_execution_tag(execution_id), "sentinelflow"]
    if extra_tags:
        tags.extend(extra_tags)
    body = {
        "_id": reference,
        "createdAt": created_ms if created_ms is not None else _recent_created_ms(),
        "caseId": case_number,
        "tags": tags,
        "title": "escalated by SentinelFlow",
        "status": "Open",
        "severity": 3,
    }
    if include_id:
        body["id"] = reference
    return body


def _http_error(code, body=SECRET_BODY):
    """A ``urllib.error.HTTPError`` carrying a secret-laden body the reader must
    never read (it uses only ``exc.code``)."""
    return urllib.error.HTTPError(
        f"{LAB_BASE_URL}/api/case/{REFERENCE}", code, "err", {}, io.BytesIO(body)
    )


# ===========================================================================
# 1. CONTRACT — the reader is a ReadAdapter; ``read`` is the sole verb
# ===========================================================================
class TestReaderContract:
    def test_is_a_read_adapter_named_thehive(self):
        reader = _reader(StubTransport())
        assert isinstance(reader, ReadAdapter)
        assert reader.name == "thehive"

    def test_read_is_the_sole_verb_no_write_verbs_exist(self):
        # / A1: a ReadAdapter structurally CANNOT execute / compensate /
        # dispatch / create / close / delete — those verbs do not exist on it.
        reader = _reader(StubTransport())
        for forbidden in (
            "execute", "compensate", "dispatch", "create_case", "close_case",
            "delete", "delete_case", "trigger", "run", "write", "post",
        ):
            assert not hasattr(reader, forbidden), forbidden

    def test_rejects_credentials_for_a_different_adapter(self):
        with pytest.raises(ExecutorConfigError):
            TheHiveReadAdapter(
                AdapterCredentials(adapter="shuffle", base_url=LAB_BASE_URL, api_key="x"),
                transport=StubTransport(),
            )

    def test_rejects_non_positive_timeout(self):
        with pytest.raises(ExecutorConfigError):
            TheHiveReadAdapter(_creds(), timeout=0, transport=StubTransport())

    def test_rejects_malformed_base_url(self):
        with pytest.raises(ExecutorConfigError):
            TheHiveReadAdapter(_creds(base_url="not-a-url"), transport=StubTransport())


# ===========================================================================
# 2. VERIFIED CREATION EFFECT — the identity+correlation+creation conjunction
# ===========================================================================
class TestVerifiedCreationEffect:
    def test_200_matching_id_and_correlation_tag_yields_case_created(self):
        eid = uuid.uuid4()
        created = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        transport = StubTransport(
            body=_case_body(eid, created_ms=int(created.timestamp() * 1000))
        )
        result = _reader(transport).read(_request(eid))
        assert isinstance(result, AdapterReadResult)
        assert result.external_state == CASE_CREATED
        assert result.observed_at == created  # epoch millis -> aware UTC
        assert result.raw_evidence["resource_id"] == REFERENCE
        assert result.raw_evidence["correlation"] == "execution_tag_present"
        assert result.raw_evidence["created_at_present"] is True
        assert result.raw_evidence["case_number"] == 42
        assert transport.call_count == 1  # ONE read — no retry / poll

    def test_id_fallback_when__id_absent(self):
        # OutputCase guarantees _id == id; "id" is a defensive fallback for the
        # SAME string (never the numeric caseId).
        eid = uuid.uuid4()
        body = _case_body(eid)
        del body["_id"]
        result = _reader(StubTransport(body=body)).read(_request(eid))
        assert result.external_state == CASE_CREATED

    def test_absent_created_at_is_unverified(self):
        # M2-R : a missing createdAt FAILS the
        # creation gate -> case_unverified (reason=missing_created_at), NOT
        # case_created. Identity + a re-attachable correlation tag are NOT enough to
        # prove "this execution created this case" without an authenticated creation
        # time (the reviewer's probe: a missing / ten-year-old createdAt must not
        # verify). The reader never substitutes a server-observation time for the
        # historical creation time.
        eid = uuid.uuid4()
        body = _case_body(eid)
        del body["createdAt"]
        result = _reader(StubTransport(body=body)).read(_request(eid))
        assert result.external_state == CASE_UNVERIFIED
        assert result.observed_at is None
        assert result.raw_evidence["reason"] == "missing_created_at"

    def test_extra_tags_do_not_defeat_correlation(self):
        eid = uuid.uuid4()
        body = _case_body(eid, extra_tags=["soc:tier1", "src:sentinelflow"])
        result = _reader(StubTransport(body=body)).read(_request(eid))
        assert result.external_state == CASE_CREATED

    def test_case_created_is_refused_by_the_fail_closed_map(self):
        # M2-R : the reader still EMITS case_created, but the path-agnostic 3.4.3-B
        # map now REFUSES it (fail-closed) — the 2-param contract cannot tell
        # this trusted-reader word from a webhook-forged string, so it maps to NOTHING
        # on ANY path until the source-isolation Amendment lands.
        with pytest.raises(UnrecognizedExternalState):
            normalize_external_state("thehive", CASE_CREATED)


# ===========================================================================
# 3. UNVERIFIED REFUSALS — a 200 that FAILS the conjunction is NEVER success
# ===========================================================================
class TestUnverifiedRefusals:
    def _read(self, eid, body, *, reference=REFERENCE):
        return _reader(StubTransport(status=200, body=body)).read(
            _request(eid, reference=reference)
        )

    def test_resource_id_mismatch_is_unverified(self):
        eid = uuid.uuid4()
        body = _case_body(eid, reference="~999")  # a DIFFERENT case answered
        result = self._read(eid, body, reference=REFERENCE)
        assert result.external_state == CASE_UNVERIFIED
        assert result.observed_at is None
        assert result.raw_evidence["reason"] == "resource_id_mismatch"

    def test_missing_correlation_tag_is_unverified(self):
        eid = uuid.uuid4()
        body = _case_body(eid)
        body["tags"] = ["sentinelflow", "soc:tier1"]  # no execution tag
        result = self._read(eid, body)
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "missing_execution_correlation_tag"

    def test_a_sibling_executions_tag_is_unverified(self):
        # the SAME reference but a tag binding a DIFFERENT execution -> not THIS
        # execution's effect (a historical / cross-tenant same-id case is rejected).
        eid = uuid.uuid4()
        other = uuid.uuid4()
        body = _case_body(other, reference=REFERENCE)
        result = self._read(eid, body, reference=REFERENCE)
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "missing_execution_correlation_tag"

    def test_no_string_resource_id_is_unverified(self):
        eid = uuid.uuid4()
        body = _case_body(eid)
        body["_id"] = 42  # numeric, NOT a string resource id
        body["id"] = 42
        result = self._read(eid, body)
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "no_string_resource_id"

    def test_numeric_case_number_is_never_the_reference(self):
        # the human caseId (number) can NEVER substitute for the string _id.
        eid = uuid.uuid4()
        body = {
            "caseId": 42,
            "createdAt": _recent_created_ms(),
            "tags": [sentinelflow_execution_tag(eid)],
        }
        result = self._read(eid, body)
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "no_string_resource_id"

    def test_empty_tags_is_unverified(self):
        eid = uuid.uuid4()
        body = _case_body(eid)
        body["tags"] = []
        result = self._read(eid, body)
        assert result.external_state == CASE_UNVERIFIED

    def test_non_json_body_is_unverified(self):
        eid = uuid.uuid4()
        transport = StubTransport(status=200, body=b"<html>not json</html>")
        result = _reader(transport).read(_request(eid))
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "non_json_body"

    def test_json_array_body_is_unverified(self):
        eid = uuid.uuid4()
        transport = StubTransport(status=200, body=[{"_id": REFERENCE}])  # non-object
        result = _reader(transport).read(_request(eid))
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "non_object_body"

    def test_empty_reference_never_issues_a_get(self):
        eid = uuid.uuid4()
        transport = StubTransport()
        result = _reader(transport).read(_request(eid, reference=""))
        assert result.external_state == CASE_UNVERIFIED
        assert result.raw_evidence["reason"] == "missing_reference"
        assert transport.call_count == 0  # no fabricated reference, no GET

    def test_case_unverified_is_refused_by_the_mapping(self):
        # the crux: a 200 that fails the conjunction is NEVER laundered to success.
        with pytest.raises(UnrecognizedExternalState) as exc:
            normalize_external_state("thehive", CASE_UNVERIFIED)
        assert exc.value.adapter == "thehive"


# ===========================================================================
# 4. ERROR DISCRIMINATION — read failures, NEVER effect verdicts
# ===========================================================================
class TestErrorDiscrimination:
    @pytest.mark.parametrize(
        "code,category",
        [
            (401, "authentication_failure"),
            (403, "authorization_failure"),
            (404, "not_found"),
            (500, "transport_error"),
            (502, "adapter_unavailable"),
            (503, "adapter_unavailable"),
            (504, "adapter_unavailable"),
        ],
    )
    def test_http_errors_map_to_safe_static_categories(self, code, category):
        eid = uuid.uuid4()
        transport = StubTransport(exc=_http_error(code))
        with pytest.raises(ReadTransportError) as exc:
            _reader(transport).read(_request(eid))
        assert exc.value.category == category
        assert LAB_API_KEY not in str(exc.value)  # never leaks the key
        assert "SUPER_SECRET_BODY" not in str(exc.value)  # never carries the body

    def test_timeout_maps_to_timeout_category(self):
        eid = uuid.uuid4()
        transport = StubTransport(exc=TimeoutError("simulated timeout"))
        with pytest.raises(ReadTransportError) as exc:
            _reader(transport).read(_request(eid))
        assert exc.value.category == "timeout"

    def test_urlerror_maps_to_connection_failure(self):
        eid = uuid.uuid4()
        transport = StubTransport(exc=urllib.error.URLError("connection refused"))
        with pytest.raises(ReadTransportError) as exc:
            _reader(transport).read(_request(eid))
        assert exc.value.category == "connection_failure"

    def test_oserror_maps_to_connection_failure(self):
        eid = uuid.uuid4()
        transport = StubTransport(exc=OSError("network unreachable"))
        with pytest.raises(ReadTransportError) as exc:
            _reader(transport).read(_request(eid))
        assert exc.value.category == "connection_failure"
        assert transport.call_count == 1

    def test_non_200_non_raising_is_transport_error(self):
        # a stub that RETURNS (not raises) an odd 2xx is a read UNCERTAINTY.
        eid = uuid.uuid4()
        transport = StubTransport(status=201, body=_case_body(eid))
        with pytest.raises(ReadTransportError) as exc:
            _reader(transport).read(_request(eid))
        assert exc.value.category == "transport_error"

    def test_no_error_category_is_ever_a_mapped_failure_state(self):
        # 401/403/404/timeout are READ failures -> reconciliation_failed, NEVER
        # confirmed_failure. The thehive vocabulary evidences NO failure word.
        assert ADAPTER_STATE_VOCABULARIES["thehive"].terminal_failure_states == frozenset()


# ===========================================================================
# 5. URL / REFERENCE SAFETY
# ===========================================================================
class TestUrlAndReferenceSafety:
    def test_get_url_is_case_api_plus_reference(self):
        eid = uuid.uuid4()
        transport = StubTransport(body=_case_body(eid))
        _reader(transport).read(_request(eid, reference="~42"))
        req = transport.last_request
        assert req.full_url == f"{LAB_BASE_URL}/api/case/~42"  # ~ is always-safe
        assert req.get_method() == "GET"

    def test_authorization_header_carries_the_bearer_key(self):
        eid = uuid.uuid4()
        transport = StubTransport(body=_case_body(eid))
        _reader(transport).read(_request(eid))
        assert transport.last_request.get_header("Authorization") == f"Bearer {LAB_API_KEY}"

    def test_timeout_is_forwarded_to_the_transport(self):
        eid = uuid.uuid4()
        transport = StubTransport(body=_case_body(eid))
        _reader(transport, timeout=7.5).read(_request(eid))
        assert transport.last_timeout == 7.5

    def test_path_traversal_reference_is_neutralized(self):
        eid = uuid.uuid4()
        hostile = "../../etc/passwd"
        transport = StubTransport(body=_case_body(eid, reference=hostile))
        _reader(transport).read(_request(eid, reference=hostile))
        url = transport.last_request.full_url
        segment = url.split("/api/case/", 1)[1]
        assert "/" not in segment  # quote(..., safe="") encoded every slash
        assert segment == "..%2F..%2Fetc%2Fpasswd"


# ===========================================================================
# 6. SECRET HYGIENE (3.2.2 boundary)
# ===========================================================================
class TestSecretHygiene:
    def test_api_key_never_appears_in_any_raised_message(self):
        eid = uuid.uuid4()
        for exc in (
            _http_error(401), _http_error(404), TimeoutError("t"),
            urllib.error.URLError("u"), OSError("o"),
        ):
            with pytest.raises(ReadTransportError) as raised:
                _reader(StubTransport(exc=exc)).read(_request(eid))
            assert LAB_API_KEY not in str(raised.value)

    def test_error_body_is_never_carried_into_the_message(self):
        eid = uuid.uuid4()
        with pytest.raises(ReadTransportError) as raised:
            _reader(StubTransport(exc=_http_error(500))).read(_request(eid))
        assert "SUPER_SECRET_BODY" not in str(raised.value)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(raised.value)

    def test_a_configured_secret_in_a_transport_error_is_redacted(self, monkeypatch):
        # _sanitize runs redact_text against current_secret_values(); a value that IS
        # a live setting secret is masked even if the OS error text carries it.
        sentinel = "SUPER_SECRET_LAB_KEY_0123456789"
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", sentinel)
        eid = uuid.uuid4()
        exc = OSError(f"handshake failed with {sentinel}")
        with pytest.raises(ReadTransportError) as raised:
            _reader(StubTransport(exc=exc)).read(_request(eid))
        assert sentinel not in str(raised.value)
        assert "***" in str(raised.value)

    def test_raw_evidence_carries_no_secret(self):
        eid = uuid.uuid4()
        result = _reader(StubTransport(body=_case_body(eid))).read(_request(eid))
        blob = json.dumps(result.raw_evidence)
        assert LAB_API_KEY not in blob
        assert "Authorization" not in blob
        assert set(result.raw_evidence) <= {
            "resource_id", "status", "correlation", "created_at_present", "case_number",
        }


# ===========================================================================
# 7. FACTORY — settings-driven registry, fail-closed,
# never mutates the seal
# ===========================================================================
def _authorize_thehive_reader(
    monkeypatch,
    *,
    base_url=LAB_BASE_URL,
    read_api_key=LAB_API_KEY,
    expected_version=CERTIFIED_THEHIVE_VERSION,
):
    """M2-R : set the THREE settings that authorize a TheHive reader — base URL
    + an INDEPENDENT read-only key + an EXACT certified version. The WRITE key
    (THEHIVE_API_KEY) is left untouched on purpose: authorization must never
    depend on it."""
    monkeypatch.setattr(settings, "THEHIVE_BASE_URL", base_url)
    monkeypatch.setattr(settings, "THEHIVE_READ_API_KEY", read_api_key)
    monkeypatch.setattr(settings, "THEHIVE_EXPECTED_VERSION", expected_version)


class TestRegistryFactory:
    def test_unconfigured_settings_register_no_thehive_reader(self, monkeypatch):
        # M2-R : with NONE of the three authorization settings present, no reader.
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", "")
        monkeypatch.setattr(settings, "THEHIVE_READ_API_KEY", "")
        monkeypatch.setattr(settings, "THEHIVE_EXPECTED_VERSION", "")
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is False
        with pytest.raises(UnsupportedAdapterRead):
            registry.get("thehive")

    def test_fully_authorized_settings_register_the_thehive_reader(self, monkeypatch):
        # M2-R : base URL + INDEPENDENT read-only key + EXACT certified version.
        _authorize_thehive_reader(monkeypatch)
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is True
        reader = registry.get("thehive")
        assert isinstance(reader, TheHiveReadAdapter)
        assert reader.name == "thehive"

    def test_the_write_key_alone_never_authorizes_a_reader(self, monkeypatch):
        # M2-R LEAST PRIVILEGE (reviewer修正项 A): THEHIVE_API_KEY (the
        # create-capable WRITE key) set + version asserted, but NO independent read
        # key -> NO reader. The factory NEVER falls back to the write key, so a
        # reader can never inherit create privilege it does not need.
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        monkeypatch.setattr(settings, "THEHIVE_READ_API_KEY", "")
        monkeypatch.setattr(
            settings, "THEHIVE_EXPECTED_VERSION", CERTIFIED_THEHIVE_VERSION
        )
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is False

    def test_the_reader_rides_the_read_key_not_the_write_key(self, monkeypatch):
        # M2-R : when BOTH keys are set, the Authorization header the reader
        # actually sends carries the INDEPENDENT read-only key, NEVER the
        # create-capable write key. Behavior-level: inspect the real request.
        write_key = "WRITE_KEY_MUST_NOT_RIDE_THE_READER"
        read_key = "READ_ONLY_KEY_EXPECTED_ON_THE_READER"
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", write_key)
        monkeypatch.setattr(settings, "THEHIVE_READ_API_KEY", read_key)
        monkeypatch.setattr(
            settings, "THEHIVE_EXPECTED_VERSION", CERTIFIED_THEHIVE_VERSION
        )
        transport = StubTransport(body={})
        reader = create_read_adapter_registry(transport=transport).get("thehive")
        reader.read(_request(uuid.uuid4()))  # one GET; body {} -> unverified, no raise
        auth = transport.last_request.get_header("Authorization")
        assert auth == f"Bearer {read_key}"
        assert write_key not in (auth or "")

    def test_missing_expected_version_fails_closed(self, monkeypatch):
        # M2-R : URL + read key present but NO asserted version -> fail-closed.
        # Mere URL + key presence never auto-authorizes the reader.
        _authorize_thehive_reader(monkeypatch, expected_version="")
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is False

    def test_version_mismatch_fails_closed(self, monkeypatch):
        # M2-R : a DIFFERENT asserted version refuses — 4.1.24-1 read semantics
        # are never applied to a non-certified server version by a one-line wiring.
        _authorize_thehive_reader(monkeypatch, expected_version="4.1.25-1")
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is False

    def test_malformed_base_url_is_skipped_not_raised(self, monkeypatch):
        # TOLERANT: one adapter's misconfiguration can never 500 every reconcile.
        _authorize_thehive_reader(monkeypatch, base_url="not-a-url")
        registry = create_read_adapter_registry()  # MUST NOT raise
        assert registry.is_supported("thehive") is False

    def test_factory_never_mutates_the_sealed_default_registry(self, monkeypatch):
        _authorize_thehive_reader(monkeypatch)
        create_read_adapter_registry()
        # the SEALED production default stays EMPTY (TestEvidenceGap invariant).
        assert default_read_adapter_registry().registered_adapters() == ()
        assert default_read_adapter_registry().is_supported("thehive") is False

    def test_factory_registers_only_thehive_not_other_adapters(self, monkeypatch):
        _authorize_thehive_reader(monkeypatch)
        registry = create_read_adapter_registry()
        for other in ("shuffle", "wazuh", "mock"):
            assert registry.is_supported(other) is False

    def test_factory_issues_no_http_at_build_time(self, monkeypatch):
        _authorize_thehive_reader(monkeypatch)
        transport = StubTransport()
        registry = create_read_adapter_registry(transport=transport)
        registry.get("thehive")  # building + fetching the reader issues NO GET
        assert transport.call_count == 0


# ===========================================================================
# 7b. NO-REDIRECT CREDENTIAL LEAK — a cross-host 3xx must NEVER carry
# the Authorization header. Network-free: the property lives in the handler.
# ===========================================================================
class TestNoRedirectCredentialLeak:
    def test_redirect_request_returns_none_so_auth_is_never_forwarded(self):
        # ``urlopen`` follows a 3xx AND forwards Authorization to the target — a
        # cross-host leak (CWE-522). Returning ``None`` makes urllib RAISE for the
        # 3xx instead of re-issuing the GET (with the Bearer key) to another host;
        # ``read()`` maps that to ReadTransportError -> reconciliation_failed.
        handler = _NoRedirectHandler()
        req = urllib.request.Request(
            "https://thehive.lab.local/api/case/~42",
            headers={"Authorization": "Bearer READ_ONLY_SECRET"},
        )
        assert (
            handler.redirect_request(
                req,
                None,
                302,
                "Found",
                {"Location": "https://evil.example/steal"},
                "https://evil.example/steal",
            )
            is None
        )

    def test_default_opener_installs_the_no_redirect_handler(self):
        # The production opener the reader defaults to carries _NoRedirectHandler.
        opener = _build_opener()
        assert any(isinstance(h, _NoRedirectHandler) for h in opener.handlers)

    def test_default_transport_is_not_bare_urlopen(self):
        # With NO injected transport the reader must NOT default to bare urlopen
        # (which would follow a cross-host 3xx with the Authorization header).
        reader = TheHiveReadAdapter(_creds())
        assert reader._transport is not urllib.request.urlopen


# ===========================================================================
# 8. SERVICE LEVEL — the REAL pipeline via explicit reader injection
# ===========================================================================
def _seed_approval(db_session):
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force on edge-gateway",
        category="authentication",
        severity="high",
        first_seen=NOW,
        last_seen=NOW,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "escalate_to_incident", "target": "case", "rationale": "escalate"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id, status="approved", reviewer="analyst-1", reviewed_at=NOW
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _seed_chain(db_session, execution_id, *, rows, operator="ops-1"):
    """One execute chain from ``[(decision, detail), ...]`` in CHRONOLOGICAL order."""
    approval = _seed_approval(db_session)
    db_session.add_all(
        [
            ExecutionLog(
                execution_id=execution_id,
                approval_id=approval.id,
                decision=decision,
                direction="execute",
                action="escalate_to_incident",
                target="case",
                operator=operator,
                detail=detail,
                created_at=NOW + timedelta(seconds=i),
            )
            for i, (decision, detail) in enumerate(rows)
        ]
    )
    db_session.commit()
    return approval


def _thehive_rows(reference=REFERENCE, case_number=42):
    """A thehive dispatch chain: adapter from rows[0].detail['executor'], reference
    from rows[-1].detail['case_id'] (``_EXTERNAL_REFERENCE_KEYS['thehive']``)."""
    return [
        ("requested", {"executor": "thehive"}),
        ("dispatched", {"executor": "thehive"}),
        ("succeeded", {"case_id": reference, "case_number": case_number}),
    ]


def _facts(db_session, execution_id):
    return list(
        db_session.scalars(
            select(ExecutionOutcome).where(ExecutionOutcome.execution_id == execution_id)
        )
    )


def _only_fact(db_session, execution_id):
    rows = _facts(db_session, execution_id)
    assert len(rows) == 1, f"expected exactly one fact, got {len(rows)}"
    return rows[0]


def _outcome_count(db_session):
    return len(list(db_session.scalars(select(ExecutionOutcome))))


class TestServiceLevelClosure:
    """correlate -> read -> validate 3.4.3-A -> map 3.4.3-B, driven by an EXPLICITLY
    INJECTED ``TheHiveReadAdapter``. Under M2-R fail-closed the map REFUSES the
    reader's verified ``case_created`` -> ZERO Outcome Fact (the read-FAILURE
    ``reconciliation_failed`` path is unchanged). This injection-based isolation
    chain is NOT a complete HTTP E2E and does NOT claim a confirmed closure — it
    proves the fail-closed gate holds end-to-end at the service layer."""

    def test_verified_creation_is_refused_by_fail_closed_map_zero_facts(self, db_session):
        # M2-R : the reader VERIFIES the creation (identity + correlation + a valid
        # createdAt) and EMITS case_created, but the fail-closed path-agnostic map
        # REFUSES it -> UnrecognizedExternalState -> ZERO Outcome Fact. Proves the
        # synthesis signal cannot reach a confirmed_success fact from ANY path until
        # the source-isolation Amendment lands. The read still happens exactly once.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        created = datetime.now(timezone.utc) - timedelta(minutes=3)
        body = _case_body(eid, created_ms=int(created.timestamp() * 1000))
        transport = StubTransport(body=body)
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(
                db_session, eid, OPERATOR, ReadAdapterRegistry([_reader(transport)])
            )
        assert transport.call_count == 1  # ONE read — no retry / poll / compensation
        assert _outcome_count(db_session) == 0  # fail-closed: ZERO fact

    def test_unverified_read_is_refused_zero_facts(self, db_session):
        # a 200 for a DIFFERENT case (identity fails) -> case_unverified -> the map
        # REFUSES it -> ZERO facts. A bare 200 is NEVER a success fact.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        body = _case_body(eid, reference="~999")
        with pytest.raises(UnrecognizedExternalState):
            reconcile_execution(
                db_session, eid, OPERATOR, ReadAdapterRegistry([_reader(StubTransport(body=body))])
            )
        assert _outcome_count(db_session) == 0

    def test_404_is_reconciliation_failed_never_confirmed_failure(self, db_session):
        # a deleted / tenant-invisible case is a READ failure, NOT proof the creation
        # failed -> reconciliation_failed (ONE fact), NEVER confirmed_failure.
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        response = reconcile_execution(
            db_session, eid, OPERATOR,
            ReadAdapterRegistry([_reader(StubTransport(exc=_http_error(404)))]),
        )
        assert response.outcome_status == "reconciliation_failed"
        assert response.observed_at_kind == "server-observation"
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "reconciliation_failed"
        assert fact.outcome_status != "confirmed_failure"
        assert fact.detail["failure_category"] == "not_found"
        assert fact.detail["reason"] == "read_transport_failure"

    def test_repeat_reconcile_stays_fail_closed_zero_facts(self, db_session):
        # M2-R : reconciling TWICE over a verified creation still REFUSES both times
        # (fail-closed) -> ZERO facts, never an overwrite and never a laundered
        # success. (The append-only TWO-fact property is proven on the read-FAILURE
        # reconciliation_failed path, which the vocabulary fix does not touch.)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        body = _case_body(eid, created_ms=_recent_created_ms(minutes_ago=3))
        registry = ReadAdapterRegistry([_reader(StubTransport(body=body))])
        for _ in range(2):
            with pytest.raises(UnrecognizedExternalState):
                reconcile_execution(db_session, eid, OPERATOR, registry)
        assert _outcome_count(db_session) == 0


# ===========================================================================
# 9. REAL LAB READ — deselected by default; SKIPS (LAB BLOCKED), never fakes
# ===========================================================================
@pytest.mark.external
class TestRealLabRead:
    """The REAL ``GET /api/case/{_id}`` against a live TheHive 4.1.24-1 Lab.

    Behind ``@pytest.mark.external`` (conftest DESELECTS it unless ``-m external``)
    AND a live-Lab env guard, so a normal ``pytest`` run never touches a real system
    and this SKIPS rather than fabricating a result. LAB BLOCKED on this host (no
    container runtime / virtualization / memory — see the M2 Lab feasibility
    finding); it documents the exact real-read intent for the phase that has a
    running Lab, and is the ONLY place a real TheHive ``GET`` is issued.
    """

    def test_real_get_case_verifies_creation(self):
        # M2-R : a REAL success test must assert the VERIFIED creation effect
        # through the trusted evidence gate — it must NOT accept case_unverified as
        # success (the M2 disjunction ``in (CASE_CREATED, CASE_UNVERIFIED)`` let an
        # unverified read pass). So this asserts CASE_CREATED STRICTLY. NOTE: the
        # platform-level confirmed_success + persisted Outcome is FAIL-CLOSED under
        # M2-R (the empty vocabulary refuses case_created on every path), so this
        # real-Lab test proves the READER half only; the persisted-Outcome closure is
        # deferred to the source-isolation Amendment and stays LAB BLOCKED here.
        base_url = os.environ.get("THEHIVE_LAB_BASE_URL", "")
        api_key = os.environ.get("THEHIVE_LAB_API_KEY", "")
        reference = os.environ.get("THEHIVE_LAB_CASE_REF", "")
        execution_id = os.environ.get("THEHIVE_LAB_EXECUTION_ID", "")
        if not (base_url and api_key and reference and execution_id):
            pytest.skip(
                "LAB BLOCKED: no real TheHive Lab configured (THEHIVE_LAB_* env "
                "unset) — the read contract is SOURCE-certified only (b6649bb / "
                "2c2a7a4); see the M2-R §6 Lab feasibility finding"
            )
        creds = AdapterCredentials(adapter="thehive", base_url=base_url, api_key=api_key)
        reader = TheHiveReadAdapter(creds)  # REAL urllib opener, no stub
        result = reader.read(
            AdapterReadRequest(
                execution_id=uuid.UUID(execution_id),
                adapter="thehive",
                external_reference=reference,
            )
        )
        # STRICT: a real VERIFIED creation ONLY — an unverified read (a 200 that
        # failed identity / correlation / creation) is NOT success and must not pass.
        # A transport failure raises ReadTransportError (never a fabricated verdict).
        assert result.external_state == CASE_CREATED
        assert result.observed_at is not None  # a real authenticated creation time
