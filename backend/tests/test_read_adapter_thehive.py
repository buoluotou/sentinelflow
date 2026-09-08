"""TheHiveReadAdapter isolation tests (Phase 3.4.5-M2 §5 / §6).

WHAT THIS PROVES — and what it deliberately does NOT. The TheHive read contract is
SOURCE-certified (TheHive 4.1.24-1 = git ``b6649bb`` / ScalliGraph ``2c2a7a4``),
but there is NO real TheHive runtime on this host (LAB BLOCKED — no container
runtime / virtualization / sufficient memory). So this file proves the reader with
an INJECTED stub transport (no network) at THREE levels, and marks the real read as
a deselected, env-gated SKIP:

  1. UNIT — ``TheHiveReadAdapter.read()`` against a ``StubTransport``: the verified
     creation conjunction (``case_created``), every unverified refusal
     (``case_unverified``), the 401/403/404/timeout/connection/5xx discrimination
     (each a ``ReadTransportError`` with a SAFE STATIC category, NEVER
     ``confirmed_failure``), URL / reference safety, and secret hygiene.
  2. MAPPING — the reader's two words tie into the single path-agnostic 3.4.3-B
     map: ``case_created`` -> ``confirmed_success``; ``case_unverified`` -> REFUSED
     (``UnrecognizedExternalState``), so a bare HTTP 200 is never laundered.
  3. SERVICE — the REAL pipeline (correlate -> read -> validate 3.4.3-A -> map
     3.4.3-B -> append ONE Outcome Fact) driven by an EXPLICITLY INJECTED reader
     (the sanctioned constructor-injection seam, spec §22). This is the injection-
     based isolation platform chain that stands in for the LAB-BLOCKED real E2E.
  4. FACTORY — ``create_read_adapter_registry`` registers the reader iff THEHIVE
     credentials are configured, fails CLOSED otherwise, is TOLERANT of a malformed
     URL, issues NO HTTP at build time, and NEVER mutates the sealed empty
     ``default_read_adapter_registry()``.

The REAL ``GET`` is ``TestRealLabRead`` — behind ``@pytest.mark.external``
(deselected unless ``-m external``) AND a live-Lab env guard, so it SKIPS rather
than faking a result. No default ``pytest`` run here touches a real system.

Design invariants honored (M2 §5): ``read`` is the SOLE verb (no execute /
compensate / dispatch / create / close); ONE read attempt, no retry / poll /
compensation; the numeric ``caseId`` is NEVER the reference; identity + correlation
+ creation must ALL hold for ``case_created``; a failed READ is
``reconciliation_failed``, never ``confirmed_failure``; credentials ride ONLY in the
``Authorization`` header and never surface in a message, a fact, or ``raw_evidence``.
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
    TheHiveReadAdapter,
)

# ---------------------------------------------------------------------------
# constants + stub transport (the isolation seam — NO network, ever)
# ---------------------------------------------------------------------------
#: An obviously-fake loopback-style Lab base URL + key. NEVER a real secret; used
#: only so the hygiene tests can assert these exact values never leak.
LAB_BASE_URL = "https://thehive.lab.local"
LAB_API_KEY = "LAB_THEHIVE_KEY_DO_NOT_USE"

#: A secret that only ever lives inside a stubbed HTTP error BODY — the reader must
#: never read an error body, so this must never surface in a raised message.
SECRET_BODY = b'{"message":"SUPER_SECRET_BODY","x":"AKIAIOSFODNN7EXAMPLE"}'

#: Fixed clock for seeding the dispatch chain (execution_log.created_at).
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)

#: A realistic EntityIdOrName string reference (OutputCase ``_id`` == ``id``); the
#: ``~`` id-prefix is in urllib's always-safe set, so it survives URL-encoding.
REFERENCE = "~42"

#: The authenticated human recorder identity for service-level calls.
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
    then returns a canned response OR raises a canned exception. This is the ONLY
    way the reader is exercised here — no socket is ever opened."""

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
    """A realistic OutputCase v0 body (TheHive 4.1.24-1 = ``b6649bb``): ``_id`` ==
    ``id`` (String), ``createdAt`` (epoch millis), ``tags`` (the ``Set[String]``
    ``CaseSrv.create`` persists + echoes), ``caseId`` (the human case NUMBER,
    audit-only — NEVER the reference)."""
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
    NEVER read (it uses only ``exc.code``)."""
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
        # design §21 / A1: a ReadAdapter structurally CANNOT execute / compensate /
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

    def test_absent_created_at_still_verifies_with_server_observation_time(self):
        eid = uuid.uuid4()
        body = _case_body(eid)
        del body["createdAt"]
        result = _reader(StubTransport(body=body)).read(_request(eid))
        # identity + correlation already prove the creation; observed_at None -> the
        # platform supplies a SERVER-OBSERVATION time (the A1 None branch).
        assert result.external_state == CASE_CREATED
        assert result.observed_at is None
        assert result.raw_evidence["created_at_present"] is False

    def test_extra_tags_do_not_defeat_correlation(self):
        eid = uuid.uuid4()
        body = _case_body(eid, extra_tags=["soc:tier1", "src:sentinelflow"])
        result = _reader(StubTransport(body=body)).read(_request(eid))
        assert result.external_state == CASE_CREATED

    def test_case_created_maps_to_confirmed_success(self):
        # tie the reader word into the single path-agnostic 3.4.3-B map.
        mapped = normalize_external_state("thehive", CASE_CREATED)
        assert mapped.outcome_status == "confirmed_success"


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
        # the human caseId (number) can NEVER substitute for the string _id (M1 §4).
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
        # §5: 401/403/404/timeout are READ failures -> reconciliation_failed, NEVER
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
# 7. FACTORY — settings-driven registry, fail-closed, never mutates the seal
# ===========================================================================
class TestRegistryFactory:
    def test_unconfigured_settings_register_no_thehive_reader(self, monkeypatch):
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", "")
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", "")
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is False
        with pytest.raises(UnsupportedAdapterRead):
            registry.get("thehive")

    def test_configured_settings_register_the_thehive_reader(self, monkeypatch):
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        registry = create_read_adapter_registry()
        assert registry.is_supported("thehive") is True
        reader = registry.get("thehive")
        assert isinstance(reader, TheHiveReadAdapter)
        assert reader.name == "thehive"

    def test_malformed_base_url_is_skipped_not_raised(self, monkeypatch):
        # TOLERANT: one adapter's misconfiguration can never 500 every reconcile.
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", "not-a-url")
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        registry = create_read_adapter_registry()  # MUST NOT raise
        assert registry.is_supported("thehive") is False

    def test_factory_never_mutates_the_sealed_default_registry(self, monkeypatch):
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        create_read_adapter_registry()
        # the SEALED production default stays EMPTY (TestEvidenceGap invariant).
        assert default_read_adapter_registry().registered_adapters() == ()
        assert default_read_adapter_registry().is_supported("thehive") is False

    def test_factory_registers_only_thehive_not_other_adapters(self, monkeypatch):
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        registry = create_read_adapter_registry()
        for other in ("shuffle", "wazuh", "mock"):
            assert registry.is_supported(other) is False

    def test_factory_issues_no_http_at_build_time(self, monkeypatch):
        monkeypatch.setattr(settings, "THEHIVE_BASE_URL", LAB_BASE_URL)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", LAB_API_KEY)
        transport = StubTransport()
        registry = create_read_adapter_registry(transport=transport)
        registry.get("thehive")  # building + fetching the reader issues NO GET
        assert transport.call_count == 0


# ===========================================================================
# 8. SERVICE LEVEL — the REAL pipeline via explicit reader injection (spec §22)
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
    """correlate -> read -> validate 3.4.3-A -> map 3.4.3-B -> append ONE Outcome
    Fact, driven by an EXPLICITLY INJECTED ``TheHiveReadAdapter``. This is the
    injection-based isolation platform chain that stands in for the LAB-BLOCKED
    real E2E (M2 §6)."""

    def test_verified_creation_yields_confirmed_success_one_fact(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        created = datetime.now(timezone.utc) - timedelta(minutes=3)
        body = _case_body(eid, created_ms=int(created.timestamp() * 1000))
        transport = StubTransport(body=body)
        response = reconcile_execution(
            db_session, eid, OPERATOR, ReadAdapterRegistry([_reader(transport)])
        )
        assert isinstance(response, ManualReconcileResponse)
        assert response.accepted is True
        assert response.outcome_status == "confirmed_success"
        assert response.source == MANUAL_RECONCILE_SOURCE
        assert response.observed_at_kind == "external"  # createdAt supplied the time
        assert transport.call_count == 1  # ONE read — no retry / poll / compensation
        fact = _only_fact(db_session, eid)
        assert fact.outcome_status == "confirmed_success"
        assert fact.operator == OPERATOR
        assert fact.source == MANUAL_RECONCILE_SOURCE

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

    def test_repeat_reconcile_is_append_only(self, db_session):
        eid = uuid.uuid4()
        _seed_chain(db_session, eid, rows=_thehive_rows())
        body = _case_body(eid, created_ms=_recent_created_ms(minutes_ago=3))
        registry = ReadAdapterRegistry([_reader(StubTransport(body=body))])
        first = reconcile_execution(db_session, eid, OPERATOR, registry)
        second = reconcile_execution(db_session, eid, OPERATOR, registry)
        assert first.outcome_status == second.outcome_status == "confirmed_success"
        rows = _facts(db_session, eid)
        assert len(rows) == 2  # TWO append-only facts, never an overwrite
        assert len({r.id for r in rows}) == 2


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
        base_url = os.environ.get("THEHIVE_LAB_BASE_URL", "")
        api_key = os.environ.get("THEHIVE_LAB_API_KEY", "")
        reference = os.environ.get("THEHIVE_LAB_CASE_REF", "")
        execution_id = os.environ.get("THEHIVE_LAB_EXECUTION_ID", "")
        if not (base_url and api_key and reference and execution_id):
            pytest.skip(
                "LAB BLOCKED: no real TheHive Lab configured (THEHIVE_LAB_* env "
                "unset) — the read contract is SOURCE-certified only (b6649bb / "
                "2c2a7a4); see the M2 Lab feasibility finding"
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
        # A real read is either the verified creation or an honest refusal — never a
        # guess. Anything else (a transport failure) raises ReadTransportError.
        assert result.external_state in (CASE_CREATED, CASE_UNVERIFIED)
