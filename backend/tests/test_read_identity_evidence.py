"""M4-B read-side identity / version evidence seam tests (Phase 3.4.5-M4 §B; Amendment §12.2-B).

WHAT THIS PROVES — and what it deliberately does NOT. M4-B builds the READ-side half of the
gate-5 (INSTANCE / TENANT) unlock design: a read-only probe of the AUTHORITATIVE version /
organisation interfaces the EXACT certified TheHive version supports, plus a PURE fail-closed
assessor. TheHive 4.1.24-1 (= git ``b6649bb`` / ScalliGraph ``2c2a7a4``) is SOURCE-certified:

  - ``GET /api/status`` (v0 default router, PUBLIC) -> ``versions.TheHive``: a REAL RUNTIME
    version observation (a liveness proof, DISTINCT from the config-declared
    ``THEHIVE_EXPECTED_VERSION``). The SAME body carries ``config.protectDownloadsWith`` (the
    attachment-ZIP password — a SECRET) which the probe MUST NEVER return / log / persist.
  - ``GET /api/user/current`` (AUTHENTICATED, read-only key) -> ``organisation`` + ``roles``: the
    READER's OWN tenant context and RBAC roles.
  - ``GET /api/system`` DOES NOT EXIST in the source — it is a CANDIDATE only and is NEVER
    assumed / probed (the task's explicit rule).

THE HONEST LIMIT (why gate 5 STAYS fail-closed). The reader's OWN organisation is NOT the CASE's
owner; a 200 on ``/api/case/{id}`` proves only VISIBILITY (owned OR shared), never ownership; and
``/api/status`` exposes NO stable instance identity. OutputCase (4.1.24-1) carries NO organisation
field, so Amendment §12.2-B B2's precondition is UNMET: ``assess_identity_evidence`` ALWAYS returns
``gate5_instance_binding`` / ``gate5_tenant_binding`` = ``None`` — the seam UPGRADES the version
assertion to a runtime observation and records the reader's tenant context, but it NEVER unlocks
``confirmed_success`` on its own. A base URL / config string is NEVER a real identity.

There is NO real TheHive runtime on this host (LAB BLOCKED — no container runtime / virtualization
/ sufficient memory), so ``read_identity`` is exercised with an INJECTED path-routing stub
transport (no socket is ever opened) and the assessor is a pure function. NO test here marks a real
version as runtime-certified; that needs a real Lab probe (Amendment §12).

Design invariants honored: ``read_identity`` is a READ verb (never execute / compensate / dispatch
/ create / close / write / post); ONE probe per endpoint (no retry / poll); a probe failure is
INSUFFICIENT EVIDENCE (fail-closed), never a raise that aborts the reconcile, never a fabricated
identity; credentials ride ONLY in the ``Authorization`` header and the attachment password never
surfaces in an observation.
"""
import io
import json
import urllib.error
import urllib.parse

import pytest

from app.services.executions.secrets import AdapterCredentials
from app.services.read_adapters.thehive import (
    CERTIFIED_THEHIVE_VERSION,
    TheHiveReadAdapter,
)
from app.services.read_adapters.verified import (
    IDENTITY_PROBE_OBSERVED,
    IDENTITY_PROBE_UNAVAILABLE,
    IDENTITY_REASON_CASE_OWNER_UNOBSERVABLE,
    IDENTITY_REASON_READER_ORG_UNOBSERVED,
    IDENTITY_REASON_VERSION_NOT_CERTIFIED,
    IDENTITY_REASON_VERSION_UNOBSERVED,
    IdentityAssessment,
    IdentityEvidence,
    assess_identity_evidence,
)

# ---------------------------------------------------------------------------
# constants + path-routing stub transport (the isolation seam — NO network, ever)
# ---------------------------------------------------------------------------
#: An obviously-fake loopback-style Lab base URL + key. NEVER a real secret; used only so the
#: hygiene tests can assert these exact values never leak into an observation.
LAB_BASE_URL = "https://thehive.lab.local"
LAB_API_KEY = "LAB_THEHIVE_KEY_DO_NOT_USE"

#: The attachment-ZIP password (``config.protectDownloadsWith``) that rides inside the
#: ``/api/status`` body. It is a SECRET the probe MUST extract AROUND — it must NEVER appear in
#: an ``IdentityEvidence``.
ATTACHMENT_PASSWORD = "SUPER_SECRET_ATTACHMENT_PW_DO_NOT_LEAK"

#: The reader's own organisation (tenant context) + RBAC roles, as /api/user/current returns.
READER_ORG = "organisation-1"
READER_ROLES = ["read", "manageCase"]

#: The write-verb absence seal (mirrors test_read_adapter_thehive.py): read_identity is a READ
#: verb, so NONE of these may ever exist on the reader.
FORBIDDEN_WRITE_VERBS = (
    "execute", "compensate", "dispatch", "create_case", "close_case",
    "delete", "delete_case", "trigger", "run", "write", "post",
)


class _StubResponse:
    """Mimics the subset of ``http.client.HTTPResponse`` the probe touches: ``.status`` +
    ``.read()`` -> bytes."""

    def __init__(self, status, body):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


class IdentityStubTransport:
    """Routes by URL PATH: ``read_identity`` hits TWO endpoints (``/api/status`` +
    ``/api/user/current``), so a single-body stub is not enough. Each path maps to a canned
    ``(status, body)`` OR an exception to raise; an unconfigured path raises a 404 (fail-closed —
    the endpoint is treated as absent). This is the ONLY way the probe is exercised here — no
    socket is ever opened."""

    def __init__(self, *, routes=None):
        self._routes = routes or {}
        self.calls: list[tuple] = []

    def __call__(self, request, timeout=None):
        path = urllib.parse.urlparse(request.full_url).path
        self.calls.append((path, request, timeout))
        spec = self._routes.get(path)
        if spec is None:
            # An unconfigured path == the endpoint does not exist -> 404 (fail-closed).
            raise _http_error(404, path)
        if isinstance(spec, BaseException):
            raise spec
        status, body = spec
        return _StubResponse(status, body)

    @property
    def paths(self):
        return [c[0] for c in self.calls]

    @property
    def call_count(self):
        return len(self.calls)


def _http_error(code, path="/api/status", body=b'{"message":"SUPER_SECRET_BODY"}'):
    """A ``urllib.error.HTTPError`` carrying a secret-laden body the probe must NEVER read."""
    return urllib.error.HTTPError(
        f"{LAB_BASE_URL}{path}", code, "err", {}, io.BytesIO(body)
    )


def _status_body(version=CERTIFIED_THEHIVE_VERSION, *, include_secret=True, include_versions=True):
    """A realistic v0 ``/api/status`` body (TheHive 4.1.24-1 StatusCtrl.get): ``versions.TheHive``
    from the running JAR + ``config.protectDownloadsWith`` (the attachment password SECRET)."""
    body = {
        "config": {"authType": "local", "capabilities": ["password"], "ssoAutoLogin": False},
        "schemaStatus": [],
    }
    if include_versions:
        body["versions"] = {"Scalligraph": "3.4.5", "TheHive": version, "Play": "2.8.16"}
    if include_secret:
        body["config"]["protectDownloadsWith"] = ATTACHMENT_PASSWORD
    return body


def _user_body(organisation=READER_ORG, roles=None, *, include_org=True):
    """A realistic v0 ``OutputUser`` body from ``/api/user/current``: ``organisation`` (String) +
    ``roles`` (Set[String])."""
    body = {
        "_id": "~8", "id": "~8", "login": "reader@thehive.local", "name": "SF Reader",
        "hasKey": True, "status": "ok", "_type": "User",
    }
    if include_org:
        body["organisation"] = organisation
    if roles is not None:
        body["roles"] = roles
    else:
        body["roles"] = list(READER_ROLES)
    return body


def _creds(base_url=LAB_BASE_URL, api_key=LAB_API_KEY):
    return AdapterCredentials(adapter="thehive", base_url=base_url, api_key=api_key)


def _reader(transport, *, timeout=30.0, creds=None):
    return TheHiveReadAdapter(creds or _creds(), timeout=timeout, transport=transport)


def _both_ok_transport(version=CERTIFIED_THEHIVE_VERSION, organisation=READER_ORG):
    """A transport whose TWO probes BOTH succeed with a certified version + a reader org."""
    return IdentityStubTransport(routes={
        "/api/status": (200, _status_body(version)),
        "/api/user/current": (200, _user_body(organisation)),
    })


def _evidence(**overrides):
    """A fully-observed IdentityEvidence (certified version + reader org), overridable."""
    base = dict(
        observed_version=CERTIFIED_THEHIVE_VERSION,
        observed_reader_organisation=READER_ORG,
        observed_reader_roles=tuple(sorted(READER_ROLES)),
        version_probe=IDENTITY_PROBE_OBSERVED,
        organisation_probe=IDENTITY_PROBE_OBSERVED,
    )
    base.update(overrides)
    return IdentityEvidence(**base)


# ===========================================================================
# 1. assess_identity_evidence — the PURE fail-closed assessor (Component)
# ===========================================================================
class TestAssessIdentityEvidence:
    def test_full_evidence_version_matches_but_gate5_stays_none(self):
        # THE crux: even a fully-observed certified version + reader org NEVER binds gate 5,
        # because the CASE-owned tenant / instance is unobservable in 4.1.24-1 (§12.2-B B2 unmet).
        result = assess_identity_evidence(_evidence(), certified_version=CERTIFIED_THEHIVE_VERSION)
        assert isinstance(result, IdentityAssessment)
        assert result.version_matches_certified is True
        assert result.reader_organisation_known is True
        assert result.gate5_instance_binding is None
        assert result.gate5_tenant_binding is None
        assert result.reason == IDENTITY_REASON_CASE_OWNER_UNOBSERVABLE

    def test_version_mismatch_is_not_certified(self):
        result = assess_identity_evidence(
            _evidence(observed_version="4.1.99-9"), certified_version=CERTIFIED_THEHIVE_VERSION
        )
        assert result.version_matches_certified is False
        assert result.reason == IDENTITY_REASON_VERSION_NOT_CERTIFIED
        assert result.gate5_tenant_binding is None

    def test_version_unobserved_fails_closed(self):
        result = assess_identity_evidence(
            _evidence(observed_version=None, version_probe=IDENTITY_PROBE_UNAVAILABLE),
            certified_version=CERTIFIED_THEHIVE_VERSION,
        )
        assert result.version_matches_certified is False
        assert result.reason == IDENTITY_REASON_VERSION_UNOBSERVED

    def test_empty_version_string_is_unobserved(self):
        result = assess_identity_evidence(
            _evidence(observed_version=""), certified_version=CERTIFIED_THEHIVE_VERSION
        )
        assert result.version_matches_certified is False
        assert result.reason == IDENTITY_REASON_VERSION_UNOBSERVED

    def test_non_string_version_is_never_certified(self):
        # a bool / int / dict version is not a real observed version string.
        for bad in (True, 4, {"TheHive": "4.1.24-1"}):
            result = assess_identity_evidence(
                _evidence(observed_version=bad), certified_version=CERTIFIED_THEHIVE_VERSION
            )
            assert result.version_matches_certified is False

    def test_reader_org_unobserved(self):
        result = assess_identity_evidence(
            _evidence(observed_reader_organisation=None,
                      organisation_probe=IDENTITY_PROBE_UNAVAILABLE),
            certified_version=CERTIFIED_THEHIVE_VERSION,
        )
        assert result.reader_organisation_known is False
        assert result.reason == IDENTITY_REASON_READER_ORG_UNOBSERVED
        # version was still certified, but the org gap is reported and gate 5 stays None.
        assert result.version_matches_certified is True
        assert result.gate5_tenant_binding is None

    def test_empty_org_string_is_unobserved(self):
        result = assess_identity_evidence(
            _evidence(observed_reader_organisation=""), certified_version=CERTIFIED_THEHIVE_VERSION
        )
        assert result.reader_organisation_known is False

    def test_base_url_is_never_a_certified_version(self):
        # the task's explicit rule: a base URL string is NEVER passed off as a real identity.
        result = assess_identity_evidence(
            _evidence(observed_version=LAB_BASE_URL), certified_version=CERTIFIED_THEHIVE_VERSION
        )
        assert result.version_matches_certified is False
        assert result.reason == IDENTITY_REASON_VERSION_NOT_CERTIFIED

    def test_config_expected_version_string_alone_is_not_an_observation(self):
        # even if the observed version EQUALS the config-declared string, the assessor only
        # credits a match on the OBSERVED field; a None observation (no probe) never matches.
        result = assess_identity_evidence(
            _evidence(observed_version=None), certified_version=CERTIFIED_THEHIVE_VERSION
        )
        assert result.version_matches_certified is False

    def test_gate5_bindings_are_always_none_across_the_matrix(self):
        # NO combination of evidence EVER populates a gate-5 binding for 4.1.24-1.
        for ev in (
            _evidence(),
            _evidence(observed_version="0.0.0"),
            _evidence(observed_version=None),
            _evidence(observed_reader_organisation=None),
            _evidence(observed_version=None, observed_reader_organisation=None),
        ):
            result = assess_identity_evidence(ev, certified_version=CERTIFIED_THEHIVE_VERSION)
            assert result.gate5_instance_binding is None
            assert result.gate5_tenant_binding is None

    def test_assessor_is_pure_no_mutation_of_input(self):
        ev = _evidence()
        before = (ev.observed_version, ev.observed_reader_organisation,
                  ev.observed_reader_roles, ev.version_probe, ev.organisation_probe)
        assess_identity_evidence(ev, certified_version=CERTIFIED_THEHIVE_VERSION)
        after = (ev.observed_version, ev.observed_reader_organisation,
                 ev.observed_reader_roles, ev.version_probe, ev.organisation_probe)
        assert before == after

    def test_roles_default_to_empty_tuple(self):
        ev = _evidence(observed_reader_roles=())
        assert ev.observed_reader_roles == ()
        # an empty role set does NOT affect the org-known decision (the org string is what matters).
        result = assess_identity_evidence(ev, certified_version=CERTIFIED_THEHIVE_VERSION)
        assert result.reader_organisation_known is True


# ===========================================================================
# 2. read_identity — the probe verb against a path-routing stub (Component)
# ===========================================================================
class TestReadIdentityVerb:
    def test_observes_version_and_organisation(self):
        reader = _reader(_both_ok_transport())
        ev = reader.read_identity()
        assert isinstance(ev, IdentityEvidence)
        assert ev.observed_version == CERTIFIED_THEHIVE_VERSION
        assert ev.observed_reader_organisation == READER_ORG
        assert ev.observed_reader_roles == tuple(sorted(READER_ROLES))
        assert ev.version_probe == IDENTITY_PROBE_OBSERVED
        assert ev.organisation_probe == IDENTITY_PROBE_OBSERVED

    def test_extracts_only_version_never_the_raw_body(self):
        # SECRET HYGIENE: the /api/status body carries config.protectDownloadsWith (the attachment
        # password). It MUST NEVER appear anywhere in the IdentityEvidence.
        reader = _reader(_both_ok_transport())
        ev = reader.read_identity()
        dumped = repr(ev)
        assert ATTACHMENT_PASSWORD not in dumped
        assert "protectDownloadsWith" not in dumped
        # the evidence carries ONLY the extracted fields, never a raw body / dict.
        assert ev.observed_version == CERTIFIED_THEHIVE_VERSION

    def test_probes_only_status_and_user_current_never_system(self):
        # /api/system is a CANDIDATE only and DOES NOT exist in 4.1.24-1 -> NEVER probed.
        transport = _both_ok_transport()
        _reader(transport).read_identity()
        assert set(transport.paths) == {"/api/status", "/api/user/current"}
        assert "/api/system" not in transport.paths

    def test_one_probe_per_endpoint_no_retry(self):
        transport = _both_ok_transport()
        _reader(transport).read_identity()
        assert transport.call_count == 2  # exactly ONE GET per endpoint — no retry / poll.
        assert transport.paths.count("/api/status") == 1
        assert transport.paths.count("/api/user/current") == 1

    def test_status_probe_failure_yields_unavailable_version(self):
        transport = IdentityStubTransport(routes={
            "/api/status": _http_error(500, "/api/status"),
            "/api/user/current": (200, _user_body()),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None
        assert ev.version_probe == IDENTITY_PROBE_UNAVAILABLE
        # the org probe still succeeded independently.
        assert ev.observed_reader_organisation == READER_ORG

    def test_user_current_401_yields_unavailable_organisation(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, _status_body()),
            "/api/user/current": _http_error(401, "/api/user/current"),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_reader_organisation is None
        assert ev.observed_reader_roles == ()
        assert ev.organisation_probe == IDENTITY_PROBE_UNAVAILABLE
        # the version probe still succeeded independently.
        assert ev.observed_version == CERTIFIED_THEHIVE_VERSION

    def test_absent_versions_field_is_unavailable(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, _status_body(include_versions=False)),
            "/api/user/current": (200, _user_body()),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None
        assert ev.version_probe == IDENTITY_PROBE_UNAVAILABLE

    def test_absent_thehive_version_field_is_unavailable(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, {"versions": {"Scalligraph": "3.4.5", "Play": "2.8.16"}}),
            "/api/user/current": (200, _user_body()),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None

    def test_absent_organisation_field_is_unavailable(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, _status_body()),
            "/api/user/current": (200, _user_body(include_org=False)),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_reader_organisation is None
        assert ev.organisation_probe == IDENTITY_PROBE_UNAVAILABLE

    def test_non_json_status_body_is_unavailable(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, b"not-json"),
            "/api/user/current": (200, _user_body()),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None
        assert ev.version_probe == IDENTITY_PROBE_UNAVAILABLE

    def test_non_object_json_body_is_unavailable(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, b'["a","list","not","an","object"]'),
            "/api/user/current": (200, _user_body()),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None

    def test_timeout_is_insufficient_evidence_not_a_raise(self):
        transport = IdentityStubTransport(routes={
            "/api/status": TimeoutError("timed out"),
            "/api/user/current": (200, _user_body()),
        })
        # a probe failure NEVER raises out of read_identity — it is insufficient evidence.
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None
        assert ev.version_probe == IDENTITY_PROBE_UNAVAILABLE

    def test_connection_failure_is_insufficient_evidence_not_a_raise(self):
        transport = IdentityStubTransport(routes={
            "/api/status": urllib.error.URLError("connection refused"),
            "/api/user/current": urllib.error.URLError("connection refused"),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_version is None
        assert ev.observed_reader_organisation is None
        assert ev.version_probe == IDENTITY_PROBE_UNAVAILABLE
        assert ev.organisation_probe == IDENTITY_PROBE_UNAVAILABLE

    def test_both_probes_down_yields_fully_unavailable_evidence(self):
        transport = IdentityStubTransport(routes={})  # every path -> 404
        ev = _reader(transport).read_identity()
        result = assess_identity_evidence(ev, certified_version=CERTIFIED_THEHIVE_VERSION)
        assert result.version_matches_certified is False
        assert result.reader_organisation_known is False
        assert result.reason == IDENTITY_REASON_VERSION_UNOBSERVED
        assert result.gate5_tenant_binding is None

    def test_roles_are_sorted_and_non_strings_filtered(self):
        transport = IdentityStubTransport(routes={
            "/api/status": (200, _status_body()),
            "/api/user/current": (200, _user_body(roles=["zebra", "alpha", 42, None, "manageCase"])),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_reader_roles == ("alpha", "manageCase", "zebra")

    def test_absent_roles_yields_empty_tuple(self):
        body = _user_body()
        del body["roles"]
        transport = IdentityStubTransport(routes={
            "/api/status": (200, _status_body()),
            "/api/user/current": (200, body),
        })
        ev = _reader(transport).read_identity()
        assert ev.observed_reader_roles == ()
        # an org is still observed even without roles.
        assert ev.observed_reader_organisation == READER_ORG

    def test_end_to_end_full_probe_still_never_unlocks_gate5(self):
        # the honest M4-B conclusion: a REAL certified-version + reader-org observation STILL
        # yields gate-5 bindings None (the case-owned tenant is unobservable in 4.1.24-1).
        ev = _reader(_both_ok_transport()).read_identity()
        result = assess_identity_evidence(ev, certified_version=CERTIFIED_THEHIVE_VERSION)
        assert result.version_matches_certified is True
        assert result.reader_organisation_known is True
        assert result.gate5_instance_binding is None
        assert result.gate5_tenant_binding is None
        assert result.reason == IDENTITY_REASON_CASE_OWNER_UNOBSERVABLE


# ===========================================================================
# 3. isolation — read_identity is a READ verb; no secret leaks
# ===========================================================================
class TestReadIdentityIsolation:
    def test_read_identity_is_a_read_verb_no_write_verbs_exist(self):
        reader = _reader(IdentityStubTransport(routes={}))
        assert hasattr(reader, "read_identity")
        assert hasattr(reader, "read")           # the frozen public verb is untouched
        assert hasattr(reader, "read_creation")  # the M3 internal verb is untouched
        for forbidden in FORBIDDEN_WRITE_VERBS:
            assert not hasattr(reader, forbidden), forbidden

    def test_read_identity_name_is_read_prefixed(self):
        # it is structurally a READ (the name begins with "read"), never a mutation verb.
        assert "read_identity".startswith("read")

    def test_error_body_secret_never_surfaces_in_evidence(self):
        transport = IdentityStubTransport(routes={
            "/api/status": _http_error(500, "/api/status",
                                       body=b'{"x":"AKIAIOSFODNN7EXAMPLE"}'),
            "/api/user/current": _http_error(403, "/api/user/current",
                                             body=b'{"y":"SUPER_SECRET_BODY"}'),
        })
        ev = _reader(transport).read_identity()
        dumped = repr(ev)
        assert "AKIAIOSFODNN7EXAMPLE" not in dumped
        assert "SUPER_SECRET_BODY" not in dumped
        assert LAB_API_KEY not in dumped

    def test_api_key_never_surfaces_in_evidence(self):
        ev = _reader(_both_ok_transport()).read_identity()
        assert LAB_API_KEY not in repr(ev)

    def test_base_url_is_not_reported_as_an_observed_identity(self):
        # the observed version / org come from the probe bodies, NEVER from the base URL string.
        ev = _reader(_both_ok_transport()).read_identity()
        assert ev.observed_version != LAB_BASE_URL
        assert ev.observed_reader_organisation != LAB_BASE_URL
        assert LAB_BASE_URL not in (ev.observed_version or "")
