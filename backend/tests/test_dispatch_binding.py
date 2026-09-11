"""E: dedicated UNIT coverage for the A forward dispatch binding primitives.

WHY THIS FILE EXISTS. ``executions/binding.py`` is the immutable pre-dispatch target
record. Before E its primitives were exercised only
INDIRECTLY — ``test_verified_creation_proof.py`` builds a binding detail to drive the
proof derivation, and ``test_execution_cross_layer_regression.py`` asserts the binding
rides the ``dispatched`` row on the SUCCESS journey. Neither unit-tests the primitives
themselves. This file closes that gap at the COMPONENT layer:

- ``build_dispatch_binding`` records EVERY server-side platform fact, mints a FRESH
``attempt_id``, and stores the dispatch START as an ISO server-clock detail fact;
- the contributor merge is an EXPLICIT WHITELIST — a malicious adapter contributor can
NEVER override a platform fact (execution_id / attempt_id / schema / ...) and can
NEVER smuggle an arbitrary key (a secret, a ``verified`` flag, a raw_response) into
the binding;
- ``to_detail`` projects to PURE JSON scalars over a CLOSED 14-key set;
- ``parse_dispatch_binding`` is FAIL-CLOSED on the whole matrix — absent / non-dict /
no binding key (OLD HISTORY) / unknown schema / missing-or-blank-or-non-string on
ANY of the seven platform-identity facts ALL yield ``None``, and it NEVER raises;
- ``started_at`` round-trips an aware UTC instant and returns ``None`` (never a
substituted server time) on a malformed stored string;
- ``DispatchBindingContributor`` is ``runtime_checkable`` on PRESENCE only — the real
offline ``MockExecutor`` is NOT a contributor (its binding carries platform facts
alone), and the protocol never vouches for trust (the call chain does).

These are pure component tests: no DB, no HTTP, no external system, zero outbound.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from app.services.executions.binding import (
    BINDING_DETAIL_KEY,
    BINDING_SCHEMA,
    TERMINAL_REFERENCE_KEY,
    VERSION_ASSERTION_CONFIG,
    DispatchBinding,
    DispatchBindingContributor,
    build_dispatch_binding,
    parse_dispatch_binding,
)
from app.services.executions.mock import MockExecutor
from app.services.executions.models import ExecutionDispatch

#
# Fixed identities / instants (deterministic, no wall-clock dependence)
#
EXECUTION_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
APPROVAL_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
ATTEMPT_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

ACTION = "escalate_to_incident"
TARGET = "case"
ADAPTER = "thehive"
LAB_BASE_URL = "https://thehive.lab.local"

# The CLOSED key set ``to_detail`` may emit — the whitelist boundary. A binding
# detail carrying ANY key outside this set is smuggling.
DETAIL_KEYS = {
    "schema",
    "execution_id",
    "approval_id",
    "adapter",
    "action",
    "target",
    "attempt_id",
    "dispatch_started_at",
    "approval_status_at_dispatch",
    "endpoint",
    "version_evidence_ref",
    "version_assertion_kind",
    "target_instance",
    "target_tenant",
}

# The seven platform-identity facts ``parse_dispatch_binding`` REQUIRES present,
# non-empty strings — missing/blank/non-string on ANY one fails the whole read closed.
REQUIRED_FACTS = (
    "execution_id",
    "approval_id",
    "adapter",
    "action",
    "target",
    "attempt_id",
    "dispatch_started_at",
)


#
# Helpers
#
def _build(**overrides) -> DispatchBinding:
    """Build a binding from SERVER-SIDE facts with optional overrides."""
    kwargs = dict(
        execution_id=EXECUTION_ID,
        approval_id=APPROVAL_ID,
        adapter=ADAPTER,
        action=ACTION,
        target=TARGET,
        approval_status="approved",
        dispatch_started_at=NOW,
    )
    kwargs.update(overrides)
    return build_dispatch_binding(**kwargs)


def _detail(**overrides) -> dict:
    """A VALID binding detail dict (the shape ``build().to_detail()`` emits) with
optional field overrides, for the parse fail-closed matrix."""
    base = {
        "schema": BINDING_SCHEMA,
        "execution_id": str(EXECUTION_ID),
        "approval_id": str(APPROVAL_ID),
        "adapter": ADAPTER,
        "action": ACTION,
        "target": TARGET,
        "attempt_id": str(ATTEMPT_ID),
        "dispatch_started_at": NOW.isoformat(),
        "approval_status_at_dispatch": "approved",
        "endpoint": LAB_BASE_URL,
        "version_evidence_ref": None,
        "version_assertion_kind": VERSION_ASSERTION_CONFIG,
        "target_instance": None,
        "target_tenant": None,
    }
    base.update(overrides)
    return base


def _binding_obj(**overrides) -> DispatchBinding:
    """Construct a ``DispatchBinding`` DIRECTLY (frozen+slots) — used to probe
``started_at`` against a malformed stored ISO string that ``build`` would never
itself produce."""
    fields = dict(
        schema=BINDING_SCHEMA,
        execution_id=str(EXECUTION_ID),
        approval_id=str(APPROVAL_ID),
        adapter=ADAPTER,
        action=ACTION,
        target=TARGET,
        attempt_id=str(ATTEMPT_ID),
        dispatch_started_at=NOW.isoformat(),
        approval_status_at_dispatch="approved",
        endpoint=LAB_BASE_URL,
        version_evidence_ref=None,
        version_assertion_kind=VERSION_ASSERTION_CONFIG,
        target_instance=None,
        target_tenant=None,
    )
    fields.update(overrides)
    return DispatchBinding(**fields)


class _TheHiveLikeContributor:
    """A HONEST contributor: returns ONLY the five whitelisted identity keys, with
TheHive 4.1.24-1's truthful UNKNOWN instance/tenant (no authoritative source)."""

    name = "thehive"

    def dispatch_binding_facts(self, dispatch: ExecutionDispatch) -> dict:
        return {
            "endpoint": LAB_BASE_URL,
            "version_evidence_ref": None,
            "version_assertion_kind": VERSION_ASSERTION_CONFIG,
            "target_instance": None,
            "target_tenant": None,
        }


class _MaliciousContributor:
    """A ROGUE contributor: tries to override platform facts AND smuggle arbitrary
keys (a secret, a client-controlled ``verified`` flag, a raw_response). The
whitelist must neutralise ALL of it."""

    name = "thehive"

    def dispatch_binding_facts(self, dispatch: ExecutionDispatch) -> dict:
        return {
            # platform-fact override attempts (must be IGNORED)
            "schema": "attacker.schema",
            "execution_id": str(uuid.uuid4()),
            "approval_id": str(uuid.uuid4()),
            "adapter": "attacker",
            "action": "delete_everything",
            "target": "attacker-target",
            "attempt_id": str(uuid.uuid4()),
            "dispatch_started_at": "1999-01-01T00:00:00+00:00",
            "approval_status_at_dispatch": "approved-by-attacker",
            # arbitrary-key smuggling attempts (must be DROPPED)
            "api_key": "SUPER_SECRET_DO_NOT_LEAK",
            "authorization": "Bearer LEAKED_TOKEN",
            "password": "hunter2",
            "verified": True,
            "source": "client-controlled",
            "raw_response": {"createdAt": 0},
            # the ONE legitimate whitelisted key
            "endpoint": LAB_BASE_URL,
        }


def _dispatch() -> ExecutionDispatch:
    return ExecutionDispatch(
        execution_id=EXECUTION_ID, action=ACTION, target=TARGET, approval_id=APPROVAL_ID
    )


# ===========================================================================
# 1. build_dispatch_binding — the server-side platform facts
# ===========================================================================
class TestBuildDispatchBinding:
    def test_records_every_platform_fact(self):
        binding = _build()
        assert binding.schema == BINDING_SCHEMA
        assert binding.execution_id == str(EXECUTION_ID)
        assert binding.approval_id == str(APPROVAL_ID)
        assert binding.adapter == ADAPTER
        assert binding.action == ACTION
        assert binding.target == TARGET
        assert binding.approval_status_at_dispatch == "approved"
        assert binding.dispatch_started_at == NOW.isoformat()

    def test_attempt_id_is_a_fresh_valid_uuid4_each_build(self):
        first, second = _build(), _build()
        # a unique identifier of THIS attempt — never reused across attempts
        assert first.attempt_id != second.attempt_id
        for binding in (first, second):
            parsed = uuid.UUID(binding.attempt_id)
            assert parsed.version == 4

    def test_dispatch_started_at_is_the_caller_server_clock_iso(self):
        binding = _build(dispatch_started_at=NOW)
        assert binding.dispatch_started_at == NOW.isoformat()
        # the accessor round-trips to the SAME aware instant
        assert binding.started_at() == NOW

    @pytest.mark.parametrize("bad_status", [None, 42, "", ['approved'], object()])
    def test_non_string_approval_status_becomes_none(self, bad_status):
        # the dispatch-time approval snapshot is an honest UNKNOWN, never coerced
        assert _build(approval_status=bad_status).approval_status_at_dispatch is None

    def test_non_contributor_binding_has_honest_none_identity(self):
        # the OFFLINE MOCK shape: platform facts alone, NO fabricated instance/tenant
        binding = _build(contributor_facts=None)
        assert binding.endpoint is None
        assert binding.version_evidence_ref is None
        assert binding.version_assertion_kind is None
        assert binding.target_instance is None
        assert binding.target_tenant is None


# ===========================================================================
# 2. the contributor whitelist — no override, no smuggling
# ===========================================================================
class TestContributorWhitelist:
    def test_honest_contributor_identity_keys_are_merged(self):
        binding = _build(
            contributor_facts=_TheHiveLikeContributor().dispatch_binding_facts(_dispatch())
        )
        assert binding.endpoint == LAB_BASE_URL
        assert binding.version_assertion_kind == VERSION_ASSERTION_CONFIG
        # TheHive 4.1.24-1: an HONEST UNKNOWN, never a base-URL substitute
        assert binding.target_instance is None
        assert binding.target_tenant is None

    def test_malicious_contributor_cannot_override_any_platform_fact(self):
        binding = _build(
            contributor_facts=_MaliciousContributor().dispatch_binding_facts(_dispatch())
        )
        # every platform fact is the SERVER-SIDE value, untouched by the contributor
        assert binding.schema == BINDING_SCHEMA
        assert binding.execution_id == str(EXECUTION_ID)
        assert binding.approval_id == str(APPROVAL_ID)
        assert binding.adapter == ADAPTER
        assert binding.action == ACTION
        assert binding.target == TARGET
        assert binding.approval_status_at_dispatch == "approved"
        assert binding.dispatch_started_at == NOW.isoformat()
        # attempt_id is STILL a freshly minted uuid4, never the attacker's
        assert uuid.UUID(binding.attempt_id).version == 4

    def test_malicious_contributor_cannot_smuggle_arbitrary_keys(self):
        binding = _build(
            contributor_facts=_MaliciousContributor().dispatch_binding_facts(_dispatch())
        )
        detail = binding.to_detail()
        # the key set is CLOSED — exactly the 14 declared fields, nothing smuggled
        assert set(detail.keys()) == DETAIL_KEYS
        for smuggled in ("api_key", "authorization", "password", "verified",
                         "source", "raw_response"):
            assert smuggled not in detail

    def test_smuggled_secret_never_appears_in_the_serialised_binding(self):
        binding = _build(
            contributor_facts=_MaliciousContributor().dispatch_binding_facts(_dispatch())
        )
        serialised = json.dumps(binding.to_detail())
        for secret in ("SUPER_SECRET_DO_NOT_LEAK", "LEAKED_TOKEN", "hunter2"):
            assert secret not in serialised

    @pytest.mark.parametrize("bad", [None, "", 42, True, ["x"], {"k": "v"}])
    def test_blank_or_non_string_identity_becomes_none(self, bad):
        # the _optional_str gate: an absent/blank/non-string adapter fact is an
        # honest UNKNOWN, never coerced into a fabricated identity
        binding = _build(contributor_facts={
            "endpoint": bad, "version_evidence_ref": bad,
            "version_assertion_kind": bad, "target_instance": bad, "target_tenant": bad,
        })
        assert binding.endpoint is None
        assert binding.version_evidence_ref is None
        assert binding.version_assertion_kind is None
        assert binding.target_instance is None
        assert binding.target_tenant is None


# ===========================================================================
# 3. to_detail — pure JSON scalars over a closed key set
# ===========================================================================
class TestToDetail:
    def test_emits_pure_json_scalars(self):
        detail = _build().to_detail()
        assert set(detail.keys()) == DETAIL_KEYS
        for value in detail.values():
            assert value is None or isinstance(value, str)
        # json round-trips with no type error (a detail must be JSON-storable)
        assert json.loads(json.dumps(detail)) == detail

    def test_round_trips_through_parse(self):
        original = _build(
            contributor_facts=_TheHiveLikeContributor().dispatch_binding_facts(_dispatch())
        )
        parsed = parse_dispatch_binding({BINDING_DETAIL_KEY: original.to_detail()})
        assert isinstance(parsed, DispatchBinding)
        assert parsed.to_detail() == original.to_detail()


# ===========================================================================
# 4. parse_dispatch_binding — the FAIL-CLOSED reader
# ===========================================================================
class TestParseFailClosed:
    @pytest.mark.parametrize("garbage", [None, "x", 42, True, [], (), object(), 3.5])
    def test_absent_or_non_dict_detail_returns_none(self, garbage):
        assert parse_dispatch_binding(garbage) is None

    def test_detail_without_binding_key_returns_none(self):
        # the OLD-HISTORY shape: a dispatched row that predates A has NO binding
        assert parse_dispatch_binding({"executor": "thehive"}) is None
        assert parse_dispatch_binding({}) is None

    @pytest.mark.parametrize("bad_binding", [None, "x", 42, [], True])
    def test_non_dict_binding_returns_none(self, bad_binding):
        assert parse_dispatch_binding({BINDING_DETAIL_KEY: bad_binding}) is None

    @pytest.mark.parametrize("bad_schema",
                             [None, "", "bogus", "sentinelflow.dispatch_binding.v2",
                              "SENTINELFLOW.DISPATCH_BINDING.V1", 42])
    def test_unknown_schema_returns_none(self, bad_schema):
        # a forward parser refuses an UNKNOWN shape rather than mis-reading it
        assert parse_dispatch_binding(
            {BINDING_DETAIL_KEY: _detail(schema=bad_schema)}
        ) is None

    @pytest.mark.parametrize("field", REQUIRED_FACTS)
    def test_missing_any_platform_identity_fact_returns_none(self, field):
        detail = _detail()
        del detail[field]
        assert parse_dispatch_binding({BINDING_DETAIL_KEY: detail}) is None

    @pytest.mark.parametrize("field", REQUIRED_FACTS)
    @pytest.mark.parametrize("bad", [None, "", 42, True, ["x"]])
    def test_blank_or_non_string_platform_fact_returns_none(self, field, bad):
        # a binding missing/corrupt on ANY required fact is NEVER partially trusted
        assert parse_dispatch_binding(
            {BINDING_DETAIL_KEY: _detail(**{field: bad})}
        ) is None

    def test_never_raises_on_garbage(self):
        for garbage in (None, {}, {"dispatch_binding": None},
                        {BINDING_DETAIL_KEY: {"schema": BINDING_SCHEMA}},
                        {BINDING_DETAIL_KEY: _detail(dispatch_started_at="not-a-date")}):
            # parse is total: it returns None or a binding, it never raises
            parse_dispatch_binding(garbage)

    def test_preserves_optional_identity_when_present(self):
        detail = _detail(
            endpoint=LAB_BASE_URL,
            version_evidence_ref="config:EXPECTED_VERSION",
            version_assertion_kind=VERSION_ASSERTION_CONFIG,
            target_instance="instance-7",
            target_tenant="organisation-1",
        )
        parsed = parse_dispatch_binding({BINDING_DETAIL_KEY: detail})
        assert parsed is not None
        assert parsed.endpoint == LAB_BASE_URL
        assert parsed.version_evidence_ref == "config:EXPECTED_VERSION"
        assert parsed.version_assertion_kind == VERSION_ASSERTION_CONFIG
        assert parsed.target_instance == "instance-7"
        assert parsed.target_tenant == "organisation-1"

    @pytest.mark.parametrize("bad", [None, "", 42, ["x"]])
    def test_coerces_blank_optional_identity_to_none(self, bad):
        parsed = parse_dispatch_binding({BINDING_DETAIL_KEY: _detail(
            endpoint=bad, target_instance=bad, target_tenant=bad,
            version_evidence_ref=bad, version_assertion_kind=bad,
        )})
        assert parsed is not None  # required facts intact -> binding still valid
        assert parsed.endpoint is None
        assert parsed.target_instance is None
        assert parsed.target_tenant is None
        assert parsed.version_evidence_ref is None
        assert parsed.version_assertion_kind is None


# ===========================================================================
# 5. started_at — fail-closed time accessor (never substitutes a server time)
# ===========================================================================
class TestStartedAt:
    def test_aware_utc_round_trip(self):
        assert _binding_obj(dispatch_started_at=NOW.isoformat()).started_at() == NOW

    def test_naive_iso_is_assumed_utc(self):
        naive = datetime(2026, 9, 9, 12, 0, 0)  # no tzinfo
        parsed = _binding_obj(dispatch_started_at=naive.isoformat()).started_at()
        assert parsed is not None
        assert parsed.tzinfo is not None
        assert parsed == NOW

    @pytest.mark.parametrize("bad", ["not-a-date", "", "2026-13-45T99:99:99", "12345"])
    def test_malformed_stored_string_returns_none(self, bad):
        # the derivation NEVER substitutes a server time for the historical dispatch
        # start (constraint #2) — a malformed stamp is an honest UNKNOWN
        assert _binding_obj(dispatch_started_at=bad).started_at() is None


# ===========================================================================
# 6. DispatchBindingContributor — runtime_checkable on PRESENCE only
# ===========================================================================
class TestContributorProtocol:
    def test_protocol_is_runtime_checkable_positive(self):
        assert isinstance(_TheHiveLikeContributor(), DispatchBindingContributor)

    def test_real_offline_mock_is_not_a_contributor(self):
        # the production offline mock makes NO external request -> it must NOT
        # contribute adapter identity; its binding carries platform facts alone
        assert not isinstance(MockExecutor(), DispatchBindingContributor)

    def test_plain_object_is_not_a_contributor(self):
        assert not isinstance(object(), DispatchBindingContributor)

    def test_presence_not_signature_is_what_isinstance_checks(self):
        # the DOCUMENTED caveat: isinstance checks ONLY the presence of the method,
        # never its correctness — the trust is the controlled call chain, not the type
        class _NameOnly:
            def dispatch_binding_facts(self):  # wrong signature, still "present"
                return None

        assert isinstance(_NameOnly(), DispatchBindingContributor)

    def test_whitelist_neutralises_a_runtime_contributor_via_build(self):
        # end-to-end through the real build path with a rogue runtime contributor
        contributor = _MaliciousContributor()
        assert isinstance(contributor, DispatchBindingContributor)
        binding = _build(contributor_facts=contributor.dispatch_binding_facts(_dispatch()))
        assert set(binding.to_detail().keys()) == DETAIL_KEYS
        assert binding.adapter == ADAPTER  # never "attacker"


# ===========================================================================
# 7. terminal reference key — the link the terminal row writes
# ===========================================================================
class TestTerminalReference:
    def test_terminal_reference_key_is_distinct_from_binding_key(self):
        # the dispatched row carries the BINDING; the terminal row carries only the
        # attempt_id REFERENCE — two distinct keys, the terminal never re-writes it
        assert BINDING_DETAIL_KEY == "dispatch_binding"
        assert TERMINAL_REFERENCE_KEY == "dispatch_attempt_id"
        assert BINDING_DETAIL_KEY != TERMINAL_REFERENCE_KEY

    def test_attempt_id_survives_the_detail_round_trip(self):
        # the terminal row references binding.attempt_id; that link must survive
        # persisting the binding into the dispatched row's detail and parsing it back
        binding = _build()
        assert isinstance(binding.attempt_id, str) and binding.attempt_id
        parsed = parse_dispatch_binding({BINDING_DETAIL_KEY: binding.to_detail()})
        assert parsed is not None
        assert parsed.attempt_id == binding.attempt_id
