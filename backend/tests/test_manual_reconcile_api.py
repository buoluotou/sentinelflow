"""Manual Reconcile — secured-route acceptance tests.

Locks the route contract that needs no seeded chain: RBAC, the empty request body,
and the status codes the route resolves to. The route parses and correlates the
path execution_id, extracts the external reference read-only, and hands that
context to the ``ReadAdapterRegistry``. An execution_id that maps to no chain (or
is malformed) is a uniform 404, a chain with no reconcilable handle is a 422, and
a correlated, reference-bearing chain rejects at the empty production registry
with ``UnsupportedAdapterRead`` -> 404, because no reader exists for any adapter
yet. A 501 is reachable only under a test-injected ``FakeReadAdapter``
(``test_manual_reconcile_reader.py``). The 404/422/501 paths that require a seeded
chain, and the correlation/extraction core, live in
``test_manual_reconcile_correlation.py`` and ``test_manual_reconcile_reader.py``;
this file stays seeding-free and proves the invariants that hold regardless of
history:

- RBAC: executor/admin are admitted past auth (a 404 on an unseeded id — never
401/403); viewer/reviewer -> 403; missing/wrong/malformed/empty/unconfigured
token -> 401; legacy EXECUTION_TOKEN still admitted.
- Rejection: an authorized operator on an unseeded id gets a static 404, never a
200 ``accepted`` and never a fabricated reconciliation success; the detail leaks
no identity / execution_id / token.
- Request schema: the body is empty; any field
(operator/source/adapter/external_reference/external_state/execution_id/
observed_at/outcome_status/api_key/authorization/token/password) -> 422.
Auth precedes body validation, so an unauthenticated caller cannot probe the
schema, and a client can never smuggle the adapter or the reference the
pipeline extracts from history.
- No side effects: 404/403/401 write zero execution_outcome rows and zero
execution_log rows — no read, no persist, no dispatch, no execution.
- Service gate: ``reconcile_execution(session, uuid, operator)`` correlates first
— an unseeded UUID raises ``UnmappableExecutionId`` and writes nothing.
- Structural: the reconcile router exposes exactly one POST route — no accidental
extra capability.
- Path parsing: execution_id is parsed and correlated, so a non-UUID and a
nonexistent chain both yield the same uniform 404.

Routing, extraction and registry lookup decide the status code; the RBAC and
schema invariants below are independent of them. No real external read (the
production registry is empty), no mapping, no persistence, no execution.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.core.config import settings
from app.models.execution_log import ExecutionLog
from app.models.execution_outcome import ExecutionOutcome
from app.schemas.reconcile import (
    MANUAL_RECONCILE_SOURCE,
    ManualReconcileRequest,
    ManualReconcileResponse,
)
from app.services.outcomes.correlation import UnmappableExecutionId
from app.services.outcomes.manual_reconcile import reconcile_execution

# The reconcile path template (execution_id is a path param).
RECONCILE = "/api/v1/executions/{eid}/reconcile"

# A well-formed but non-existent execution id. Correlation maps an unseeded id to
# no chain -> the uniform 404, never the registry's 404 UnsupportedAdapterRead,
# which needs a seeded reference-bearing chain — see
# test_manual_reconcile_correlation.py / test_manual_reconcile_reader.py.
EXECUTION_ID = "22222222-2222-2222-2222-222222222222"

# Fields a client must never be able to smuggle into the empty body.
SMUGGLED_FIELDS = [
    "operator",
    "source",
    "adapter",
    "external_reference",
    "external_state",
    "execution_id",
    "observed_at",
    "outcome_status",
    "api_key",
    "authorization",
    "token",
    "password",
]


def _url(eid: str = EXECUTION_ID) -> str:
    return RECONCILE.format(eid=eid)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


#
# Fixtures
#
@pytest.fixture()
def operators(monkeypatch):
    """Four operators, one per role, via OPERATORS_JSON.

The conftest autouse fixture resets the module-level registry around every
test, so the monkeypatched config always takes effect on the next
``get_operator_registry()`` (which the route triggers lazily)."""
    monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
        {"token": "tok-exec", "name": "exec-op", "role": "executor"},
        {"token": "tok-admin", "name": "admin-op", "role": "admin"},
        {"token": "tok-viewer", "name": "view-op", "role": "viewer"},
        {"token": "tok-reviewer", "name": "rev-op", "role": "reviewer"},
    ]))


#
# RBAC — reuse authenticate_operator, never a new stack
#
class TestOperatorRBAC:
    def test_executor_admitted_past_auth_404(self, client, operators):
        # An executor is admitted past auth + RBAC + body: on an unseeded id the
        # pipeline correlates and 404s — proving admission (a 401/403 would mean
        # the auth gate rejected it before the service ever ran).
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.status_code not in (401, 403)

    def test_admin_admitted_past_auth_404(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-admin"))
        assert r.status_code == 404
        assert r.status_code not in (401, 403)

    def test_viewer_forbidden_403(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-viewer"))
        assert r.status_code == 403

    def test_reviewer_forbidden_403(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-reviewer"))
        assert r.status_code == 403

    def test_missing_token_401(self, client, operators):
        r = client.post(_url(), json={})
        assert r.status_code == 401

    def test_wrong_token_401(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-attacker"))
        assert r.status_code == 401

    def test_malformed_scheme_401(self, client, operators):
        r = client.post(_url(), json={}, headers={"Authorization": "Token tok-exec"})
        assert r.status_code == 401

    def test_empty_bearer_401(self, client, operators):
        r = client.post(_url(), json={}, headers={"Authorization": "Bearer "})
        assert r.status_code == 401

    def test_nothing_configured_401(self, client, monkeypatch):
        # No OPERATORS_JSON and no legacy EXECUTION_TOKEN -> fully closed.
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "")
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 401

    def test_legacy_execution_token_admitted_404(self, client, monkeypatch):
        # Legacy EXECUTION_TOKEN fallback -> synthetic executor -> admitted past
        # auth (a 404 on the unseeded id, never 401/403).
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        r = client.post(_url(), json={}, headers=_auth("legacy-tok"))
        assert r.status_code == 404
        assert r.status_code not in (401, 403)


#
# Rejection — never a fabricated success, seeding-free
#
class TestHonestRejection:
    def test_authorized_unseeded_is_404_not_200(self, client, operators):
        # An authorized operator on an unseeded id is never answered with a fake
        # 200 accepted; correlation rejects it. The seeded-chain outcomes (404
        # UnsupportedAdapterRead, and the 501 under a test-injected fake reader)
        # are proven in the correlation / reader suites.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.status_code != 200

    def test_404_detail_is_static(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.json()["detail"] == "execution correlation failed"

    def test_never_accepted_true(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        body = r.json()
        # The route must not return a fake success envelope.
        assert body.get("accepted") is not True
        assert "outcome_status" not in body

    def test_detail_leaks_no_identity(self, client, operators):
        detail = client.post(
            _url(), json={}, headers=_auth("tok-exec")
        ).json()["detail"]
        assert EXECUTION_ID not in detail
        assert "exec-op" not in detail
        assert "tok-exec" not in detail


#
# Request schema — empty body forbids every smuggle
#
class TestRequestBodyForbidden:
    @pytest.mark.parametrize("field", SMUGGLED_FIELDS)
    def test_smuggled_field_rejected_422(self, client, operators, field):
        r = client.post(_url(), json={field: "x"}, headers=_auth("tok-exec"))
        assert r.status_code == 422

    def test_empty_body_passes_schema_gate(self, client, operators):
        # {} clears the schema gate — not a 422. On the unseeded id it then 404s
        # at correlation; the point here is that the empty body itself is never a
        # schema rejection.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code != 422
        assert r.status_code == 404

    def test_unauth_with_smuggled_body_is_401_not_422(self, client, operators):
        # The auth dependency runs before body validation: an unauthenticated
        # caller cannot even probe the schema (defense in depth, mirroring the
        # webhook's auth-first ordering).
        r = client.post(_url(), json={"operator": "alice"})
        assert r.status_code == 401

    def test_viewer_with_smuggled_body_is_403_not_422(self, client, operators):
        r = client.post(_url(), json={"source": "webhook"}, headers=_auth("tok-viewer"))
        assert r.status_code == 403

    @pytest.mark.parametrize("field", SMUGGLED_FIELDS)
    def test_schema_model_forbids_field(self, field):
        with pytest.raises(ValidationError):
            ManualReconcileRequest.model_validate({field: "x"})

    def test_schema_model_has_no_fields(self):
        # The request body is structurally empty — execution_id is path-only.
        assert set(ManualReconcileRequest.model_fields) == set()

    def test_schema_model_accepts_empty(self):
        ManualReconcileRequest.model_validate({})


#
# No side effects
#
class TestNoSideEffects:
    def test_404_writes_no_outcome_fact(self, client, db_session, operators):
        client.post(_url(), json={}, headers=_auth("tok-exec"))
        rows = db_session.execute(select(ExecutionOutcome)).scalars().all()
        assert rows == []

    def test_404_writes_no_execution_log(self, client, db_session, operators):
        # Manual Reconcile never dispatches or executes, and correlation is
        # read-only — the unseeded 404 path creates no execution_log row.
        client.post(_url(), json={}, headers=_auth("tok-exec"))
        rows = db_session.execute(select(ExecutionLog)).scalars().all()
        assert rows == []

    def test_403_writes_nothing(self, client, db_session, operators):
        client.post(_url(), json={}, headers=_auth("tok-viewer"))
        assert db_session.execute(select(ExecutionOutcome)).scalars().all() == []
        assert db_session.execute(select(ExecutionLog)).scalars().all() == []

    def test_401_writes_nothing(self, client, db_session, operators):
        client.post(_url(), json={})
        assert db_session.execute(select(ExecutionOutcome)).scalars().all() == []
        assert db_session.execute(select(ExecutionLog)).scalars().all() == []


#
# Service gate — correlation runs first, writes nothing
#
class TestServiceGate:
    def test_unseeded_uuid_raises_unmappable(self, db_session):
        # The signature is (session, uuid.UUID, operator, registry=None) and
        # correlates first: an unseeded UUID -> UnmappableExecutionId, before the
        # registry is ever consulted. The seeded-chain outcomes
        # (UnsupportedAdapterRead at the empty registry, and the NotImplementedError
        # under a test-injected fake reader) are proven in the correlation / reader
        # suites.
        with pytest.raises(UnmappableExecutionId):
            reconcile_execution(db_session, uuid.UUID(EXECUTION_ID), "exec-op")

    def test_gate_writes_no_outcome_fact(self, db_session):
        with pytest.raises(UnmappableExecutionId):
            reconcile_execution(db_session, uuid.UUID(EXECUTION_ID), "exec-op")
        assert db_session.execute(select(ExecutionOutcome)).scalars().all() == []


#
# Structural — exactly one POST route, no extra capability
#
class TestRouteStructure:
    def test_reconcile_router_exposes_one_post_route(self):
        from app.api.v1 import reconcile as reconcile_module
        paths = {
            (r.path, tuple(sorted(r.methods)))
            for r in reconcile_module.router.routes
        }
        assert paths == {("/executions/{execution_id}/reconcile", ("POST",))}

    def test_route_is_registered_on_the_app(self, client, operators):
        # A wrong method on the exact path proves the path exists (405, not 404)
        # and that no GET read surface was opened.
        r = client.get(_url(), headers=_auth("tok-exec"))
        assert r.status_code == 405


#
# Path parsing — execution_id is parsed and correlated
#
class TestA2BScope:
    def test_non_uuid_is_404(self, client, operators):
        # The path id is parsed and correlated: a non-UUID is a correlation-input
        # failure -> the uniform 404, never the reader stub.
        r = client.post(_url(eid="not-a-uuid"), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404

    def test_nonexistent_execution_is_404(self, client, operators):
        # A well-formed id with no chain correlates to nothing -> 404.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404

    def test_non_uuid_and_nonexistent_are_indistinguishable(self, client, operators):
        # Non-discrimination: the same static detail for a malformed id and an
        # absent chain — a caller cannot tell a format failure from a nonexistent one.
        a = client.post(_url(eid="not-a-uuid"), json={}, headers=_auth("tok-exec"))
        b = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert a.status_code == b.status_code == 404
        assert a.json()["detail"] == b.json()["detail"]


#
# Response envelope — defined and documented; no route in this file returns it
#
class TestResponseSchema:
    def test_response_envelope_constructs(self):
        resp = ManualReconcileResponse(
            accepted=True,
            execution_id=uuid.uuid4(),
            adapter="wazuh",
            outcome_status="confirmed_success",
            observed_at=datetime.now(timezone.utc),
            source=MANUAL_RECONCILE_SOURCE,
            derived_outcome_status="confirmed_success",
            observed_at_kind="external",
        )
        assert resp.source == "manual_reconcile"
        assert resp.accepted is True

    def test_source_literal_is_manual_reconcile(self):
        assert MANUAL_RECONCILE_SOURCE == "manual_reconcile"
