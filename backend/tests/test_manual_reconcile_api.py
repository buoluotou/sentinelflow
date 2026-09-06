"""3.4.5-A2-A Manual Reconcile — secured-route acceptance tests.

Locks the A2-A seam ONLY (spec §35 / §36): the route is safely established,
RBAC is enforced by REUSING ``authenticate_operator``, the empty body forbids
every smuggled field, and everything else is an honest 501 placeholder — never
a 200 ``accepted``, never a fabricated reconciliation success, never a fact,
never an execution.

Coverage map (A2-A acceptance gate):
- RBAC (§36 / §28 items 1-3): executor/admin -> endpoint (501); viewer/reviewer
  -> 403; missing/wrong/malformed/empty/unconfigured token -> 401; legacy
  EXECUTION_TOKEN still admitted (backwards compatible).
- Placeholder (§36): authorized -> 501 (NOT 200), STATIC detail, never
  ``accepted=true``, detail leaks no identity/execution_id/token.
- Request schema (§6 / §28 items 27-30): the body is EMPTY; ANY field
  (operator/source/adapter/external_reference/external_state/execution_id/
  observed_at/outcome_status/api_key/authorization/token/password) -> 422;
  auth precedes body validation (an unauthenticated caller cannot probe the
  schema).
- No side effects (§25 / §28 items 31-35 / §29 zero-fact): 501/403/401 write
  ZERO execution_outcome rows and ZERO execution_log rows — no read, no
  persist, no dispatch, no execution.
- Service stub (§35): ``reconcile_execution`` raises NotImplementedError and
  writes nothing.
- Structural (§28 items 40-41): the reconcile router exposes EXACTLY ONE POST
  route — no accidental extra capability.
- A2-A scope (§35): execution_id is an opaque path string (no correlation / no
  UUID parse yet — a non-UUID still reaches the 501 stub).

No external read, no ReadAdapterRegistry access, no correlation, no mapping, no
persistence, no execution — those land in A2-B..E. No change to any sealed layer.
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
from app.services.outcomes.manual_reconcile import reconcile_execution

#: The reconcile path template (execution_id is a PATH param). A2-A does NOT
#: parse/correlate it, so any string reaches the stub.
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: A well-formed but NON-EXISTENT execution id. A2-A never correlates, so the
#: chain need not exist — the request still reaches the 501 stub.
EXECUTION_ID = "22222222-2222-2222-2222-222222222222"

#: Fields a client must NEVER be able to smuggle into the empty body (§6/§7/§8).
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


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def operators(monkeypatch):
    """Four operators, one per role, via OPERATORS_JSON (the 3.3.1 harness).

    The conftest autouse fixture resets the module-level registry around every
    test, so the monkeypatched config always takes effect on the next
    ``get_operator_registry()`` (which the route triggers lazily)."""
    monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
        {"token": "tok-exec", "name": "exec-op", "role": "executor"},
        {"token": "tok-admin", "name": "admin-op", "role": "admin"},
        {"token": "tok-viewer", "name": "view-op", "role": "viewer"},
        {"token": "tok-reviewer", "name": "rev-op", "role": "reviewer"},
    ]))


# --------------------------------------------------------------------------
# RBAC (§36 / §28 items 1-3) — reuse authenticate_operator, never a new stack
# --------------------------------------------------------------------------
class TestOperatorRBAC:
    def test_executor_reaches_endpoint_501(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501

    def test_admin_reaches_endpoint_501(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-admin"))
        assert r.status_code == 501

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

    def test_legacy_execution_token_admitted_501(self, client, monkeypatch):
        # Legacy EXECUTION_TOKEN fallback -> synthetic executor -> endpoint.
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        r = client.post(_url(), json={}, headers=_auth("legacy-tok"))
        assert r.status_code == 501


# --------------------------------------------------------------------------
# Placeholder semantics (§36) — honest 501, never a fabricated success
# --------------------------------------------------------------------------
class TestPlaceholderSemantics:
    def test_authorized_is_501_not_200(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501
        assert r.status_code != 200

    def test_501_detail_is_static(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.json()["detail"] == "manual reconcile not yet implemented"

    def test_never_accepted_true(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        body = r.json()
        # A2-A must NOT return a fake success envelope (§36).
        assert body.get("accepted") is not True
        assert "outcome_status" not in body

    def test_detail_leaks_no_identity(self, client, operators):
        detail = client.post(
            _url(), json={}, headers=_auth("tok-exec")
        ).json()["detail"]
        assert EXECUTION_ID not in detail
        assert "exec-op" not in detail
        assert "tok-exec" not in detail


# --------------------------------------------------------------------------
# Request schema (§6 / §28 items 27-30) — empty body forbids every smuggle
# --------------------------------------------------------------------------
class TestRequestBodyForbidden:
    @pytest.mark.parametrize("field", SMUGGLED_FIELDS)
    def test_smuggled_field_rejected_422(self, client, operators, field):
        r = client.post(_url(), json={field: "x"}, headers=_auth("tok-exec"))
        assert r.status_code == 422

    def test_empty_body_passes_schema_gate(self, client, operators):
        # {} clears the schema (then 501 at the stub) — NOT a 422.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501

    def test_unauth_with_smuggled_body_is_401_not_422(self, client, operators):
        # The auth dependency runs BEFORE body validation: an unauthenticated
        # caller cannot even probe the schema (defense in depth, mirrors the
        # sealed webhook Gate-1-first behaviour).
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
        # The request body is structurally EMPTY — execution_id is path-only.
        assert set(ManualReconcileRequest.model_fields) == set()

    def test_schema_model_accepts_empty(self):
        ManualReconcileRequest.model_validate({})


# --------------------------------------------------------------------------
# No side effects (§25 / §28 items 31-35 / §29 zero-fact)
# --------------------------------------------------------------------------
class TestNoSideEffects:
    def test_501_writes_no_outcome_fact(self, client, db_session, operators):
        client.post(_url(), json={}, headers=_auth("tok-exec"))
        rows = db_session.execute(select(ExecutionOutcome)).scalars().all()
        assert rows == []

    def test_501_writes_no_execution_log(self, client, db_session, operators):
        # Manual Reconcile must NEVER dispatch / execute (§25).
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


# --------------------------------------------------------------------------
# Service stub (§35) — minimal entrypoint, always raises, writes nothing
# --------------------------------------------------------------------------
class TestServiceStub:
    def test_reconcile_execution_raises_not_implemented(self, db_session):
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, EXECUTION_ID, "exec-op")

    def test_stub_writes_no_outcome_fact(self, db_session):
        with pytest.raises(NotImplementedError):
            reconcile_execution(db_session, EXECUTION_ID, "exec-op")
        assert db_session.execute(select(ExecutionOutcome)).scalars().all() == []


# --------------------------------------------------------------------------
# Structural (§28 items 40-41) — exactly one POST route, no extra capability
# --------------------------------------------------------------------------
class TestRouteStructure:
    def test_reconcile_router_exposes_one_post_route(self):
        from app.api.v1 import reconcile as reconcile_module
        paths = {
            (r.path, tuple(sorted(r.methods)))
            for r in reconcile_module.router.routes
        }
        assert paths == {("/executions/{execution_id}/reconcile", ("POST",))}

    def test_route_is_registered_on_the_app(self, client, operators):
        # A wrong method on the exact path proves the path EXISTS (405, not 404)
        # and that A2-A did not open any GET read surface.
        r = client.get(_url(), headers=_auth("tok-exec"))
        assert r.status_code == 405


# --------------------------------------------------------------------------
# A2-A scope (§35) — no correlation / no UUID parse yet
# --------------------------------------------------------------------------
class TestA2AScope:
    def test_execution_id_is_opaque_no_correlation(self, client, operators):
        # A non-UUID path STILL reaches the stub (501), proving A2-A does no
        # correlation and no UUID validation (those land in A2-B -> 404).
        r = client.post(_url(eid="not-a-uuid"), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501

    def test_nonexistent_execution_still_501(self, client, operators):
        # A2-A does not require the chain to exist (no correlation yet).
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 501


# --------------------------------------------------------------------------
# Response envelope (§35 deliverable / §4.4) — defined, documented, not returned
# --------------------------------------------------------------------------
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
