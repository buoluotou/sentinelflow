"""3.4.5-A2 Manual Reconcile — secured-route acceptance tests (the A2-A seam as
evolved by A2-B correlation wiring).

Locks the ROUTE contract that needs NO seeded chain. A2-A established the seam
(RBAC + the empty body + an honest placeholder); A2-B wired correlation + read-only
external-reference extraction into it (spec §20 / §21), so the placeholder status
EVOLVES: an execution_id that maps to NO chain (or is malformed) is now a uniform
404, a chain with no reconcilable handle is a 422, and only a correlated,
reference-bearing chain reaches the honest 501 (no read adapter yet). The 501/422
paths that REQUIRE a seeded chain — and the whole §18 correlation/extraction core —
live in ``test_manual_reconcile_correlation.py``; this file stays seeding-free and
proves the invariants that hold regardless of history:

- RBAC (§36 / §28 items 1-3): executor/admin are admitted PAST auth (a 404 on an
  unseeded id — never 401/403); viewer/reviewer -> 403; missing/wrong/malformed/
  empty/unconfigured token -> 401; legacy EXECUTION_TOKEN still admitted.
- Honest rejection (§36 / §20): an authorized operator on an unseeded id gets a
  STATIC 404, NEVER a 200 ``accepted``, never a fabricated reconciliation success,
  and the detail leaks no identity / execution_id / token.
- Request schema (§6 / §28 items 27-30): the body is EMPTY; ANY field
  (operator/source/adapter/external_reference/external_state/execution_id/
  observed_at/outcome_status/api_key/authorization/token/password) -> 422;
  auth precedes body validation (an unauthenticated caller cannot probe the
  schema). This is the §19 boundary guard: a client can never smuggle the adapter
  or the reference the pipeline extracts from history.
- No side effects (§25 / §29 zero-fact): 404/403/401 write ZERO execution_outcome
  rows and ZERO execution_log rows — no read, no persist, no dispatch, no execution.
- Service gate (§35, evolved): ``reconcile_execution(session, uuid, operator)``
  correlates FIRST — an unseeded UUID raises ``UnmappableExecutionId`` (3.4.4-C)
  and writes nothing.
- Structural (§28 items 40-41): the reconcile router exposes EXACTLY ONE POST
  route — no accidental extra capability.
- A2-B scope (§20 / §21): execution_id is now PARSED + CORRELATED — a non-UUID and
  a nonexistent chain both yield the SAME uniform 404.

No external read, no ReadAdapterRegistry access, no mapping, no persistence, no
execution — those land in A2-C..E. The A2-A commit (4b09d18) stays byte-frozen;
this file evolves only where §20 / §21 changed the placeholder's status code.
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

#: The reconcile path template (execution_id is a PATH param). A2-A does NOT
#: parse/correlate it, so any string reaches the stub.
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: A well-formed but NON-EXISTENT execution id. A2-B CORRELATES (spec §20), so an
#: unseeded id maps to no chain -> the uniform 404 (never the 501 stub, which now
#: needs a seeded reference-bearing chain — see test_manual_reconcile_correlation.py).
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
    def test_executor_admitted_past_auth_404(self, client, operators):
        # An executor is admitted PAST auth + RBAC + body: on an unseeded id the
        # pipeline correlates and 404s (spec §20) — proving admission (a 401/403
        # would mean the auth gate rejected it before the service ever ran).
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


# --------------------------------------------------------------------------
# Honest rejection (§36 / §20) — never a fabricated success, seeding-free
# --------------------------------------------------------------------------
class TestHonestRejection:
    def test_authorized_unseeded_is_404_not_200(self, client, operators):
        # An authorized operator on an unseeded id is NEVER answered with a fake
        # 200 accepted; correlation rejects it (spec §20). The 501 placeholder (a
        # seeded reference-bearing chain) is proven in the correlation suite.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404
        assert r.status_code != 200

    def test_404_detail_is_static(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.json()["detail"] == "execution correlation failed"

    def test_never_accepted_true(self, client, operators):
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        body = r.json()
        # A2-B must NOT return a fake success envelope (§20 / §36).
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
        # {} clears the schema gate — NOT a 422. On the unseeded id it then 404s at
        # correlation (spec §20); the point here is that the EMPTY body itself is
        # never a schema rejection.
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code != 422
        assert r.status_code == 404

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
    def test_404_writes_no_outcome_fact(self, client, db_session, operators):
        client.post(_url(), json={}, headers=_auth("tok-exec"))
        rows = db_session.execute(select(ExecutionOutcome)).scalars().all()
        assert rows == []

    def test_404_writes_no_execution_log(self, client, db_session, operators):
        # Manual Reconcile must NEVER dispatch / execute (§25), and correlation is
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


# --------------------------------------------------------------------------
# Service gate (§35, evolved by A2-B) — correlation runs FIRST, writes nothing
# --------------------------------------------------------------------------
class TestServiceGate:
    def test_unseeded_uuid_raises_unmappable(self, db_session):
        # A2-B signature is (session, uuid.UUID, operator) and CORRELATES first: an
        # unseeded UUID -> UnmappableExecutionId (3.4.4-C), before any placeholder.
        # The NotImplementedError (a seeded reference-bearing chain) is proven in
        # test_manual_reconcile_correlation.py.
        with pytest.raises(UnmappableExecutionId):
            reconcile_execution(db_session, uuid.UUID(EXECUTION_ID), "exec-op")

    def test_gate_writes_no_outcome_fact(self, db_session):
        with pytest.raises(UnmappableExecutionId):
            reconcile_execution(db_session, uuid.UUID(EXECUTION_ID), "exec-op")
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
# A2-B scope (§20 / §21) — execution_id is now PARSED + CORRELATED
# --------------------------------------------------------------------------
class TestA2BScope:
    def test_non_uuid_is_404(self, client, operators):
        # A2-B PARSES the path id: a non-UUID is a correlation-input failure -> the
        # uniform 404 (in A2-A it reached the 501 stub; correlation now gates it).
        r = client.post(_url(eid="not-a-uuid"), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404

    def test_nonexistent_execution_is_404(self, client, operators):
        # A2-B CORRELATES: a well-formed id with no chain -> 404 (spec §20).
        r = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert r.status_code == 404

    def test_non_uuid_and_nonexistent_are_indistinguishable(self, client, operators):
        # §21 non-discrimination: the SAME static detail for a malformed id and an
        # absent chain — a caller cannot tell a format failure from a nonexistent one.
        a = client.post(_url(eid="not-a-uuid"), json={}, headers=_auth("tok-exec"))
        b = client.post(_url(), json={}, headers=_auth("tok-exec"))
        assert a.status_code == b.status_code == 404
        assert a.json()["detail"] == b.json()["detail"]


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
