"""Manual Reconcile API — secured route seam (Phase 3.4.5-A2-A).

The PULL-side counterpart to the webhook (PUSH-side) inbound path. Where a
webhook lets an EXTERNAL SYSTEM report an outcome, Manual Reconcile lets an
AUTHENTICATED HUMAN OPERATOR ask the platform to GO READ the external system's
current state for one past execution and append what it finds as an Outcome Fact
(``source="manual_reconcile"``).

    Authenticated Operator -> POST /api/v1/executions/{execution_id}/reconcile
        -> Operator RBAC (reuse authenticate_operator)   <- THIS STEP (A2-A)
        -> Correlation / External Reference              <- A2-B
        -> ReadAdapterRegistry / ReadAdapter.read         <- A2-C
        -> Read Failure -> reconciliation_failed          <- A2-D
        -> 3.4.3 Validation / Mapping / Fact Append       <- A2-E

3.4.5-A2-A SCOPE (spec §35): establish the route SAFELY and nothing more. This
module wires exactly three things:

  - Operator authentication / RBAC by REUSING ``authenticate_operator`` (3.3.1,
    ``response_execution.py``) — NEVER a new auth stack, and NEVER a callback
    token (spec §3 / §4 / §27). The human trust domain (``EXECUTION_TOKEN`` /
    ``OPERATORS_JSON``) guards this path; the inbound-callback trust domain does
    NOT. ``executor`` / ``admin`` pass; ``viewer`` / ``reviewer`` -> 403;
    missing / malformed / wrong / unconfigured token -> 401.
  - The Gate-2 body ``ManualReconcileRequest`` (EMPTY, ``extra="forbid"``): the
    client supplies NO observation data — ``execution_id`` comes from the PATH,
    and ``operator`` / ``source`` / ``adapter`` / ``external_reference`` / any
    credential are structurally impossible to smuggle (spec §6 / §7 / §8).
  - A call into the service entrypoint ``reconcile_execution`` (a STUB in A2-A)
    whose ``NotImplementedError`` maps to ONE STATIC HTTP 501 — an honest "not
    yet implemented", NEVER a 200 ``accepted`` and NEVER a fabricated
    reconciliation success (spec §36).

A2-A performs NO external read, NO ``ReadAdapterRegistry`` access, NO
correlation, NO Outcome persistence, and NO execution / dispatch / compensation
(spec §25 / §35). HTTP mapping lives HERE, never in the domain (mirrors
``webhooks.py``); when the pipeline lands the SERVICE will own the transaction
(A2-E), so this router carries NO persistence surface and never echoes the ORM,
an external state, or a credential.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.response_execution import authenticate_operator
from app.core.database import get_db
from app.schemas.reconcile import (
    ManualReconcileRequest,
    ManualReconcileResponse,
)
from app.services.executions.operators import Operator
from app.services.outcomes.manual_reconcile import reconcile_execution

router = APIRouter(tags=["manual-reconcile"])

#: ONE uniform "not yet implemented" detail (3.4.5-A2-A). STATIC by design: it
#: carries NO execution_id, NO operator name, NO adapter, NO credential and NO
#: internal exception text — nothing an attacker can discriminate on. The
#: pipeline lands in A2-B..E; until then an authorized operator gets an honest
#: 501, never a fabricated success (spec §36).
RECONCILE_NOT_IMPLEMENTED_DETAIL = "manual reconcile not yet implemented"


@router.post(
    "/executions/{execution_id}/reconcile",
    response_model=ManualReconcileResponse,
    status_code=200,
)
def manual_reconcile(
    execution_id: str,
    payload: ManualReconcileRequest,
    authenticated: Operator = Depends(authenticate_operator),
    db: Session = Depends(get_db),
) -> ManualReconcileResponse:
    """POST /api/v1/executions/{execution_id}/reconcile — the 3.4.5-A2-A seam.

    Order mirrors ``webhooks.py`` (auth gate FIRST, then body, then service):

      - ``authenticate_operator`` (a dependency) resolves the Bearer token to
        the server-side ``Operator`` identity and enforces ``can_execute`` — it
        short-circuits to 401 / 403 BEFORE the body is ever considered. The
        operator identity is ``authenticated.name`` (NEVER a body field, spec
        §7); the webhook's ``adapter:{identity}`` recorder rule is NOT copied
        here — this is the human trust domain;
      - FastAPI validates ``payload`` against the EMPTY ``ManualReconcileRequest``
        (``extra="forbid"``) — any smuggled field is its own 422 (spec §6);
      - ``reconcile_execution`` is the service entrypoint. In A2-A it is a STUB
        that raises ``NotImplementedError``, mapped here to ONE static 501 (spec
        §36). A2-B..E replace the stub with the real pull pipeline, after which
        this handler returns the §4.4 ``ManualReconcileResponse`` (200) once an
        Outcome Fact is committed.

    ``execution_id`` is taken as a RAW path string in A2-A: correlation + UUID
    validation (malformed / unknown -> 404) land in A2-B, so A2-A does NOT parse
    it (spec §35 — no correlation yet). ``response_model`` / ``status_code=200``
    declare the frozen §4.3 / §4.4 success contract for documentation; A2-A
    NEVER reaches a 200 (the stub always raises), so no success is ever implied.
    """
    try:
        return reconcile_execution(db, execution_id, authenticated.name)
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=501, detail=RECONCILE_NOT_IMPLEMENTED_DETAIL
        ) from exc
