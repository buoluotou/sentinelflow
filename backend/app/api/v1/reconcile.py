"""Manual Reconcile API — secured route + correlation wiring (Phase 3.4.5-A2-B).

The PULL-side counterpart to the webhook (PUSH-side) inbound path. Where a
webhook lets an EXTERNAL SYSTEM report an outcome, Manual Reconcile lets an
AUTHENTICATED HUMAN OPERATOR ask the platform to GO READ the external system's
current state for one past execution and append what it finds as an Outcome Fact
(``source="manual_reconcile"``).

    Authenticated Operator -> POST /api/v1/executions/{execution_id}/reconcile
        -> Operator RBAC (reuse authenticate_operator)   <- 3.4.5-A2-A (sealed)
        -> Correlation / External Reference              <- THIS STEP (A2-B)
        -> ReadAdapterRegistry / ReadAdapter.read         <- A2-C
        -> Read Failure -> reconciliation_failed          <- A2-D
        -> 3.4.3 Validation / Mapping / Fact Append       <- A2-E

A2-A established the seam (RBAC + the empty body + a 501 stub). A2-B wires the
platform side of history-driven reconcile: the route parses ``execution_id`` to a
UUID and delegates to ``reconcile_execution``, which CORRELATES (reusing 3.4.4-C)
and extracts the adapter + external_reference read-only from ``execution_log``,
then stops at ``NotImplementedError`` because no read adapter exists yet. The
route maps the domain rejections to HTTP exactly as ``webhooks.py`` does:

  - a malformed ``execution_id`` OR one that maps to no chain -> 404
    (``UnmappableExecutionId``, caught BEFORE its ``ContractValidationFailure``
    base); the two are deliberately INDISTINGUISHABLE (one uniform static detail);
  - a chain with no reconcilable external reference -> 422
    (``MissingExternalReference``, a ``ContractValidationFailure``);
  - a correlated, reference-bearing chain -> 501 (``NotImplementedError``) — an
    honest "not yet implemented", NEVER a 200 ``accepted`` and NEVER a fabricated
    reconciliation success (spec §20 / §21 / §36).

A2-B performs NO external read, NO ``ReadAdapterRegistry`` access, NO mapping, NO
Outcome persistence, and NO execution / dispatch / compensation (spec §2 / §25).
HTTP mapping lives HERE, never in the domain (mirrors ``webhooks.py``); when the
pipeline completes the SERVICE will own the transaction (A2-E), so this router
carries NO persistence surface and never echoes the ORM, an external state, or a
credential. Every rejection detail is STATIC (spec §13 / §21): it leaks no
execution_id, no operator, no adapter, no reference value and no credential.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.response_execution import authenticate_operator
from app.core.database import get_db
from app.schemas.reconcile import (
    ManualReconcileRequest,
    ManualReconcileResponse,
)
from app.services.executions.operators import Operator
from app.services.outcomes.correlation import UnmappableExecutionId
from app.services.outcomes.manual_reconcile import reconcile_execution
from app.services.outcomes.reconciliation import ContractValidationFailure

router = APIRouter(tags=["manual-reconcile"])

#: Correlation failure (spec §21): a malformed ``execution_id`` OR one that maps
#: to no existing chain -> 404. STATIC + UNIFORM: a malformed id is deliberately
#: indistinguishable from an absent chain (non-discrimination, mirroring the
#: webhook's uniform 401); it echoes no execution_id, no adapter, no credential.
RECONCILE_CORRELATION_FAILURE_DETAIL = "execution correlation failed"

#: Contract rejection (spec §21): ``MissingExternalReference`` (a
#: ``ContractValidationFailure``) — the chain exists but carries no reconcilable
#: external reference -> 422. STATIC: leaks nothing about the refused value, never
#: the adapter, never a credential.
RECONCILE_VALIDATION_FAILURE_DETAIL = "reconcile validation failed"

#: ONE uniform "not yet implemented" detail (3.4.5-A2-A, unchanged). STATIC by
#: design: it carries NO execution_id, NO operator name, NO adapter, NO credential
#: and NO internal exception text — nothing an attacker can discriminate on. A2-B
#: correlates + extracts, then stops here (no read adapter yet) -> an honest 501,
#: never a fabricated success (spec §20 / §36).
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
    """POST /api/v1/executions/{execution_id}/reconcile — the 3.4.5-A2-B seam.

    Order mirrors ``webhooks.py`` (auth gate FIRST, then body, then service):

      - ``authenticate_operator`` (a dependency) resolves the Bearer token to the
        server-side ``Operator`` identity and enforces ``can_execute`` — it
        short-circuits to 401 / 403 BEFORE the body or the path id is ever
        considered. The operator identity is ``authenticated.name`` (NEVER a body
        field, spec §7); the webhook's ``adapter:{identity}`` recorder rule is NOT
        copied here — this is the human trust domain;
      - FastAPI validates ``payload`` against the EMPTY ``ManualReconcileRequest``
        (``extra="forbid"``) — any smuggled field (``adapter`` /
        ``external_reference`` / ``operator`` / ``source`` / a credential / ...) is
        its own 422 at the boundary, so a client can NEVER inject the adapter or
        the reference the pipeline is about to extract from history (spec §6 /
        §19);
      - ``execution_id`` (a raw PATH string) is parsed to a UUID; a malformed id is
        a correlation-input failure -> the SAME uniform 404 as an absent chain
        (spec §7 / §21);
      - ``reconcile_execution`` correlates (reuse 3.4.4-C) + extracts the adapter /
        external_reference read-only from ``execution_log`` (A2-B), then raises
        ``NotImplementedError`` because no read adapter exists yet -> 501.

    HTTP mapping lives HERE, never in the domain (mirrors ``webhooks.py``):
    ``UnmappableExecutionId`` (a ``ContractValidationFailure`` subclass) -> 404 and
    is caught BEFORE its base; any other ``ContractValidationFailure``
    (``MissingExternalReference``) -> 422; ``NotImplementedError`` -> 501. Every
    detail is STATIC, so a rejection leaks nothing about the refused value.

    ``response_model`` / ``status_code=200`` declare the frozen §4.4 success
    contract for documentation; A2-B NEVER reaches a 200 (the pipeline always
    stops at 404 / 422 / 501), so no success is ever implied. The §4.4 rich
    rejected envelope (``reason`` enum) lands with the success path in A2-E; until
    then a rejection is a static-detail ``HTTPException`` on the A2-A skeleton
    (spec §21 "沿用 A2-A skeleton").
    """
    try:
        execution_uuid = uuid.UUID(execution_id)
    except (ValueError, AttributeError, TypeError) as exc:
        # Malformed id -> the SAME uniform 404 as an absent chain (spec §7/§21):
        # a caller cannot tell a bad format from a nonexistent execution.
        raise HTTPException(
            status_code=404, detail=RECONCILE_CORRELATION_FAILURE_DETAIL
        ) from exc
    try:
        return reconcile_execution(db, execution_uuid, authenticated.name)
    except UnmappableExecutionId as exc:
        # Correlation failure (no chain) — caught BEFORE its ContractValidation
        # Failure base, exactly as webhooks.py does (spec §21).
        raise HTTPException(
            status_code=404, detail=RECONCILE_CORRELATION_FAILURE_DETAIL
        ) from exc
    except ContractValidationFailure as exc:
        # MissingExternalReference (chain exists, no reconcilable handle) -> 422.
        # STATIC detail — leaks nothing about the refused adapter / reference.
        raise HTTPException(
            status_code=422, detail=RECONCILE_VALIDATION_FAILURE_DETAIL
        ) from exc
    except NotImplementedError as exc:
        # Correlated + reference-bearing, but no read adapter yet -> honest 501.
        raise HTTPException(
            status_code=501, detail=RECONCILE_NOT_IMPLEMENTED_DETAIL
        ) from exc
