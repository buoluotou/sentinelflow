"""Manual Reconcile API — secured route + read-registry wiring (Phase 3.4.5-A2-C).

The PULL-side counterpart to the webhook (PUSH-side) inbound path. Where a
webhook lets an EXTERNAL SYSTEM report an outcome, Manual Reconcile lets an
AUTHENTICATED HUMAN OPERATOR ask the platform to GO READ the external system's
current state for one past execution and append what it finds as an Outcome Fact
(``source="manual_reconcile"``).

    Authenticated Operator -> POST /api/v1/executions/{execution_id}/reconcile
        -> Operator RBAC (reuse authenticate_operator)   <- 3.4.5-A2-A (sealed)
        -> Correlation / External Reference              <- 3.4.5-A2-B (sealed)
        -> ReadAdapterRegistry / ReadAdapter.read         <- THIS STEP (A2-C)
        -> Read Failure -> reconciliation_failed          <- A2-D
        -> 3.4.3 Validation / Mapping / Fact Append       <- A2-E

A2-A established the seam (RBAC + the empty body + a 501 stub); A2-B wired
correlation + read-only external-reference extraction. A2-C hands that context to
the A1 ``ReadAdapterRegistry``: the route still parses ``execution_id`` to a UUID
and delegates to ``reconcile_execution``, which now CORRELATES (reusing 3.4.4-C),
extracts the adapter + external_reference, then resolves a reader. Because the
PRODUCTION registry is EMPTY (spec §3), EVERY adapter rejects there — no reader is
ever fabricated. The route maps the domain rejections to HTTP exactly as
``webhooks.py`` does:

  - a malformed ``execution_id`` OR one that maps to no chain -> 404
    (``UnmappableExecutionId``, caught BEFORE its ``ContractValidationFailure``
    base); the two are deliberately INDISTINGUISHABLE (one uniform static detail);
  - a chain with no reconcilable external reference -> 422
    (``MissingExternalReference``, a ``ContractValidationFailure``) — this gate runs
    BEFORE the registry (spec §10 / §17 item 14);
  - a correlated, reference-bearing chain whose adapter has NO reader -> 404
    (``UnsupportedAdapterRead``, a ``ReadAdapterError`` — NOT a
    ``ContractValidationFailure``): the registry refuses to fake support. This is
    the production outcome for shuffle / wazuh / thehive / mock today (spec §8);
  - a reader that EXISTS and returns (only via a test-injected ``FakeReadAdapter``,
    never production) -> the pipeline still STOPS at ``NotImplementedError`` -> 501,
    because C maps NO state and persists NO fact (A2-E) — NEVER a 200 ``accepted``
    (spec §16).

``UnsupportedAdapterRead`` (registry lookup found no reader) is DISTINCT from
``reconciliation_failed`` (a real ``read()`` that failed at transport level — A2-D):
the former has NO read attempt, so it is a rejection with NO Outcome Fact, never a
failure fact (spec §9). A2-C performs NO real external read (the registry is empty),
NO mapping, NO Outcome persistence, and NO execution / dispatch / compensation
(spec §2 / §14 / §25). HTTP mapping lives HERE, never in the domain (mirrors
``webhooks.py``); the SERVICE will own the transaction when the pipeline completes
(A2-E), so this router carries NO persistence surface and never echoes the ORM, an
external state, or a credential. Every rejection detail is STATIC (spec §13 / §21):
it leaks no execution_id, no operator, no adapter, no reference value, no credential.
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
from app.services.manual_reconcile import UnsupportedAdapterRead
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

#: Registry-capability rejection (spec §8): ``UnsupportedAdapterRead`` — the chain
#: correlated and carries a reference, but the ReadAdapterRegistry has NO reader for
#: its adapter (EVERY adapter, in the empty production registry) -> 404. A
#: ``ReadAdapterError``, NOT a ``ContractValidationFailure``. STATIC: it names no
#: adapter and echoes no external_reference (the A1 non-echo discipline). Distinct
#: from the correlation 404 (which means "no chain"); this one means "chain exists,
#: no reader" — and is NOT reconciliation_failed (no read was attempted, spec §9).
RECONCILE_UNSUPPORTED_ADAPTER_DETAIL = "adapter read unsupported"

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
    """POST /api/v1/executions/{execution_id}/reconcile — the 3.4.5-A2-C seam.

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
        external_reference read-only from ``execution_log`` (A2-B), then resolves a
        reader from the ``ReadAdapterRegistry`` (A2-C). The production registry is
        EMPTY, so every adapter raises ``UnsupportedAdapterRead`` -> 404; a reader
        only exists under a test-injected ``FakeReadAdapter``, and even then the
        pipeline stops at ``NotImplementedError`` -> 501 (no mapping / persistence).

    HTTP mapping lives HERE, never in the domain (mirrors ``webhooks.py``):
    ``UnmappableExecutionId`` (a ``ContractValidationFailure`` subclass) -> 404 and
    is caught BEFORE its base; ``UnsupportedAdapterRead`` (a ``ReadAdapterError``, a
    SEPARATE family) -> 404; any other ``ContractValidationFailure``
    (``MissingExternalReference``) -> 422; ``NotImplementedError`` -> 501. Every
    detail is STATIC, so a rejection leaks nothing about the refused value.

    ``response_model`` / ``status_code=200`` declare the frozen §4.4 success
    contract for documentation; A2-C NEVER reaches a 200 (the pipeline always
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
    except UnsupportedAdapterRead as exc:
        # Registry-capability rejection (spec §8): the chain correlated + carries a
        # reference, but NO reader exists for its adapter (every adapter, in the
        # empty production registry). A ReadAdapterError (NOT a ContractValidation
        # Failure) -> 404, a rejection with NO Outcome Fact — and NOT
        # reconciliation_failed (no read was attempted, spec §9).
        raise HTTPException(
            status_code=404, detail=RECONCILE_UNSUPPORTED_ADAPTER_DETAIL
        ) from exc
    except ContractValidationFailure as exc:
        # MissingExternalReference (chain exists, no reconcilable handle) -> 422.
        # STATIC detail — leaks nothing about the refused adapter / reference.
        raise HTTPException(
            status_code=422, detail=RECONCILE_VALIDATION_FAILURE_DETAIL
        ) from exc
    except NotImplementedError as exc:
        # A reader existed and returned (test-only FakeReadAdapter), but C maps no
        # state and persists no fact (A2-E) -> honest 501, never a 200 accepted.
        raise HTTPException(
            status_code=501, detail=RECONCILE_NOT_IMPLEMENTED_DETAIL
        ) from exc
