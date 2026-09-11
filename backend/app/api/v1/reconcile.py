"""Manual Reconcile API — secured route and outcome mapping/persistence.

The pull-side counterpart to the webhook push-side inbound path. Where a
webhook lets an external system report an outcome, Manual Reconcile lets an
authenticated human operator ask the platform to read the external system's
current state for one past execution and append what it finds as an Outcome
Fact (``source="manual_reconcile"``).

Authenticated Operator -> POST /api/v1/executions/{execution_id}/reconcile
-> Operator RBAC (reuse authenticate_operator)
-> Correlation / External Reference
-> ReadAdapterRegistry / ReadAdapter.read
-> Read Failure -> reconciliation_failed
-> Read Success -> Validate / Map / Append

The route parses ``execution_id`` to a UUID and delegates to
``reconcile_execution``, which correlates the chain through the shared
correlation layer, extracts the adapter and external_reference read-only from
``execution_log``, then resolves a reader from the ``ReadAdapterRegistry``.
The production registry is empty, so every adapter is rejected there and no
reader is ever returned. Each domain rejection maps to HTTP the same way
``webhooks.py`` maps it:

- a malformed ``execution_id`` or one that maps to no chain -> 404
(``UnmappableExecutionId``, caught before its ``ContractValidationFailure``
base); one uniform static detail covers both, so a caller cannot tell the
two apart;
- a chain with no reconcilable external reference -> 422
(``MissingExternalReference``, a ``ContractValidationFailure``) — this gate
runs before the registry;
- a correlated, reference-bearing chain whose adapter has no reader -> 404
(``UnsupportedAdapterRead``, a ``ReadAdapterError``, not a
``ContractValidationFailure``): the registry does not report support it
cannot deliver. In production this is the outcome for shuffle / wazuh /
thehive / mock;
- a reader that exists and whose ``read()`` fails in transit (only through a
test-injected ``FakeReadAdapter``, never in production) -> one
``reconciliation_failed`` fact is appended -> 200
``ManualReconcileResponse``;
- a reader that exists and whose ``read()`` succeeds -> the external_state is
validated and mapped and one mapped Outcome Fact is appended -> 200
``ManualReconcileResponse``. When the state falls outside the mapped
vocabulary (as every shuffle / thehive / mock state does today) mapping
raises ``UnrecognizedExternalState`` -> 422 with no facts appended, so an
unmapped state never yields a 200.

``UnsupportedAdapterRead`` (registry lookup found no reader) is distinct from
``reconciliation_failed`` (a real ``read()`` that failed at transport level):
the former involves no read attempt, so it is a rejection with no Outcome Fact,
never a failure fact. Production performs no external read at all, because the
registry is empty; the real Shuffle / Wazuh / TheHive read adapters are
separate work. The route performs no execution, dispatch, compensation or
retry either; its writes are the read-failure ``reconciliation_failed`` append
and the success mapped-fact append. HTTP mapping lives here, never in the
domain (mirrors ``webhooks.py``); the service owns both transactions (the
failure inline, the success via ``manual_persist``), so this router maps either
path's ``OutcomePersistenceError`` to a 500 and never echoes the ORM, a raw
external payload, or a credential. Every rejection detail is static: it leaks
no execution_id, no operator, no adapter, no reference value, no credential.
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
from app.services.outcomes.webhook import OutcomePersistenceError

router = APIRouter(tags=["manual-reconcile"])

# Correlation failure: a malformed ``execution_id`` or one that maps to no
# existing chain -> 404. One static detail covers both, so a malformed id is
# indistinguishable from an absent chain (mirroring the webhook's uniform
# 401); it echoes no execution_id, no adapter, no credential.
RECONCILE_CORRELATION_FAILURE_DETAIL = "execution correlation failed"

# Contract rejection: ``MissingExternalReference`` (a
# ``ContractValidationFailure``) — the chain exists but carries no reconcilable
# external reference -> 422. Static: it leaks nothing about the refused value,
# never the adapter, never a credential.
RECONCILE_VALIDATION_FAILURE_DETAIL = "reconcile validation failed"

# Registry-capability rejection: ``UnsupportedAdapterRead`` — the chain
# correlated and carries a reference, but the ReadAdapterRegistry has no reader
# for its adapter (which in the empty production registry is every adapter) ->
# 404. A ``ReadAdapterError``, not a ``ContractValidationFailure``. Static: it
# names no adapter and echoes no external_reference. Distinct from the
# correlation 404, which means "no chain"; this one means "chain exists, no
# reader", and it is not ``reconciliation_failed`` because no read was
# attempted.
RECONCILE_UNSUPPORTED_ADAPTER_DETAIL = "adapter read unsupported"

# Persistence-infrastructure failure: ``OutcomePersistenceError`` — the Outcome
# Fact append (the ``reconciliation_failed`` fact on a read failure, the mapped
# fact on a read success) failed at the DB layer and was rolled back, so no
# partial fact survives -> 500. It is never accepted=true, never a 4xx contract
# rejection, and an infrastructure error is never reported as
# ``reconciliation_failed`` (mirrors ``webhooks.py``). Static: it leaks no
# execution_id, operator, or credential.
RECONCILE_PERSISTENCE_FAILURE_DETAIL = "reconcile outcome persistence failed"


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
    """POST /api/v1/executions/{execution_id}/reconcile — the Manual Reconcile seam.

Order mirrors ``webhooks.py`` (auth gate first, then body, then service):

- ``authenticate_operator`` (a dependency) resolves the Bearer token to the
server-side ``Operator`` identity and enforces ``can_execute`` — it
short-circuits to 401 / 403 before the body or the path id is ever
considered. The operator identity is ``authenticated.name``, never a body
field; the webhook's ``adapter:{identity}`` recorder rule does not apply
here, because this is the human trust domain;
- FastAPI validates ``payload`` against the empty ``ManualReconcileRequest``
(``extra="forbid"``) — a smuggled field (``adapter`` /
``external_reference`` / ``operator`` / ``source`` / a credential / ...)
is its own 422 at the boundary, so a client can never inject the adapter
or the reference the pipeline is about to read from history;
- ``execution_id`` (a raw path string) is parsed to a UUID; a malformed id
is a correlation-input failure -> the same uniform 404 as an absent
chain;
- ``reconcile_execution`` correlates the chain and extracts the adapter /
external_reference read-only from ``execution_log``, then resolves a
reader from the ``ReadAdapterRegistry``. The production registry is
empty, so every adapter raises ``UnsupportedAdapterRead`` -> 404. A
reader only exists through a test-injected ``FakeReadAdapter``; once one
is invoked the pipeline has two real exits: a read that fails in transit
is appended as one ``reconciliation_failed`` fact and returns 200, while
a read that succeeds is validated, mapped and appended as one mapped
fact and returns 200 — or, when the state is outside the mapped
vocabulary, raises ``UnrecognizedExternalState`` -> 422 with no facts
appended.

HTTP mapping lives here, never in the domain (mirrors ``webhooks.py``):
``UnmappableExecutionId`` (a ``ContractValidationFailure`` subclass) -> 404
and is caught before its base; ``UnsupportedAdapterRead`` (a
``ReadAdapterError``, a separate family) -> 404; any other
``ContractValidationFailure`` (``MissingExternalReference`` /
``UnrecognizedExternalState`` / ``InvalidObservedAt``) -> 422; and either
path's ``OutcomePersistenceError`` (the fact append failed and was rolled
back) -> 500, never accepted=true. Every detail is static, so a rejection
leaks nothing about the refused value.

``response_model`` / ``status_code=200`` declare the response envelope, which
both real exits return: the read-failure path returns the
``reconciliation_failed`` fact and the success path returns the mapped fact
in the same ``ManualReconcileResponse`` envelope, never a second response
schema. Every rejection is a static-detail ``HTTPException``; a read of an
unmapped state is refused with 422 rather than answered with 200.
"""
    try:
        execution_uuid = uuid.UUID(execution_id)
    except (ValueError, AttributeError, TypeError) as exc:
        # Malformed id -> the same uniform 404 as an absent chain: a caller
        # cannot tell a bad format from a nonexistent execution.
        raise HTTPException(
            status_code=404, detail=RECONCILE_CORRELATION_FAILURE_DETAIL
        ) from exc
    try:
        return reconcile_execution(db, execution_uuid, authenticated.name)
    except UnmappableExecutionId as exc:
        # Correlation failure (no chain) — caught before its ContractValidation
        # Failure base, as webhooks.py does.
        raise HTTPException(
            status_code=404, detail=RECONCILE_CORRELATION_FAILURE_DETAIL
        ) from exc
    except UnsupportedAdapterRead as exc:
        # Registry-capability rejection: the chain correlated and carries a
        # reference, but no reader exists for its adapter (in the empty
        # production registry, every adapter). A ReadAdapterError (not a
        # ContractValidationFailure) -> 404, a rejection with no Outcome Fact,
        # and not reconciliation_failed because no read was attempted.
        raise HTTPException(
            status_code=404, detail=RECONCILE_UNSUPPORTED_ADAPTER_DETAIL
        ) from exc
    except ContractValidationFailure as exc:
        # MissingExternalReference (chain exists, no reconcilable handle) -> 422.
        # Static detail — it leaks nothing about the refused adapter or reference.
        raise HTTPException(
            status_code=422, detail=RECONCILE_VALIDATION_FAILURE_DETAIL
        ) from exc
    except OutcomePersistenceError as exc:
        # Persistence-infrastructure failure: the Outcome Fact append — a
        # reconciliation_failed fact on a read failure, a mapped fact on a read
        # success — failed at the DB layer and was rolled back, so no partial
        # fact survives -> 500. Never accepted=true, and an infrastructure error
        # is never reported as reconciliation_failed (mirrors webhooks.py).
        # Static detail.
        raise HTTPException(
            status_code=500, detail=RECONCILE_PERSISTENCE_FAILURE_DETAIL
        ) from exc
