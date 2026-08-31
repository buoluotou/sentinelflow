"""Response-execution API (Phase 3.1.7).

Thin HTTP layer over the Execute / Compensation Service (3.1.6):

    HTTP Auth -> Request Schema -> Service

The API OWNS: Bearer EXECUTION_TOKEN on the write paths, request-schema
validation, the Service call, typed-exception -> HTTP mapping, commit,
response serialization. The API NEVER judges approval status, action,
target or lifecycle, never calls an executor and never writes
execution_log rows itself — every execution fact is produced by the
Service.

HTTP contract (frozen):
    401  write paths only — token missing / malformed / wrong; the auth
         check fails BEFORE the Service runs, so 401 writes ZERO
         execution_log rows. The token value never appears in a
         response, an exception string, audit detail or the database.
    422  schema violation — every smuggling attempt (action / target /
         direction / detail / created_at / status ...) dies here via
         extra="forbid", before the Service runs.
    404  ApprovalNotFound / ExecutionNotFound — no audit row.
    409  the D14 conflict family — Service pre-check and DB partial
         unique index raise the SAME typed exceptions; both map here.
    201  EVERY write outcome: 201 means the Intent formed an execution
         FACT, not that the underlying action succeeded — 201+succeeded,
         201+failed and 201+guard_rejected are all legal.

GET endpoints are read-only audit views and require NO token; the list
is a paged, filterable envelope (?status= / ?direction= / ?approval_id=
/ ?page= / ?size=, most recent activity first — design §10, completed
3.1.9) whose state comes exclusively from the frozen
derive_execution_state(), never a reimplementation, and the detail
returns the full history created_at ASC.
"""
import secrets
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.execution_log import ExecutionLog
from app.schemas.response_execution import (
    CompensateRequest,
    ExecuteRequest,
    ExecutionListResponse,
    ExecutionLogRowRead,
    ExecutionRead,
    ExecutionSummaryRead,
)
from app.services.executions import (
    ExecutionGuardError,
    ExecutionResult,
    ExecutionServiceError,
    ExecutorConfigError,
    ResponseExecutor,
    compensate_response,
    create_executor,
    derive_execution_state,
    execute_response,
)

router = APIRouter(tags=["response-execution"])

#: ?status= filter vocabulary — exactly the derivable states (the
#: ALLOWED_TRANSITIONS keys of services/executions/state.py); invalid
#: values fail fast with 422 (incidents ?status= precedent).
StateFilter = Literal[
    "requested",
    "guard_rejected",
    "dispatched",
    "succeeded",
    "failed",
    "compensation_requested",
    "compensation_succeeded",
    "compensation_failed",
]

#: ?direction= filter vocabulary (frozen direction words, design §4).
DirectionFilter = Literal["execute", "compensate"]


# --------------------------------------------------------------------------
# Dependencies (deployment seams, overridable in tests)
# --------------------------------------------------------------------------
def require_execution_token(authorization: str | None = Header(default=None)) -> None:
    """Write-path gate. Three failure shapes, ONE uniform 401: header
    missing, scheme malformed, secret mismatch. Fail-closed: an
    unconfigured EXECUTION_TOKEN keeps the write path fully closed.

    The presented credential is never echoed — detail strings are static,
    so the token cannot leak into a response or an exception string."""
    expected = settings.EXECUTION_TOKEN
    if not expected:
        raise HTTPException(status_code=401, detail="Execution credentials not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid execution credentials")
    candidate = authorization[len("Bearer ") :]
    if not candidate or not secrets.compare_digest(candidate, expected):
        raise HTTPException(status_code=401, detail="Invalid execution credentials")


def get_response_executor() -> ResponseExecutor:
    """Registry-produced adapter from settings (mock by default, frozen
    3.1.5). Tests override this dependency to drive failure paths.

    3.2.2: a misconfigured adapter is a server-side deployment fault,
    mapped to ONE static 503 detail — the sanitized config message (and
    anything an adapter ever whispers) never reaches the client."""
    try:
        return create_executor(settings)
    except ExecutorConfigError:
        raise HTTPException(
            status_code=503, detail="Execution adapter misconfigured"
        )


# --------------------------------------------------------------------------
# Write endpoints (token required)
# --------------------------------------------------------------------------
@router.post(
    "/executions",
    response_model=ExecutionRead,
    status_code=201,
    dependencies=[Depends(require_execution_token)],
)
def create_execution(
    payload: ExecuteRequest,
    db: Session = Depends(get_db),
    executor: ResponseExecutor = Depends(get_response_executor),
) -> ExecutionRead:
    """Run one Execute Intent end-to-end. 201 = an execution fact exists;
    the verdict lives in derived_state (succeeded / failed /
    guard_rejected). A raised Service error aborts BEFORE commit, so no
    conflicting fact is ever persisted."""
    try:
        result = execute_response(
            db,
            approval_id=payload.approval_id,
            execution_id=payload.execution_id,
            operator=payload.operator,
            executor=executor,
            comment=payload.comment,
        )
    except (ExecutionServiceError, ExecutionGuardError) as exc:
        # http_status-driven mapping: ApprovalNotFound / ExecutionNotFound
        # carry 404, the D14 conflict family carries 409 — the base
        # classes catch them all, the subclasses decide the status.
        raise _to_http_error(exc) from exc
    response = _render_execution(result)
    db.commit()
    return response


@router.post(
    "/executions/compensate",
    response_model=ExecutionRead,
    status_code=201,
    dependencies=[Depends(require_execution_token)],
)
def compensate_execution(
    payload: CompensateRequest,
    db: Session = Depends(get_db),
    executor: ResponseExecutor = Depends(get_response_executor),
) -> ExecutionRead:
    """Run one Compensation Intent: a FRESH execution_id undoing a
    settled forward execution. approval_id / action / target are
    inherited server-side from the original chain — never accepted here."""
    try:
        result = compensate_response(
            db,
            compensates_execution_id=payload.compensates_execution_id,
            execution_id=payload.execution_id,
            operator=payload.operator,
            executor=executor,
            comment=payload.comment,
        )
    except (ExecutionServiceError, ExecutionGuardError) as exc:
        raise _to_http_error(exc) from exc
    response = _render_execution(result)
    db.commit()
    return response


# --------------------------------------------------------------------------
# Read endpoints (no token — read-only audit views)
# --------------------------------------------------------------------------
@router.get("/executions", response_model=ExecutionListResponse)
def list_executions(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    status: StateFilter | None = Query(
        default=None, description="Filter by derived state (never recomputed)"
    ),
    direction: DirectionFilter | None = Query(
        default=None, description="Filter by chain direction"
    ),
    approval_id: uuid.UUID | None = Query(
        default=None, description="Filter by the approval the chain belongs to"
    ),
    db: Session = Depends(get_db),
) -> ExecutionListResponse:
    """Paged audit list, most recent activity first (design §10 frozen
    read contract, completed 3.1.9). Filters narrow the derived-state
    view only — state comes exclusively from the frozen
    derive_execution_state(); this layer never recomputes. Read ≠
    execute: no token, no writes."""
    rows = list(
        db.scalars(
            select(ExecutionLog).order_by(
                ExecutionLog.created_at.asc(), ExecutionLog.id.asc()
            )
        )
    )
    grouped: dict[uuid.UUID, list[ExecutionLog]] = {}
    order: list[uuid.UUID] = []
    for row in rows:
        if row.execution_id not in grouped:
            grouped[row.execution_id] = []
            order.append(row.execution_id)
        grouped[row.execution_id].append(row)
    summaries: list[ExecutionSummaryRead] = []
    for execution_id in order:
        asc_rows = grouped[execution_id]
        first, last = asc_rows[0], asc_rows[-1]
        summaries.append(
            ExecutionSummaryRead(
                execution_id=execution_id,
                approval_id=first.approval_id,
                direction=first.direction,
                action=first.action,
                target=first.target,
                operator=first.operator,
                derived_state=derive_execution_state(list(reversed(asc_rows))),
                chain=[row.decision for row in asc_rows],
                created_at=first.created_at,
                last_decision_at=last.created_at,
            )
        )
    # Filters operate on server-derived fields only — never re-deriving.
    if status is not None:
        summaries = [s for s in summaries if s.derived_state == status]
    if direction is not None:
        summaries = [s for s in summaries if s.direction == direction]
    if approval_id is not None:
        summaries = [s for s in summaries if s.approval_id == approval_id]
    # Most recent activity first; fully deterministic tie-breaks.
    summaries.sort(
        key=lambda s: (s.last_decision_at, s.created_at, s.execution_id),
        reverse=True,
    )
    total = len(summaries)
    items = summaries[(page - 1) * size : (page - 1) * size + size]
    return ExecutionListResponse(total=total, page=page, size=size, items=items)


@router.get("/executions/{execution_id}", response_model=ExecutionRead)
def execution_detail(execution_id: str, db: Session = Depends(get_db)) -> ExecutionRead:
    """One execution's complete audit history, created_at ASC; 404 when
    the execution_id is unknown (malformed ids map to the same 404)."""
    rows = list(
        db.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == _to_uuid(execution_id))
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Execution not found")
    first = rows[0]
    return ExecutionRead(
        execution_id=first.execution_id,
        approval_id=first.approval_id,
        direction=first.direction,
        action=first.action,
        target=first.target,
        derived_state=derive_execution_state(list(reversed(rows))),
        chain=[row.decision for row in rows],
        history=[ExecutionLogRowRead.model_validate(row) for row in rows],
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _to_http_error(exc: Exception) -> HTTPException:
    """http_status-driven mapping (frozen on the typed exception family):
    404 not-found, 409 conflicts; anything unclassified stays a 500. The
    detail carries the exception class name and message — never the token."""
    status = getattr(exc, "http_status", 500)
    return HTTPException(
        status_code=status,
        detail={"error": type(exc).__name__, "message": str(exc)},
    )


def _render_execution(result: ExecutionResult) -> ExecutionRead:
    """Serialize BEFORE commit: the Service's in-memory rows carry every
    value, so the commit boundary never re-reads expired attributes."""
    rows_asc = list(result.rows)
    first = rows_asc[0]
    return ExecutionRead(
        execution_id=result.execution_id,
        approval_id=result.approval_id,
        direction=result.direction,
        action=first.action,
        target=first.target,
        derived_state=result.final_decision,
        chain=list(result.chain),
        history=[ExecutionLogRowRead.model_validate(row) for row in rows_asc],
    )


def _to_uuid(value: str) -> uuid.UUID:
    """Malformed ids map to the same 404 as unknown ids (Step 12.3 style)."""
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Execution not found") from exc
