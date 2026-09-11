"""Response-execution API.

Thin HTTP layer over the Execute / Compensation Service:

    Bearer Token -> Operator Auth -> Request Schema -> Service

The API owns: Bearer token authentication on the write paths (the token
maps to an Operator identity through the static registry, with a legacy
EXECUTION_TOKEN fallback), request-schema validation, the Service call,
typed-exception -> HTTP mapping, commit, response serialization. It does
not judge approval status, action, target or lifecycle, never calls an
executor and never writes execution_log rows itself — every execution
fact is produced by the Service.

HTTP contract:
    401  write paths only — token missing / malformed / wrong; the auth
         check fails before the Service runs, so a 401 writes no
         execution_log rows. The token value never appears in a
         response, an exception string, audit detail or the database.
    422  schema violation — a smuggled field (action / target /
         direction / detail / created_at / status ...) fails here via
         extra="forbid", before the Service runs.
    404  ApprovalNotFound / ExecutionNotFound — no audit row.
    409  the conflict family — the Service pre-check and the DB partial
         unique index raise the same typed exceptions; both map here.
    201  every write outcome: 201 means the intent formed an execution
         fact, not that the underlying action succeeded — 201+succeeded,
         201+failed and 201+guard_rejected are all legal.

GET endpoints are read-only audit views and require no token; the list
is a paged, filterable envelope (?status= / ?direction= / ?approval_id=
/ ?page= / ?size=, most recent activity first) whose state comes
exclusively from derive_execution_state(), never a reimplementation,
and the detail returns the full history created_at ASC.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.execution_log import ExecutionLog
from app.schemas.response_execution import (
    CompensateRequest,
    ExecuteRequest,
    ExecutionListResponse,
    ExecutionLogRowRead,
    ExecutionMetricsRead,
    ExecutionRead,
    ExecutionSummaryRead,
    ObservedHealthRead,
)
from app.services.executions import (
    DurableStoreRequired,
    ExecutionGuardError,
    ExecutionResult,
    ExecutionServiceError,
    ExecutorConfigError,
    ResponseExecutor,
    collect_execution_metrics,
    collect_observed_health,
    compensate_response,
    create_executor,
    derive_execution_state,
    execute_response,
)
from app.services.executions.durable_dispatch import DurableDispatchAttemptStore
from app.services.executions.durable_compensation import (
    DurableCompensationAttemptStore,
)
from app.services.executions.operators import (
    Operator,
    get_operator_registry,
)
from app.services.executions.policy import PolicyViolation

router = APIRouter(tags=["response-execution"])

# ?status= filter vocabulary — exactly the derivable states (the
# ALLOWED_TRANSITIONS keys of services/executions/state.py); invalid
# values fail fast with 422, matching the incidents ?status= filter.
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

# ?direction= filter vocabulary (the direction recorded on the chain).
DirectionFilter = Literal["execute", "compensate"]


#
# Dependencies (deployment seams, overridable in tests)
#
def _extract_bearer(authorization: str | None) -> str | None:
    """Extract the Bearer token from the Authorization header. Returns
    None when the header is missing or malformed — the caller decides
    the HTTP response (always 401 with a static detail string)."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    candidate = authorization[len("Bearer "):]
    return candidate if candidate else None


def authenticate_operator(
    authorization: str | None = Header(default=None),
) -> Operator:
    """Write-path gate with Operator identity.

    Resolves the Bearer token to an authenticated Operator via the
    static registry (or legacy EXECUTION_TOKEN fallback). The returned
    Operator's name is the server-side identity — the endpoint uses it
    instead of any client-supplied ``operator`` field.

    Role check: only ``executor`` and ``admin`` may dispatch executions;
    other roles get 403 (authenticated but not authorized)."""
    token = _extract_bearer(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Invalid execution credentials")
    registry = get_operator_registry()
    operator = registry.lookup(token, legacy_token=settings.EXECUTION_TOKEN)
    if operator is None:
        if not settings.EXECUTION_TOKEN and registry.operator_count == 0:
            raise HTTPException(
                status_code=401,
                detail="Execution credentials not configured",
            )
        raise HTTPException(status_code=401, detail="Invalid execution credentials")
    # Role gate: execution write paths require executor or admin.
    if not operator.role.can_execute:
        raise HTTPException(
            status_code=403,
            detail=f"Operator '{operator.name}' (role={operator.role.value}) "
            "may not dispatch executions",
        )
    return operator


def get_response_executor() -> ResponseExecutor:
    """Registry-produced adapter from settings (mock by default). Tests
    override this dependency to drive failure paths.

    A misconfigured adapter is a server-side deployment fault, mapped to
    one static 503 detail — the sanitized config message (and anything an
    adapter ever raises about it) never reaches the client."""
    try:
        return create_executor(settings)
    except ExecutorConfigError:
        raise HTTPException(
            status_code=503, detail="Execution adapter misconfigured"
        )


def get_dispatch_attempt_store(
    db: Session = Depends(get_db),
) -> DurableDispatchAttemptStore | None:
    """Dependency seam for the durable pre-dispatch attempt store.

    Production returns a store bound to the caller's engine, so
    ``execute_response`` commits the immutable dispatch intent + target binding
    on an independent transaction before the external request — the binding
    then survives a caller rollback, a terminal-write failure or a crash, which
    a flush inside the caller's transaction would not. Tests override this
    seam: the in-memory ``StaticPool`` harness shares one connection, so a real
    independent commit cannot interleave there — the conftest ``client``
    fixture overrides it to ``None`` (leaving the endpoint journeys unchanged)
    and dedicated file-backed tests drive the real store.
    """
    return DurableDispatchAttemptStore(db.get_bind())


def get_compensation_attempt_store(
    db: Session = Depends(get_db),
) -> DurableCompensationAttemptStore | None:
    """Dependency seam for the durable pre-compensation attempt store.

    Production returns a store bound to the caller's engine, so
    ``compensate_response`` commits the immutable reverse binding on an
    independent transaction before the external compensation request — the
    binding then survives a caller rollback, a terminal-write failure or a
    crash, the same guarantee the dispatch store gives on the forward path.
    Tests override this seam to ``None`` just like the dispatch store: the
    in-memory ``StaticPool`` harness shares one connection, so dedicated
    file-backed tests drive the real store.
    """
    return DurableCompensationAttemptStore(db.get_bind())


#
# Write endpoints (token required)
#
@router.post(
    "/executions",
    response_model=ExecutionRead,
    status_code=201,
)
def create_execution(
    payload: ExecuteRequest,
    db: Session = Depends(get_db),
    executor: ResponseExecutor = Depends(get_response_executor),
    authenticated: Operator = Depends(authenticate_operator),
    dispatch_attempt_store: DurableDispatchAttemptStore | None = Depends(
        get_dispatch_attempt_store
    ),
) -> ExecutionRead:
    """Run one Execute Intent end-to-end. 201 = an execution fact exists;
    the verdict lives in derived_state (succeeded / failed /
    guard_rejected). A raised Service error aborts before commit, so no
    conflicting fact is persisted.

    The operator identity comes from the authenticated token —
    ``payload.operator`` is ignored (kept optional for backwards
    compatibility, but the server-side binding is the only source of
    truth). The client can never impersonate an operator.

    A malformed execution-policy configuration is a server-side
    deployment fault, mapped to one static 503 detail — the transaction
    rolls back, so a broken policy never becomes an allow and never
    leaves a half-written chain.

    ``dispatch_attempt_store`` commits the immutable dispatch intent +
    target binding on an independent transaction before
    ``executor.execute()`` fires the external request, so the binding
    survives a caller rollback, a terminal-write failure or a crash. A
    pre-dispatch commit failure aborts before any external call."""
    try:
        result = execute_response(
            db,
            approval_id=payload.approval_id,
            execution_id=payload.execution_id,
            operator=authenticated.name,
            executor=executor,
            comment=payload.comment,
            dispatch_attempt_store=dispatch_attempt_store,
        )
    except PolicyViolation:
        # The requested intent row was already flushed inside the
        # aborted transaction — roll it back so a broken policy leaves
        # no half-written chain, then fail closed with one static 503.
        db.rollback()
        raise HTTPException(
            status_code=503, detail="Execution policy misconfigured"
        )
    except DurableStoreRequired:
        # A recognized external adapter reached the dispatch point with no
        # durable store (a DI gap or config fault). The requested intent row was
        # already flushed inside the aborted transaction — roll it back so a
        # refused-before-dispatch execution leaves no half-written chain, then
        # fail closed with one static 503, as PolicyViolation and
        # ExecutorConfigError do; the internal message never reaches the client.
        # The adapter was never called, so no external effect needs reconciling.
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Execution adapter requires a durable dispatch store",
        )
    except (ExecutionServiceError, ExecutionGuardError) as exc:
        # http_status-driven mapping: ApprovalNotFound / ExecutionNotFound
        # carry 404, the conflict family carries 409 — the base classes
        # catch them all, the subclasses decide the status.
        raise _to_http_error(exc) from exc
    response = _render_execution(result)
    db.commit()
    return response


@router.post(
    "/executions/compensate",
    response_model=ExecutionRead,
    status_code=201,
)
def compensate_execution(
    payload: CompensateRequest,
    db: Session = Depends(get_db),
    executor: ResponseExecutor = Depends(get_response_executor),
    authenticated: Operator = Depends(authenticate_operator),
    compensation_attempt_store: DurableCompensationAttemptStore | None = Depends(
        get_compensation_attempt_store
    ),
) -> ExecutionRead:
    """Run one Compensation Intent: a new execution_id that undoes a
    settled forward execution. approval_id / action / target are
    inherited server-side from the original chain — never accepted here.

    The operator identity comes from the authenticated token, as in
    create_execution — payload.operator is ignored."""
    try:
        result = compensate_response(
            db,
            compensates_execution_id=payload.compensates_execution_id,
            execution_id=payload.execution_id,
            operator=authenticated.name,
            executor=executor,
            comment=payload.comment,
            compensation_attempt_store=compensation_attempt_store,
        )
    except DurableStoreRequired:
        # A recognized external adapter reached the reverse dispatch point
        # with no durable compensation store (a DI gap or config fault). The
        # compensation_requested row was already flushed inside the aborted
        # transaction — roll it back so a refused-before-dispatch compensation
        # leaves no half-written chain, then fail closed with one static 503;
        # the internal message never reaches the client. The adapter was never
        # called, so no external reverse effect needs reconciling.
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Execution adapter requires a durable compensation store",
        )
    except (ExecutionServiceError, ExecutionGuardError) as exc:
        raise _to_http_error(exc) from exc
    response = _render_execution(result)
    db.commit()
    return response


#
# Read endpoints (no token — read-only audit views)
#
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
    """Paged audit list, most recent activity first. Filters narrow the
    derived-state view only — state comes exclusively from
    derive_execution_state(); this layer never recomputes, and the read
    endpoints take no token and write nothing.

    Pagination happens at the chain level inside SQL. Loading the whole
    ``execution_log`` table into Python, grouping and filtering it in memory
    and only then slicing a page costs O(table) memory and latency per
    request. Two window functions pick exactly one row per chain (its first
    row by ``(created_at, id)`` and its latest row by the same ordering,
    DESC — the ordering ``derive_execution_state`` uses), the chain-level
    filters, ordering and LIMIT/OFFSET run in the database, and only the
    current page's audit rows are hydrated. The ``derived_state`` of the
    returned items is still produced by ``derive_execution_state`` over those
    rows: the SQL expression is only the filter/order key, and a test pins
    the two together."""
    # 1. Rank every row inside its own chain. ``rn_first`` = the chain's first
    # row, ``rn_last`` = its latest row, both by the (created_at, id)
    # ordering of derive_execution_state() (state.py).
    first_rank = func.row_number().over(
        partition_by=ExecutionLog.execution_id,
        order_by=(ExecutionLog.created_at.asc(), ExecutionLog.id.asc()),
    ).label("rn_first")
    last_rank = func.row_number().over(
        partition_by=ExecutionLog.execution_id,
        order_by=(ExecutionLog.created_at.desc(), ExecutionLog.id.desc()),
    ).label("rn_last")
    ranked = select(
        ExecutionLog.execution_id.label("execution_id"),
        ExecutionLog.id.label("row_id"),
        ExecutionLog.created_at.label("created_at"),
        ExecutionLog.decision.label("decision"),
        ExecutionLog.direction.label("direction"),
        ExecutionLog.approval_id.label("approval_id"),
        ExecutionLog.action.label("action"),
        ExecutionLog.target.label("target"),
        ExecutionLog.operator.label("operator"),
        first_rank,
        last_rank,
    ).subquery("ranked_execution_log")
    heads = select(ranked).where(ranked.c.rn_first == 1).subquery("chain_head")
    tails = select(ranked).where(ranked.c.rn_last == 1).subquery("chain_tail")
    # 2. One row per chain: the head carries the chain's own facts, the tail its
    # latest stamp, its latest decision (= the derived state) and the row id
    # used as the ordering tie-break.
    chains = select(
        heads.c.execution_id,
        heads.c.approval_id,
        heads.c.direction,
        heads.c.action,
        heads.c.target,
        heads.c.operator,
        heads.c.created_at,
        tails.c.created_at.label("last_decision_at"),
        tails.c.row_id.label("last_row_id"),
        tails.c.decision.label("derived_state"),
    ).select_from(
        heads.join(tails, heads.c.execution_id == tails.c.execution_id)
    )
    # Filters operate on server-derived fields only — never re-deriving.
    if direction is not None:
        chains = chains.where(heads.c.direction == direction)
    if approval_id is not None:
        chains = chains.where(heads.c.approval_id == approval_id)
    if status is not None:
        chains = chains.where(tails.c.decision == status)
    # 3. total = the number of chains matching the filters; no audit rows are
    # transferred to compute it.
    total = db.scalar(select(func.count()).select_from(chains.subquery())) or 0
    # 4. Only the requested page of chains leaves the database. Most recent
    # activity first; a tie on the stamp resolves to the insert-ordered
    # UUIDv7 of the chain's last audit row, so the tie-break follows
    # insertion order rather than a random execution_id or a clock artifact.
    page_rows = db.execute(
        chains.order_by(tails.c.created_at.desc(), tails.c.row_id.desc())
        .limit(size)
        .offset((page - 1) * size)
    ).all()
    if not page_rows:
        return ExecutionListResponse(total=total, page=page, size=size, items=[])
    # 5. Hydrate the audit rows of those chains only (created_at ASC, so a chain
    # reads forward), then derive each state with derive_execution_state().
    rows = list(
        db.scalars(
            select(ExecutionLog)
            .where(
                ExecutionLog.execution_id.in_(
                    [chain.execution_id for chain in page_rows]
                )
            )
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )
    grouped: dict[uuid.UUID, list[ExecutionLog]] = {}
    for row in rows:
        grouped.setdefault(row.execution_id, []).append(row)
    items = [
        ExecutionSummaryRead(
            execution_id=chain.execution_id,
            approval_id=chain.approval_id,
            direction=chain.direction,
            action=chain.action,
            target=chain.target,
            operator=chain.operator,
            derived_state=derive_execution_state(
                list(reversed(grouped[chain.execution_id]))
            ),
            chain=[row.decision for row in grouped[chain.execution_id]],
            created_at=chain.created_at,
            last_decision_at=chain.last_decision_at,
        )
        for chain in page_rows
    ]
    return ExecutionListResponse(total=total, page=page, size=size, items=items)


@router.get("/executions/metrics", response_model=ExecutionMetricsRead)
def execution_metrics(db: Session = Depends(get_db)) -> ExecutionMetricsRead:
    """The execution metrics read model as a read-only audit view. No
    token, no writes, no re-execution:

        GET -> collect_execution_metrics -> execution_log -> numbers

    The body is the field-for-field mirror of the metrics.ExecutionMetrics
    dataclass (rates keep the None = JSON null semantics of an empty
    denominator). The endpoint neither creates nor modifies a single
    execution_log row — the read model is a pure function of what is
    already stored.

    Route registration order matters: this path is declared before
    /executions/{execution_id} so "metrics" can never be captured as an
    execution id."""
    return ExecutionMetricsRead.model_validate(collect_execution_metrics(db))


@router.get("/executions/health", response_model=ObservedHealthRead)
def execution_health(db: Session = Depends(get_db)) -> ObservedHealthRead:
    """The adapter observed-health read model as a read-only audit view.
    No token, no executor, no credentials, no external requests — health
    here is what the stored execution facts show, never a live probe:

        GET -> collect_observed_health -> execution_log -> verdicts

    The body is the field-for-field mirror of the health.ObservedHealth
    dataclass; the verdict word stays ``observed_status`` (never a boolean
    ``healthy`` flag). Two identical follow-up calls over an unchanged log
    agree on every field except the generated_at stamp.

    Route registration order matters: declared before
    /executions/{execution_id} so "health" can never be captured as an
    execution id."""
    snapshot = collect_observed_health(db, now=datetime.now(timezone.utc))
    return ObservedHealthRead.model_validate(snapshot)


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


#
# Helpers
#
def _to_http_error(exc: Exception) -> HTTPException:
    """http_status-driven mapping on the typed exception family:
    404 not-found, 409 conflicts; anything unclassified stays a 500. The
    detail carries the exception class name and message — never the token."""
    status = getattr(exc, "http_status", 500)
    return HTTPException(
        status_code=status,
        detail={"error": type(exc).__name__, "message": str(exc)},
    )


def _render_execution(result: ExecutionResult) -> ExecutionRead:
    """Serialize before commit: the Service's in-memory rows carry every
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
    """Malformed ids map to the same 404 as unknown ids."""
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Execution not found") from exc
