"""Execute / Compensation Service (Phase 3.1.6, design §9; Execution
Policy wired in 3.3.2.4, design B-3).

The first layer that produces REAL execution facts, wiring everything
frozen so far into one chain:

    Approval + Recommendation snapshot + State Machine (3.1.3)
    + Guard (3.1.4) + Execution Policy (3.3.2) + ResponseExecutor
    (3.1.5) -> execution_log rows.

Forward-chain order (frozen, B-3):

    requested -> Guard -> Policy -> dispatched -> Executor -> terminal

The Policy is the LAST deterministic governance verdict BEFORE
execution, never an execution-result processor: a policy refusal lands
as ``requested -> guard_rejected`` with ``detail.source = "policy"``
(state vocabulary unchanged — there is no policy_rejected word) and the
Executor receives ZERO calls. Guard refusals carry detail.source =
"guard" so the audit trail splits guard_rejected rows by provenance.

Transaction discipline (frozen):
- add() + flush() only — the Service NEVER calls commit(); the API layer
  owns the transaction boundary (AI-service lineage).
- One Execute Intent is ONE business transaction:
    requested -> [guard_rejected]            (D13, same transaction)
    requested -> dispatched -> succeeded|failed
  Every row lands via flush inside the caller's open transaction.
- `requested` lands BEFORE the guards (D12); guard rejections append
  `guard_rejected` in the SAME transaction; capability/lifecycle pass
  appends `dispatched`, then the adapter runs, then the terminal row.

Four untrusted inputs, four frozen answers:
- action / target: NEVER from the client — resolved exclusively from the
  approved recommendation's server-side snapshot.
- approval_id: client-supplied but re-resolved against the database.
- execution_id: idempotency / execution identity only — it can never
  decide approval, action, target or direction; replays are 409.

Concurrency (D14): the G3 pre-check is the FIRST line; the partial unique
indexes are the LAST line. An IntegrityError at flush is translated into
the same typed conflict family the pre-check raises, then the transaction
is rolled back — the API maps either to 409.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.ai_response_approval import AIResponseApproval
from app.models.ai_response_recommendation import AIResponseRecommendation
from app.models.event_risk import EventRisk
from app.models.execution_log import ExecutionLog
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import ExecutorOutcomeViolation
from app.services.executions.guard import (
    ApprovalAlreadyExecuted,
    ApprovalNotFound,
    ExecutionIdAlreadyBound,
    GuardRejection,
    check_approval_binding,
    check_executor_capability,
    check_lifecycle,
)
from app.services.executions.models import ExecutionDispatch
from app.services.executions.policy import (
    ExecutionPolicy,
    PolicyContext,
    policy_from_settings,
)
from app.services.executions.protocol import parse_execution_outcome
from app.services.executions.secrets import redact_detail
from app.services.executions.state import derive_execution_state

#: Conflict family -> HTTP status the future API layer maps (frozen here
#: so 3.1.7 never re-shapes the Service exceptions). 401/422 stay in the
#: HTTP layer and never reach this module.
HTTP_CONFLICT = 409
HTTP_NOT_FOUND = 404

#: High-water mark for audit timestamps. One business transaction writes
#: the whole chain, and (a) SQLite's CURRENT_TIMESTAMP is second-precision
#: while PostgreSQL's now() is transaction-time — both would leave every
#: row of a chain on the SAME timestamp; (b) the OS clock itself can tie
#: (Windows ~15ms resolution) or even regress. Either effect would reduce
#: the frozen derived-state rule (created_at DESC, id DESC) to a RANDOM
#: uuid4 tie-break. The high-water mark guarantees strictly increasing
#: server-clock stamps row by row — still server time only, never client
#: input (constraint 8; same precedent as approval reviewed_at).
#:
#: FROZEN CLAUSE (3.1.6 acceptance review): created_at must be a
#: server-generated, strictly monotonically increasing timestamp within a
#: single execution chain; the client may never supply or roll it back.
#: Implementation discipline: the stamping lives ENTIRELY inside _append()
#: — no caller passes created_at and no caller manufactures timestamps;
#: every future Execution Service writes rows exclusively via _append().
_LAST_AUDIT_STAMP: datetime | None = None


def _next_audit_timestamp() -> datetime:
    global _LAST_AUDIT_STAMP
    candidate = datetime.now(timezone.utc)
    if _LAST_AUDIT_STAMP is not None and candidate <= _LAST_AUDIT_STAMP:
        candidate = _LAST_AUDIT_STAMP + timedelta(microseconds=1)
    _LAST_AUDIT_STAMP = candidate
    return candidate


#: Original states eligible for compensation — a compensation undoes an
#: execution that reached a forward terminal state.
COMPENSATABLE_STATES = frozenset({"succeeded", "failed"})


# --------------------------------------------------------------------------
# Typed exception family (frozen for the 3.1.7 API mapping)
#
# The forward-execution conflicts reuse the 3.1.4 Guard classes verbatim
# (ApprovalAlreadyExecuted / ExecutionIdAlreadyBound / ApprovalNotFound,
# each carrying its http_status) — ONE conflict family per concern, both
# for the Service pre-check and the DB-index translation below. The
# compensation-specific conflicts are new in 3.1.6.
# --------------------------------------------------------------------------
class ExecutionServiceError(Exception):
    """Base class of every Service-layer error (never silent failures)."""


class ExecutionNotFound(ExecutionServiceError):
    """No execution_log rows exist for the given execution_id — 404, no
    new row. Compensation cannot target a phantom execution."""

    http_status = HTTP_NOT_FOUND


class ExecutionConflictError(ExecutionServiceError):
    """Base of the compensation-side 409 conflicts. The forward-execution
    conflicts (approval slot / execution_id identity) stay in the 3.1.4
    Guard family — every 409 class carries ``http_status = 409`` so the
    API maps them uniformly (D14: pre-check and DB index raise the SAME
    typed exceptions)."""

    http_status = HTTP_CONFLICT


class ExecutionAlreadyCompensated(ExecutionConflictError):
    """One original execution -> at most ONE compensation request
    (partial unique index on compensates_execution_id, constraint 3)."""


class OriginalExecutionNotTerminal(ExecutionConflictError):
    """Compensation targets an execution whose derived state is not
    succeeded/failed — there is nothing settled to undo yet."""

    def __init__(self, message: str, derived_state: str | None = None):
        super().__init__(message)
        self.derived_state = derived_state


class CompensationOfCompensation(ExecutionConflictError):
    """The targeted execution is itself a compensation chain — undoing an
    undo is not part of the frozen state machine."""


#: Conflict marker -> typed conflict. SQLite reports partial-index
#: violations by COLUMN ("UNIQUE constraint failed: execution_log.<col>"),
#: PostgreSQL by INDEX name — both marker sets are covered; each column
#: participates in exactly ONE unique index here, so the mapping stays
#: unambiguous across dialects (D14 last line).
_CONFLICT_MARKERS = {
    "execution_log.execution_id": ExecutionIdAlreadyBound,
    "ux_execution_log_execution_id_requested": ExecutionIdAlreadyBound,
    "execution_log.approval_id": ApprovalAlreadyExecuted,
    "ux_execution_log_approval_id_execute": ApprovalAlreadyExecuted,
    "execution_log.compensates_execution_id": ExecutionAlreadyCompensated,
    "ux_execution_log_compensates_requested": ExecutionAlreadyCompensated,
}


def _translate_integrity_error(exc: IntegrityError, session: Session) -> None:
    """Map a partial-unique-index violation at flush into the SAME typed
    conflict the Service pre-check would raise, then roll the transaction
    back (it is unusable afterwards). Re-raises unknown violations."""
    text = str(exc.orig or exc)
    session.rollback()
    for marker, exception_class in _CONFLICT_MARKERS.items():
        if marker in text:
            raise exception_class(
                "Concurrent execution conflict detected by the database "
                f"({marker}); the first execution's facts stand"
            ) from exc
    raise exc


# --------------------------------------------------------------------------
# Result DTO
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ExecutionResult:
    """Service verdict for one Intent — what the API renders (3.1.7).

    ``chain`` is the ordered decision sequence of THIS execution_id
    (e.g. ["requested", "dispatched", "succeeded"]); ``final_decision``
    is the derived state of the chain; ``rows`` the full audit rows."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID
    direction: str
    final_decision: str
    chain: tuple[str, ...]
    rows: tuple[ExecutionLog, ...]


def _result(rows: Sequence[ExecutionLog]) -> ExecutionResult:
    # rows may arrive in derived ordering (DESC) — rebuild chronological
    # order for the chain view (created_at is microsecond-stamped below,
    # so it alone orders a chain deterministically).
    ordered = sorted(rows, key=lambda row: (row.created_at, row.id))
    return ExecutionResult(
        execution_id=ordered[0].execution_id,
        approval_id=ordered[0].approval_id,
        direction=ordered[0].direction,
        final_decision=ordered[-1].decision,
        chain=tuple(row.decision for row in ordered),
        rows=tuple(ordered),
    )


def _append(
    session: Session,
    *,
    execution_id: uuid.UUID,
    approval_id: uuid.UUID,
    decision: str,
    direction: str,
    action: str,
    target: str,
    operator: str,
    detail: dict,
    compensates_execution_id: uuid.UUID | None = None,
) -> ExecutionLog:
    """Append one audit row and flush (add-only, never commit).

    ``created_at`` is stamped HERE with the server clock through the
    high-water mark above instead of the CURRENT_TIMESTAMP server default
    — see _next_audit_timestamp for why chain rows need strictly
    increasing stamps.

    3.2.2 audit gate: EVERY detail passes the secret-boundary *** gate
    at this single write point — a credential can never reach
    execution_log no matter what an adapter's outcome carried."""
    row = ExecutionLog(
        execution_id=execution_id,
        approval_id=approval_id,
        decision=decision,
        direction=direction,
        action=action,
        target=target,
        operator=operator,
        detail=redact_detail(detail),
        compensates_execution_id=compensates_execution_id,
        created_at=_next_audit_timestamp(),
    )
    session.add(row)
    return row


def _rows_for_execution(session: Session, execution_id: uuid.UUID) -> list[ExecutionLog]:
    # Frozen derived-state ordering (constraint 8): created_at DESC, id
    # DESC. SQLite's CURRENT_TIMESTAMP is second-precision, so rows of one
    # synchronous chain share created_at and the id tie-breaker decides —
    # id DESC puts the newest row first, exactly as derive expects.
    return list(
        session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.execution_id == execution_id)
            .order_by(ExecutionLog.created_at.desc(), ExecutionLog.id.desc())
        )
    )


def _rows_for_approval(session: Session, approval_id: uuid.UUID) -> list[ExecutionLog]:
    return list(
        session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.approval_id == approval_id)
            .order_by(ExecutionLog.created_at.asc(), ExecutionLog.id.asc())
        )
    )


def _resolve_snapshot(recommendation) -> tuple[str, str]:
    """Read action/target from the approved recommendation's snapshot.
    Raises GuardRejection (recorded as guard_rejected by the caller) when
    the snapshot cannot yield exactly one executable fact pair."""
    items = recommendation.recommendations or []
    if not items:
        raise GuardRejection(
            "recommendation_missing",
            f"Recommendation {recommendation.id} carries an empty snapshot; "
            f"action/target are server-side facts only",
        )
    item = items[0]
    action = item.get("action") if isinstance(item, dict) else None
    target = item.get("target") if isinstance(item, dict) else None
    if not action or not target:
        raise GuardRejection(
            "recommendation_missing",
            f"Recommendation {recommendation.id} snapshot lacks an "
            f"action/target pair to execute",
        )
    return action, target


def _terminal_outcome_detail(outcome) -> dict:
    detail = dict(outcome.detail)
    detail["raw_response"] = outcome.raw_response
    return detail


def _server_risk_score(session: Session, recommendation) -> int | None:
    """The ONE risk fact the Execution Policy may read: EventRisk.score
    of the recommendation's event — the live authoritative assessment.
    READ-ONLY: the Service never recomputes risk and never writes
    EventRisk / Incident. None = the event has no risk assessment yet
    (the Policy judges a missing fact fail-closed)."""
    if recommendation is None:
        return None
    risk = session.scalar(
        select(EventRisk).where(
            EventRisk.alert_group_id == recommendation.alert_group_id
        )
    )
    return risk.score if risk is not None else None


def _intent_detail(executor: ResponseExecutor, comment: str | None) -> dict:
    """Detail of the chain's FIRST row: which adapter was selected plus
    the optional operator comment from the HTTP Intent (3.1.7). The
    comment is audit metadata only — it can never influence action,
    target or any guard verdict."""
    detail = {"executor": executor.name}
    if comment:
        detail["comment"] = comment
    return detail


# --------------------------------------------------------------------------
# Forward execution
# --------------------------------------------------------------------------
def execute_response(
    session: Session,
    *,
    approval_id: uuid.UUID,
    execution_id: uuid.UUID,
    operator: str,
    executor: ResponseExecutor,
    comment: str | None = None,
    policy: ExecutionPolicy | None = None,
) -> ExecutionResult:
    """Run one complete forward execution chain (design §9).

    The caller's open transaction receives every row via flush; NOTHING
    is committed here. Business rejections RETURN a guard_rejected result
    (D13 audit fact); 404 / 409 conditions RAISE typed exceptions with
    NO log row.

    3.3.2.4 (B-3): ``policy`` is the deployment's ExecutionPolicy; when
    omitted it is built from application settings (disabled by default
    -> the exact frozen 3.1/3.2 behavior). Tests inject a policy to
    drive refusal paths deterministically.
    """
    approval = session.get(AIResponseApproval, approval_id)
    if approval is None:
        # 404 — no execution fact can even be formed: the requested row
        # carries the approval_id foreign key, so existence is a
        # precondition of the fact itself, not a business rejection.
        # ZERO rows land.
        raise ApprovalNotFound(f"Approval {approval_id} not found")
    recommendation = session.get(AIResponseRecommendation, approval.recommendation_id)

    # Server-side snapshot resolution: action/target are born HERE,
    # exclusively from the approved recommendation — never from the
    # client. A broken snapshot defers its rejection to the guard stage
    # below so the chain still reads requested -> guard_rejected (D13).
    pending_rejection: GuardRejection | None = None
    action: str = ""
    target: str = ""
    if recommendation is not None:
        try:
            action, target = _resolve_snapshot(recommendation)
        except GuardRejection as rejection:
            pending_rejection = rejection

    # G3 lifecycle / idempotency PRE-CHECK runs BEFORE any row lands
    # (409 family writes no audit fact): the snapshots are loaded first so
    # the current request's own requested row never counts against its
    # approval slot or its execution_id. The partial unique indexes stay
    # the last line against races (D14).
    prior_approval_rows = _rows_for_approval(session, approval_id)
    prior_execution_rows = _rows_for_execution(session, execution_id)
    check_lifecycle(prior_approval_rows, prior_execution_rows)

    # requested FIRST among the audit rows (D12): Auth+Schema have already
    # passed at the HTTP layer by the time this Service runs; the Intent
    # is an audit fact. Constraint 10 holds by construction: this is the
    # only place execute-direction chains begin.
    try:
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="requested",
            direction="execute",
            action=action,
            target=target,
            operator=operator,
            detail=_intent_detail(executor, comment),
        )
        session.flush()
    except IntegrityError as exc:
        _translate_integrity_error(exc, session)

    # Guards G2 -> G4 (G3 already pre-checked above, pre-insert). Any
    # GuardRejection becomes a guard_rejected row in the SAME transaction
    # (D13); the caller commits both together. 3.3.2.4: the detail's
    # source="guard" tag lets the audit trail split guard_rejected rows
    # from policy refusals (source="policy" below) — same frozen state,
    # distinguishable provenance.
    try:
        if pending_rejection is not None:
            raise pending_rejection
        check_approval_binding(approval, recommendation, action)
        check_executor_capability(executor, action, "execute")
    except GuardRejection as rejection:
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="guard_rejected",
            direction="execute",
            action=action,
            target=target,
            operator=operator,
            detail={
                "source": "guard",
                "code": rejection.code,
                "reason": rejection.reason,
            },
        )
        session.flush()
        return _result(_rows_for_execution(session, execution_id))

    # Execution Policy (3.3.2.4, B-3): the LAST deterministic governance
    # verdict before execution — after every Guard, before dispatch. A
    # refusal reuses the frozen guard_rejected word with detail.source =
    # "policy" (no new state) and the Executor receives ZERO calls.
    # Server-side facts only: the action comes from the approved snapshot,
    # the risk score from the event's EventRisk row (read-only), the time
    # from the SERVER clock (UTC basis) — the client supplies none of
    # these.
    active_policy = (
        policy if policy is not None else policy_from_settings(settings)
    )
    verdict = active_policy.evaluate(
        PolicyContext(
            action=action,
            risk_score=_server_risk_score(session, recommendation),
        ),
        datetime.now(timezone.utc),
    )
    if not verdict.allowed:
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="guard_rejected",
            direction="execute",
            action=action,
            target=target,
            operator=operator,
            detail=verdict.detail(),
        )
        session.flush()
        return _result(_rows_for_execution(session, execution_id))

    # Guards + Policy passed -> dispatched, then the adapter, then the
    # terminal row.
    _append(
        session,
        execution_id=execution_id,
        approval_id=approval_id,
        decision="dispatched",
        direction="execute",
        action=action,
        target=target,
        operator=operator,
        detail={"executor": executor.name},
    )
    session.flush()

    dispatch = ExecutionDispatch(
        execution_id=execution_id,
        action=action,
        target=target,
        approval_id=approval_id,
    )
    violation_message: str | None = None
    try:
        outcome = parse_execution_outcome(executor.execute(dispatch))
    except ExecutorOutcomeViolation as violation:  # D9 — platform judges
        outcome = None
        violation_message = str(violation)

    if outcome is not None:
        decision = "succeeded" if outcome.status == "succeeded" else "failed"
        detail = _terminal_outcome_detail(outcome)
    else:
        decision = "failed"
        detail = {
            "classification": "protocol_violation",
            "violation": violation_message,
            "raw_response": None,
        }
    _append(
        session,
        execution_id=execution_id,
        approval_id=approval_id,
        decision=decision,
        direction="execute",
        action=action,
        target=target,
        operator=operator,
        detail=detail,
    )
    session.flush()
    return _result(_rows_for_execution(session, execution_id))


# --------------------------------------------------------------------------
# Compensation
# --------------------------------------------------------------------------
def compensate_response(
    session: Session,
    *,
    compensates_execution_id: uuid.UUID,
    execution_id: uuid.UUID,
    operator: str,
    executor: ResponseExecutor,
    comment: str | None = None,
) -> ExecutionResult:
    """Run one complete compensation chain (design §9): a FRESH
    execution_id undoing a settled forward execution; approval_id, action
    and target are inherited SERVER-SIDE from the original rows — the
    client supplies nothing but Intent identity."""
    original_rows = _rows_for_execution(session, compensates_execution_id)
    if not original_rows:
        raise ExecutionNotFound(
            f"No execution found for execution_id {compensates_execution_id}"
        )
    if original_rows[0].direction != "execute":
        raise CompensationOfCompensation(
            "The targeted execution is itself a compensation chain; "
            "undoing an undo is not part of the frozen state machine"
        )
    derived = derive_execution_state(original_rows)
    if derived not in COMPENSATABLE_STATES:
        raise OriginalExecutionNotTerminal(
            f"Original execution's derived state is '{derived}'; only "
            f"succeeded/failed executions can be compensated",
            derived_state=derived,
        )
    if any(
        row.decision == "compensation_requested"
        and row.compensates_execution_id == compensates_execution_id
        for row in _rows_for_approval(session, original_rows[0].approval_id)
    ):
        raise ExecutionAlreadyCompensated(
            "This execution already has a compensation request; at most "
            "one compensation per original execution (constraint 3)"
        )

    original = original_rows[0]
    action, target = original.action, original.target
    approval_id = original.approval_id

    try:
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="compensation_requested",
            direction="compensate",
            action=action,
            target=target,
            operator=operator,
            detail=_intent_detail(executor, comment),
            compensates_execution_id=compensates_execution_id,
        )
        session.flush()
    except IntegrityError as exc:
        _translate_integrity_error(exc, session)

    try:
        check_executor_capability(executor, action, "compensate")
    except GuardRejection as rejection:
        # The compensate vocabulary has NO guard_rejected word (frozen
        # CHECK constraint): a capability miss ends the chain as
        # compensation_failed. Frozen semantics (3.1.6 acceptance review):
        # compensation_failed covers BOTH an executor run failure and an
        # unmet pre-capability check, told apart by detail.classification
        # — adapter runs carry the adapter's classification, the
        # capability check carries "capability_missing" below.
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="compensation_failed",
            direction="compensate",
            action=action,
            target=target,
            operator=operator,
            detail={
                "source": "guard",
                "classification": "capability_missing",
                "code": rejection.code,
                "reason": rejection.reason,
            },
            compensates_execution_id=compensates_execution_id,
        )
        session.flush()
        return _result(_rows_for_execution(session, execution_id))

    dispatch = ExecutionDispatch(
        execution_id=execution_id,
        action=action,
        target=target,
        approval_id=approval_id,
    )
    violation_message: str | None = None
    try:
        outcome = parse_execution_outcome(executor.compensate(dispatch))
    except ExecutorOutcomeViolation as violation:  # D9 — platform judges
        outcome = None
        violation_message = str(violation)

    if outcome is not None:
        decision = (
            "compensation_succeeded"
            if outcome.status == "succeeded"
            else "compensation_failed"
        )
        detail = _terminal_outcome_detail(outcome)
    else:
        decision = "compensation_failed"
        detail = {
            "classification": "protocol_violation",
            "violation": violation_message,
            "raw_response": None,
        }
    _append(
        session,
        execution_id=execution_id,
        approval_id=approval_id,
        decision=decision,
        direction="compensate",
        action=action,
        target=target,
        operator=operator,
        detail=detail,
        compensates_execution_id=compensates_execution_id,
    )
    session.flush()
    return _result(_rows_for_execution(session, execution_id))
