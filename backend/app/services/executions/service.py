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
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.ai_response_approval import AIResponseApproval
from app.models.ai_response_recommendation import AIResponseRecommendation
from app.models.event_risk import EventRisk
from app.models.execution_log import ExecutionLog
from app.services.executions.base import ResponseExecutor
from app.services.executions.binding import (
    BINDING_DETAIL_KEY,
    TERMINAL_REFERENCE_KEY,
    DispatchBindingContributor,
    build_dispatch_binding,
)
from app.services.executions.exceptions import (
    ExecutorConfigError,
    ExecutorOutcomeViolation,
)
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
from app.services.executions.registry import RECOGNIZED_ADAPTER_NAMES
from app.services.executions.secrets import redact_detail
from app.services.executions.state import derive_execution_state

if TYPE_CHECKING:  # annotation-only: the Service depends on record(), not the class
    from app.services.executions.durable_dispatch import DurableDispatchAttemptStore
from app.services.executions.compensation_binding import (
    COMPENSATION_REFERENCE_KEY,
    CompensationBindingContributor,
    build_compensation_binding,
)
from app.services.executions.durable_compensation import (
    DurableCompensationAttemptStore,
)

#: Conflict family -> HTTP status the future API layer maps (frozen here
#: so 3.1.7 never re-shapes the Service exceptions). 401/422 stay in the
#: HTTP layer and never reach this module.
HTTP_CONFLICT = 409
HTTP_NOT_FOUND = 404
HTTP_SERVICE_UNAVAILABLE = 503

#: FROZEN CLAUSE (3.1.6 acceptance review; RC2 / H-2 re-implementation):
#: created_at must be a SERVER/database-generated timestamp — the client may
#: never supply or roll it back — and the frozen derived-state ordering
#: ``created_at DESC, id DESC`` must stay deterministic on every write path.
#:
#: RC2 / H-2: the pre-RC2 process-global high-water stamp is GONE. It was
#: neither thread-safe (a read-modify-write race could hand two rows the SAME
#: stamp) nor correct across workers (each process saw only its own history),
#: so ordering correctness silently depended on "one process, no concurrency".
#: Ordering is now DATABASE-LEVEL:
#:   * ``created_at`` comes from the DATABASE at INSERT (SQLite:
#:     CURRENT_TIMESTAMP; PostgreSQL production: ``clock_timestamp()`` —
#:     per-statement real time set by migration 0014, never transaction-start
#:     ``now()``), so no caller and no process manufactures timestamps;
#:   * ``id`` is minted by :func:`app.core.ids.uuid7` — a time-ordered UUIDv7
#:     that is strictly increasing within the writing process even for a
#:     same-millisecond burst (and clamps a backward wall-clock step), so the
#:     sanctioned ``(created_at, id)`` tie-break IS the true insertion order,
#:     never a random-uuid lottery.
#: A chain is written by exactly one process (one request owns the one
#: execution_id transaction; duplicates are refused by the frozen unique
#: indexes), so per-chain ordering never needs cross-process coordination;
#: created_at ties — ubiquitous on SQLite's second-precision timestamps — are
#: resolved by the insert-ordered id.
#: Implementation discipline is UNCHANGED: every Execution Service row is
#: written exclusively via _append(); no caller passes or fabricates a
#: timestamp.


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


class DurableStoreRequired(ExecutionServiceError):
    """M4-G §2 fail-closed gate: a RECOGNIZED real external adapter
    (shuffle/wazuh/thehive) was asked to dispatch WITHOUT a durable
    pre-dispatch attempt store (``store=None`` — a DI gap, a config error, or
    a test default). Dispatching anyway would degrade to the flush-only
    pre-M4-F path, firing an external request whose intent was never durably
    committed. This is a server-side wiring fault (503), never a business
    rejection: the adapter is NOT called and no dispatch fact is produced. The
    offline mock is exempt — it makes no external call, so there is no durable
    fact to protect."""

    http_status = HTTP_SERVICE_UNAVAILABLE


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
    # M4-F §1: the durable pre-dispatch attempt carries its OWN unique index on
    # execution_id — a duplicate/concurrent replay is refused at the independent
    # commit BEFORE the adapter runs, mapping to the SAME typed 409 (D14).
    "dispatch_attempt.execution_id": ExecutionIdAlreadyBound,
    "ux_dispatch_attempt_execution_id": ExecutionIdAlreadyBound,
    # M4-G §1: the durable approval-slot reservation — a second execute attempt
    # for the SAME approval_id (two different execution_ids racing one approval)
    # is refused at the independent commit BEFORE the adapter runs, mapping to
    # the SAME typed 409 the G3 pre-check raises (D14 last line, ahead of the wire).
    "dispatch_attempt.approval_id": ApprovalAlreadyExecuted,
    "ux_dispatch_attempt_approval_id": ApprovalAlreadyExecuted,
    # RC2 / C-1: the durable pre-compensation attempt carries its OWN unique
    # indexes — a duplicate/concurrent compensation for the SAME original
    # execution is refused at the independent commit BEFORE the reverse adapter
    # runs (the C-1 reservation), and a duplicate compensation execution_id is
    # refused the same way; both map to the SAME typed 409 the pre-check raises
    # (D14 last line, ahead of the wire).
    "compensation_attempt.original_execution_id": ExecutionAlreadyCompensated,
    "ux_compensation_attempt_original_execution_id": ExecutionAlreadyCompensated,
    "compensation_attempt.execution_id": ExecutionIdAlreadyBound,
    "ux_compensation_attempt_execution_id": ExecutionIdAlreadyBound,
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

    ``created_at`` is NOT passed: the DATABASE stamps it at INSERT (RC2 / H-2
    — see the frozen-clause note above). Chain ordering is guaranteed by the
    database timestamp plus the insert-ordered uuid7 ``id`` (the sanctioned
    (created_at, id) tie-break), never by process-global clock state.

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


def _original_dispatch_attempt_id(
    original_rows: Sequence[ExecutionLog],
) -> uuid.UUID | None:
    """The compensated chain's forward durable-attempt reference, or ``None``.

    ``_rows_for_execution`` returns the chain NEWEST-FIRST; the first
    succeeded/failed row is the chain's terminal, which carries the forward
    binding reference (``detail[TERMINAL_REFERENCE_KEY]``) when the original
    ran through a durable store. Old history / store-less mock runs carry no
    reference and yield ``None`` — an honest UNKNOWN, never back-filled. A
    malformed reference is treated exactly like an absent one (fail-closed).
    """
    for row in original_rows:
        if row.decision not in ("succeeded", "failed"):
            continue
        detail = row.detail if isinstance(row.detail, dict) else {}
        reference = detail.get(TERMINAL_REFERENCE_KEY)
        if not isinstance(reference, str):
            return None
        try:
            return uuid.UUID(reference)
        except (ValueError, AttributeError, TypeError):
            return None
    return None


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
    dispatch_attempt_store: DurableDispatchAttemptStore | None = None,
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

    M4-F §1: ``dispatch_attempt_store``, when provided, durably commits the
    pre-dispatch binding on an INDEPENDENT transaction BEFORE the external
    request (surviving a caller rollback / terminal-write failure / crash). It
    does NOT breach the frozen "the Service NEVER calls commit()" clause — that
    protects the CALLER's business transaction, which still commits in the API
    layer; the store owns a SEPARATE session (the outcomes-service precedent).
    Omitted (None) -> the exact pre-M4-F flush-only path.
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

    # Guards + Policy passed -> build the dispatch DTO FIRST, persist the immutable
    # pre-dispatch BINDING in the dispatched row (M4-A: recorded BEFORE the external
    # request so it survives EVERY outcome), then the adapter, then the terminal row
    # (which REFERENCES the same binding, never re-writes it).
    dispatch = ExecutionDispatch(
        execution_id=execution_id,
        action=action,
        target=target,
        approval_id=approval_id,
    )
    # M4-A forward dispatch binding (Amendment §12.2 A1-revised). dispatch_started_at
    # is a SERVER-CLOCK fact recorded in the detail — the SAME precedent as the
    # policy-evaluation time computed above — NOT the audit-row timestamp column,
    # which the DATABASE stamps at INSERT since RC2 / H-2 (the frozen stamping
    # clause now lives in the frozen-clause note above). Contributor facts come
    # ONLY from an adapter that
    # opts into the DispatchBindingContributor protocol (the offline mock does not)
    # and are merged through binding.py's explicit whitelist.
    dispatch_started_at = datetime.now(timezone.utc)
    contributor_facts = (
        executor.dispatch_binding_facts(dispatch)
        if isinstance(executor, DispatchBindingContributor)
        else None
    )
    binding = build_dispatch_binding(
        execution_id=execution_id,
        approval_id=approval_id,
        adapter=executor.name,
        action=action,
        target=target,
        approval_status=(
            approval.status if isinstance(approval.status, str) else None
        ),
        dispatch_started_at=dispatch_started_at,
        contributor_facts=contributor_facts,
    )
    # M4-G §2 — FAIL-CLOSED DURABLE-STORE GATE. A RECOGNIZED real external adapter
    # (shuffle/wazuh/thehive) MUST NOT degrade to the flush-only pre-M4-F path: if
    # the durable store is absent (store=None — a DI gap, a config error, or a test
    # default), refuse BEFORE the external request rather than fire an adapter whose
    # dispatch intent was never durably committed. This is a server-side wiring
    # fault (503), not a business rejection — no dispatch fact is produced and the
    # adapter is never called. The offline mock is exempt (no external call, so no
    # durable fact to protect); isolated tests exercise the real durable path by
    # injecting a store explicitly.
    if executor.name in RECOGNIZED_ADAPTER_NAMES and dispatch_attempt_store is None:
        raise DurableStoreRequired(
            f"Executor '{executor.name}' is a recognized external adapter and "
            "requires a durable dispatch-attempt store before any external "
            "request; none was provided (store=None). Refusing to degrade to the "
            "flush-only path (M4-G §2 fail-closed)."
        )
    # M4-F §1 — DURABLE PRE-DISPATCH COMMIT. Before ANY external request, commit
    # the dispatch intent + target binding on an INDEPENDENT transaction (a
    # separate Session/connection) so it SURVIVES a caller rollback, a
    # terminal-write failure or a process crash — the M4 review's "flush 不等于
    # 持久提交" fix. store=None (the default) keeps the pre-M4-F path byte-identical.
    # A persistence failure means the adapter is NEVER called: a duplicate
    # execution_id at the durable commit is the D14 race last line and maps to the
    # SAME typed 409; any other failure propagates and aborts before dispatch.
    if dispatch_attempt_store is not None:
        try:
            dispatch_attempt_store.record(binding)
        except IntegrityError as exc:
            _translate_integrity_error(exc, session)
    _append(
        session,
        execution_id=execution_id,
        approval_id=approval_id,
        decision="dispatched",
        direction="execute",
        action=action,
        target=target,
        operator=operator,
        detail={
            "executor": executor.name,
            BINDING_DETAIL_KEY: binding.to_detail(),
        },
    )
    session.flush()

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
    # M4-A: the terminal row REFERENCES the ONE pre-dispatch binding (attempt_id) so
    # success / timeout / connection failure / HTTP error / response loss all stay
    # bound to the same immutable attempt identity — the binding is never re-written.
    detail[TERMINAL_REFERENCE_KEY] = binding.attempt_id
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
    compensation_attempt_store: DurableCompensationAttemptStore | None = None,
) -> ExecutionResult:
    """Run one complete compensation chain (design §9): a FRESH
    execution_id undoing a settled forward execution; approval_id, action
    and target are inherited SERVER-SIDE from the original rows — the
    client supplies nothing but Intent identity.

    RC2 / C-1: ``compensation_attempt_store``, when provided, durably commits
    the immutable reverse binding on an INDEPENDENT transaction BEFORE the
    external compensation request (surviving a caller rollback / terminal-write
    failure / crash — the reverse mirror of the M4-F §1 fix). It does NOT
    breach the frozen "the Service NEVER calls commit()" clause — that protects
    the CALLER's business transaction; the store owns a SEPARATE session. A
    persistence failure or a duplicate original_execution_id means the adapter
    is NEVER called. A recognized real adapter WITHOUT a store refuses
    fail-closed before the wire call (the reverse mirror of the M4-G §2 gate);
    the offline mock stays exempt (no external call)."""
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

    # RC2 / C-1 — FAIL-CLOSED DURABLE-STORE GATE (the reverse mirror of M4-G §2).
    # A recognized real external adapter (shuffle / wazuh) whose compensation is
    # actually dispatchable MUST NOT degrade to the flush-only pre-C-1 path:
    # refuse BEFORE the reverse external request rather than fire a compensation
    # whose intent was never durably committed. This is a server-side wiring
    # fault (503), not a business rejection — no dispatch fact is produced and
    # the adapter is never called. The offline mock is exempt (DryRun, no
    # external call); TheHive never reaches this point (supports_compensation()
    # is False -> the capability check above already ended the chain).
    if (
        executor.name in RECOGNIZED_ADAPTER_NAMES
        and compensation_attempt_store is None
    ):
        raise DurableStoreRequired(
            f"Executor '{executor.name}' is a recognized external adapter and "
            "requires a durable compensation-attempt store before any external "
            "reverse request; none was provided (store=None). Refusing to "
            "degrade to the flush-only compensation path (RC2 C-1 fail-closed)."
        )

    dispatch = ExecutionDispatch(
        execution_id=execution_id,
        action=action,
        target=target,
        approval_id=approval_id,
    )
    # RC2 / C-1 — DURABLE PRE-COMPENSATION COMMIT (the reverse mirror of M4-F §1).
    # Before ANY external reverse request, commit the compensation intent +
    # reverse binding on an INDEPENDENT transaction (a separate Session /
    # connection) so it SURVIVES a caller rollback, a terminal-write failure or
    # a process crash. A persistence failure — or a duplicate
    # original_execution_id (the durable one-compensation-per-original
    # reservation) — means the adapter is NEVER called: the duplicate maps to
    # the SAME typed 409 the pre-check raises; any other failure propagates and
    # aborts before the wire call.
    #
    # RC2-R §3.1: the reverse target facts come from the SEPARATE
    # CompensationBindingContributor protocol (the reverse mirror of
    # DispatchBindingContributor) — NEVER hard-wired from the forward
    # contributor. A contributor that cannot establish its facts (missing
    # reverse mapping / unsafe target) refuses here: the chain ends as
    # compensation_failed with ZERO outbound.
    prepared_at = datetime.now(timezone.utc)
    dispatch_started_at = datetime.now(timezone.utc)
    try:
        contributor_facts = (
            executor.compensation_binding_facts(dispatch)
            if isinstance(executor, CompensationBindingContributor)
            else None
        )
        binding = build_compensation_binding(
            execution_id=execution_id,
            original_execution_id=compensates_execution_id,
            original_dispatch_attempt_id=_original_dispatch_attempt_id(original_rows),
            approval_id=approval_id,
            adapter=executor.name,
            action=action,
            target=target,
            operator=operator,
            reason=comment,
            original_outcome_state=derived,
            prepared_at=prepared_at,
            dispatch_started_at=dispatch_started_at,
            contributor_facts=contributor_facts,
        )
    except ExecutorConfigError as config_error:
        # The reverse target could not be honestly bound (missing reverse
        # configuration, unsafe target, adapter mismatch) — the adapter is
        # NEVER called and the chain ends as a terminal compensation_failed.
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="compensation_failed",
            direction="compensate",
            action=action,
            target=target,
            operator=operator,
            detail=redact_detail(
                {
                    "source": "binding",
                    "classification": "binding_missing",
                    "reason": str(config_error),
                }
            ),
            compensates_execution_id=compensates_execution_id,
        )
        session.flush()
        return _result(_rows_for_execution(session, execution_id))
    if compensation_attempt_store is not None:
        try:
            compensation_attempt_store.record(binding)
        except IntegrityError as exc:
            _translate_integrity_error(exc, session)
    violation_message: str | None = None
    try:
        # RC2-R §3.1: a contributor CONSUMES the committed binding (the wire
        # call uses the BOUND reverse operation + endpoint — never a re-read of
        # mutable settings). Any drift discovered at the send boundary refuses
        # fail-closed BEFORE transport, mapped below to a terminal failure.
        if isinstance(executor, CompensationBindingContributor):
            outcome = parse_execution_outcome(
                executor.compensate_with_binding(dispatch, binding)
            )
        else:
            outcome = parse_execution_outcome(executor.compensate(dispatch))
    except ExecutorOutcomeViolation as violation:  # D9 — platform judges
        outcome = None
        violation_message = str(violation)
    except ExecutorConfigError as config_error:
        # Binding-vs-configuration drift discovered at send time: the adapter
        # refused BEFORE any outbound (zero external call). The chain ends as
        # a terminal compensation_failed; the durable attempt survives for
        # manual, read-only reconciliation.
        _append(
            session,
            execution_id=execution_id,
            approval_id=approval_id,
            decision="compensation_failed",
            direction="compensate",
            action=action,
            target=target,
            operator=operator,
            detail=redact_detail(
                {
                    "source": "binding",
                    "classification": "binding_mismatch",
                    "reason": str(config_error),
                    COMPENSATION_REFERENCE_KEY: binding.compensation_attempt_id,
                }
            ),
            compensates_execution_id=compensates_execution_id,
        )
        session.flush()
        return _result(_rows_for_execution(session, execution_id))

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
    # RC2 / C-1: the terminal compensation row REFERENCES the ONE durable
    # pre-compensation attempt (compensation_attempt_id) so success / timeout /
    # connection failure / HTTP error / response loss all stay bound to the
    # same immutable attempt identity — the binding is never re-written (the
    # reverse mirror of M4-A's terminal reference).
    detail[COMPENSATION_REFERENCE_KEY] = binding.compensation_attempt_id
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
