"""Durable pre-compensation attempt store (the reverse of durable_dispatch).

WHY IT EXISTS. The forward path commits the immutable dispatch binding on its own
transaction BEFORE ``executor.execute()``. The reverse path had no equivalent —
``compensate_response`` fired ``executor.compensate()`` with only a flushed
``compensation_requested`` row, so a caller rollback, a terminal-write failure or
a process crash AFTER the external reverse request could erase every durable
trace of the attempt while the external effect may already have applied.

WHAT IT DOES. This store commits the compensation intent and the reverse binding
on its own transaction (a separate Session/connection derived from the caller's
bind) BEFORE the external compensation request is sent. Because it is committed
independently of the caller's execution_log transaction, it survives a caller
rollback, a terminal-write failure or a process crash. Recovery then correlates a
committed attempt that has no terminal compensation row -> a manual
reconciliation candidate (never an auto-retry).

COMMIT BOUNDARY. The store does not commit the caller's business transaction: it
owns a separate session and commits only that one — the same precedent as
``durable_dispatch`` and the outcomes services. The caller's execution_log
transaction is untouched; its commit boundary stays in the API layer.

SECRETS. The binding projection passes ``redact_detail`` at this single write
point, and no binding field is a credential (the endpoint is the validated
secret-free base URL; the version is a config declaration, never a liveness
proof).
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import CompensationAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.compensation_binding import (
    COMPENSATION_REFERENCE_KEY,
    CompensationBinding,
)
from app.services.executions.secrets import redact_detail


class DurableCompensationAttemptStore:
    """Commits the pre-compensation reverse binding on its own durable transaction.

Constructed with a SQLAlchemy ``bind`` (an Engine — in production the API
layer passes ``db.get_bind()``; in tests a file-backed engine). ``record``
opens an independent Session on that bind, INSERTs the append-only
``CompensationAttempt`` row and commits it, then closes. A duplicate
``original_execution_id`` (a replay / concurrent race — a unique index allows
one durable compensation per original execution) raises ``IntegrityError`` —
the caller must treat that as "do not emit the external reverse request".
"""

    def __init__(self, bind) -> None:
        self._bind = bind

    def record(self, binding: CompensationBinding) -> None:
        """Durably commit ``binding`` BEFORE the external compensation request is sent.

Returns ``None`` (the row is committed and the session closed, so no ORM
object is handed back). On any failure the independent session is rolled
back and the exception propagates, so the caller never proceeds to the
external adapter when the durable pre-compensation fact did not commit.
"""
        detail = redact_detail(binding.to_detail())
        prepared = binding.prepared_instant() or datetime.now(timezone.utc)
        started_at = binding.started_at() or prepared
        row = CompensationAttempt(
            compensation_attempt_id=uuid.UUID(binding.compensation_attempt_id),
            execution_id=uuid.UUID(binding.execution_id),
            original_execution_id=uuid.UUID(binding.original_execution_id),
            original_dispatch_attempt_id=(
                uuid.UUID(binding.original_dispatch_attempt_id)
                if binding.original_dispatch_attempt_id
                else None
            ),
            approval_id=uuid.UUID(binding.approval_id),
            adapter=binding.adapter,
            reverse_action=binding.reverse_action,
            target=binding.target,
            endpoint=binding.endpoint,
            operator=binding.operator,
            reason=binding.reason,
            original_outcome_state=binding.original_outcome_state,
            prepared_at=prepared,
            dispatch_started_at=started_at,
            detail=detail,
            # id / recorded_at are left unset so the model defaults apply
            # (append-only).
        )
        # An independent Session on its own connection: committing here (not on
        # the caller's session) is what makes the attempt durable across the
        # caller's rollback / terminal-write failure / crash. The original
        # IntegrityError is re-raised unwrapped so the Execution Service can
        # translate a duplicate original_execution_id into its typed 409 — the
        # store never hides it.
        session = Session(self._bind)
        try:
            session.add(row)
            session.flush()
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            raise
        finally:
            session.close()


# execution_log decisions of the compensation chain that carry a terminal audit
# for an attempt's reverse dispatch. A terminal settles a compensation attempt
# only when all of the attempt's immutable durable facts agree — its ``detail``
# references that attempt's ``compensation_attempt_id``
# (``COMPENSATION_REFERENCE_KEY``) and the terminal row's ``execution_id``
# equals the attempt's and its ``approval_id`` equals the attempt's. Never by
# the attempt id alone, so a stale / mis-attributed / cross-execution terminal
# cannot mask a still-pending compensation attempt. ``compensation_requested``
# rows are not terminal and never settle an attempt.
_COMPENSATION_TERMINAL_DECISIONS = ("compensation_succeeded", "compensation_failed")


class CompensationRecoveryDisposition(str, Enum):
    """The read-only classification of a committed compensation attempt during
recovery. The three states stay distinct and are never collapsed into one
another:

* ``TERMINAL_AUDIT_PRESENT`` — a committed terminal compensation row
references this attempt's ``compensation_attempt_id`` and shares its
``execution_id`` + ``approval_id``. The compensation audit is settled
(``compensation_succeeded`` / ``compensation_failed``), but this is an
audit fact about what the service recorded, not a confirmation of the
external world's reverse effect. A ``compensation_failed`` terminal is
never ``confirmed_failure``: the external reverse action may still have
landed (a timeout after the effect applied, a lost response).
* ``DISPATCH_STATUS_UNKNOWN`` — a committed attempt with no terminal that
agrees on all its immutable facts: "emitted but no reliable terminal".
The external reverse effect is unknown; this is a manual, read-only
human-reconciliation candidate, never an auto-retry / re-compensation /
re-dispatch, and never a fabricated ``compensation_succeeded`` row.
* ``EXTERNAL_EFFECT_CONFIRMED`` — the external reverse effect was
authoritatively confirmed. This state lives only in the Outcome layer,
produced only by the authoritative Manual Reconcile / trusted-reader
proof path. The recovery read never produces it.
"""

    TERMINAL_AUDIT_PRESENT = "terminal_audit_present"
    DISPATCH_STATUS_UNKNOWN = "dispatch_status_unknown"
    EXTERNAL_EFFECT_CONFIRMED = "external_effect_confirmed"


@dataclass(frozen=True, slots=True)
class CompensationRecovery:
    """The read-only recovery classification of one committed compensation attempt.

The identity facts (``adapter`` / ``reverse_action`` / ``target``) are the
durable attempt's immutable snapshot, never back-filled from the current
config. This record carries no authorization power: it is evidence for a
human operator, who reconciles through the existing Manual Reconcile path.
"""

    compensation_attempt_id: uuid.UUID
    execution_id: uuid.UUID
    original_execution_id: uuid.UUID
    approval_id: uuid.UUID
    adapter: str
    reverse_action: str
    target: str
    disposition: CompensationRecoveryDisposition
    # The terminal audit decision (``compensation_succeeded`` /
    # ``compensation_failed``) when a terminal agrees on all this attempt's
    # immutable facts, else ``None``. An audit fact only — never an
    # external-effect confirmation.
    audit_decision: str | None


@dataclass(frozen=True, slots=True)
class _CompensationTerminalRef:
    """One committed terminal compensation row's immutable correlation facts,
as read for recovery: the ``execution_id`` / ``approval_id`` the row was
written under and its terminal ``decision``. Whether the ref actually
settles a given ``CompensationAttempt`` is decided by
:func:`_settling_compensation_decision`."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID | None
    decision: str


def _compensation_terminal_refs_by_attempt(
    session: Session,
) -> dict[str, list[_CompensationTerminalRef]]:
    """Group every committed terminal compensation row that references an
attempt (via ``COMPENSATION_REFERENCE_KEY``) by its canonical referenced
``compensation_attempt_id`` (str).

Read-only. A non-str / malformed reference is skipped (fail-closed — settles
nothing). Rows are scanned oldest-first so the latest matching terminal wins.
"""
    refs: dict[str, list[_CompensationTerminalRef]] = {}
    terminals = session.scalars(
        select(ExecutionLog)
        .where(ExecutionLog.decision.in_(_COMPENSATION_TERMINAL_DECISIONS))
        .order_by(ExecutionLog.created_at, ExecutionLog.id)
    ).all()
    for row in terminals:
        detail = row.detail if isinstance(row.detail, dict) else {}
        reference = detail.get(COMPENSATION_REFERENCE_KEY)
        if not isinstance(reference, str):
            continue
        try:
            key = str(uuid.UUID(reference))  # canonicalize the reference
        except (ValueError, AttributeError, TypeError):
            continue  # a malformed reference settles nothing (fail-closed)
        refs.setdefault(key, []).append(
            _CompensationTerminalRef(
                execution_id=row.execution_id,
                approval_id=row.approval_id,
                decision=row.decision,
            )
        )
    return refs


def _settling_compensation_decision(
    attempt: CompensationAttempt, refs: dict[str, list[_CompensationTerminalRef]]
) -> str | None:
    """The terminal audit decision that settles ``attempt``, else ``None``.

A terminal settles the attempt only when all of the attempt's immutable
durable facts agree with the terminal row:

* ``terminal.execution_id == attempt.execution_id`` — a cross-execution
terminal that merely references this ``compensation_attempt_id`` cannot
settle it;
* the referenced ``compensation_attempt_id`` equals
``attempt.compensation_attempt_id`` (the dict key); and
* when the terminal carries an ``approval_id`` (a committed
``execution_log`` row always does), ``terminal.approval_id ==
attempt.approval_id``.

Any missing / malformed / cross-execution / cross-approval / wrong-attempt
reference is fail-closed -> ``None`` -> DISPATCH_STATUS_UNKNOWN (the safe
direction). Oldest-first scan, so the latest fully-matching terminal's
decision wins.
"""
    candidates = refs.get(str(attempt.compensation_attempt_id))
    if not candidates:
        return None
    decision: str | None = None
    for ref in candidates:
        if ref.execution_id != attempt.execution_id:
            continue  # cross-execution mis-reference cannot settle
        if ref.approval_id is not None and ref.approval_id != attempt.approval_id:
            continue  # cross-approval mis-reference cannot settle
        decision = ref.decision  # all immutable facts agree; latest match wins
    return decision


def _committed_compensations(session: Session) -> Sequence[CompensationAttempt]:
    """Every committed durable compensation attempt, oldest-first (a stable
recovery order)."""
    return session.scalars(
        select(CompensationAttempt).order_by(
            CompensationAttempt.recorded_at, CompensationAttempt.id
        )
    ).all()


def find_unreconciled_compensations(session: Session) -> Sequence[CompensationAttempt]:
    """Committed pre-compensation attempts with no committed terminal
compensation row that agrees on all their immutable facts —
``execution_id`` + ``compensation_attempt_id`` + ``approval_id``.

Recovery read. After a crash / lost response / terminal-write failure /
caller rollback, the durably committed ``CompensationAttempt`` survives
while the caller's terminal compensation row (``compensation_succeeded`` /
``compensation_failed``) may never have committed. An attempt with no
agreeing terminal is "emitted but no reliable terminal" ->
DISPATCH_STATUS_UNKNOWN, surfaced for manual human reconciliation.

It never re-dispatches, retries or compensates: the external reverse effect
of such an attempt is unknown, and an absent terminal is not proof the
external call failed. Pure read of committed data on the caller's session.
"""
    refs = _compensation_terminal_refs_by_attempt(session)
    return [
        attempt
        for attempt in _committed_compensations(session)
        if _settling_compensation_decision(attempt, refs) is None
    ]


def classify_compensation_recovery(
    session: Session,
) -> Sequence[CompensationRecovery]:
    """Classify every committed compensation attempt (read-only) into its disposition.

Surfaces the controlled, read-only manual-recovery view: each attempt is
TERMINAL_AUDIT_PRESENT (a terminal agrees on all its immutable facts;
``audit_decision`` carries the compensation_succeeded/failed audit) or
DISPATCH_STATUS_UNKNOWN (no terminal agrees on all of them -> a human-check
candidate). It never yields EXTERNAL_EFFECT_CONFIRMED and never interprets a
``compensation_failed`` audit as ``confirmed_failure`` — external-effect
confirmation belongs to the Outcome layer, reachable only through the
authoritative reconcile / trusted-reader proof path.

Pure read: no write, no re-dispatch, no retry, no re-compensation, no Outcome
fact, no fabricated ``compensation_succeeded`` row. Recovery identity comes
from the immutable durable attempt, never back-filled from the current config.
"""
    refs = _compensation_terminal_refs_by_attempt(session)
    classified: list[CompensationRecovery] = []
    for attempt in _committed_compensations(session):
        decision = _settling_compensation_decision(attempt, refs)
        disposition = (
            CompensationRecoveryDisposition.TERMINAL_AUDIT_PRESENT
            if decision is not None
            else CompensationRecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        classified.append(
            CompensationRecovery(
                compensation_attempt_id=attempt.compensation_attempt_id,
                execution_id=attempt.execution_id,
                original_execution_id=attempt.original_execution_id,
                approval_id=attempt.approval_id,
                adapter=attempt.adapter,
                reverse_action=attempt.reverse_action,
                target=attempt.target,
                disposition=disposition,
                audit_decision=decision,
            )
        )
    return classified
