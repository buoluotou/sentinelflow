"""Durable pre-dispatch attempt store.

The dispatch binding is persisted inside the ``dispatched`` execution_log row and
flushed before ``executor.execute()``. The Execution Service never commits
(``service.py`` does ``add() + flush()`` only — the API caller owns the single
business transaction and commits after the external request returns). A flush is
not a durable commit: if the process crashes, the terminal write fails, or the
caller rolls back after the external request already fired, the flushed binding
vanishes with the aborted transaction.

This store commits the dispatch intent + target binding on its own transaction
(a separate Session/connection derived from the caller's bind) before the
external request is sent. Because it is committed independently of the caller's
execution_log transaction, it survives a caller rollback, a terminal-write
failure or a process crash. Recovery then correlates a committed attempt that has
no terminal execution_log row -> a manual reconciliation candidate, never an
auto-retry: an "emitted but no reliable terminal" attempt keeps its uncertainty
and a human-check path.

This does not violate "the Service never calls commit()": that clause protects
the caller's business transaction. The store owns a separate session and commits
only that one — the same arrangement the outcomes services (webhook /
manual_reconcile / manual_persist / verified_proof) already use, each of which
manages its own flush+commit+rollback. The caller's execution_log transaction is
untouched; its commit boundary stays in the API layer.

The binding projection passes ``redact_detail`` at this single write point, and
no binding field is a credential (the endpoint is the validated secret-free base
URL; the version is a config declaration, never a liveness proof).
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

from app.models import DispatchAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.binding import TERMINAL_REFERENCE_KEY, DispatchBinding
from app.services.executions.secrets import redact_detail


class DurableDispatchAttemptStore:
    """Commits the pre-dispatch attempt binding on its own durable transaction.

Constructed with a SQLAlchemy ``bind`` (an Engine — in production the API
layer passes ``db.get_bind()``; in tests a file-backed engine). ``record``
opens an independent Session on that bind, INSERTs the append-only
``DispatchAttempt`` row and commits it, then closes. A duplicate
``execution_id`` (a replay/concurrent race) raises ``IntegrityError`` — the
caller must treat that as "do not emit the external request".
"""

    def __init__(self, bind) -> None:
        self._bind = bind

    def record(self, binding: DispatchBinding) -> None:
        """Durably commit ``binding`` before the external request is sent.

Returns ``None``: the row is committed and the session closed, so no ORM
object is handed back — reading it after close would raise
``DetachedInstanceError``. On any failure the independent session is
rolled back and the exception propagates, so the caller never proceeds to
the external adapter when the durable pre-dispatch fact did not commit.
"""
        detail = redact_detail(binding.to_detail())
        started_at = binding.started_at() or datetime.now(timezone.utc)
        row = DispatchAttempt(
            attempt_id=uuid.UUID(binding.attempt_id),
            execution_id=uuid.UUID(binding.execution_id),
            approval_id=uuid.UUID(binding.approval_id),
            adapter=binding.adapter,
            action=binding.action,
            target=binding.target,
            dispatch_started_at=started_at,
            detail=detail,
            # id / recorded_at intentionally unset -> model defaults (append-only).
        )
        # An independent Session on its own connection: committing here (not on
        # the caller's session) is what makes the attempt durable across the
        # caller's rollback / terminal-write failure / crash. The original
        # IntegrityError is re-raised unwrapped so the Execution Service can
        # translate a duplicate execution_id into its typed 409 conflict — the
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


# execution_log decisions that carry a terminal audit for an attempt's dispatch.
# A terminal settles an attempt only when all of the attempt's immutable durable
# facts agree — its ``detail`` references that attempt's ``attempt_id``
# (``TERMINAL_REFERENCE_KEY``) and the terminal row's ``execution_id`` equals the
# attempt's and (a committed ``execution_log`` row always carries a non-null
# ``approval_id``) its ``approval_id`` equals the attempt's. Never by
# ``attempt_id`` or ``execution_id`` alone, so a stale / mis-attributed /
# cross-execution / cross-approval terminal cannot mask a still-pending attempt.
# ``requested`` / ``dispatched`` rows are not terminal and never settle an
# attempt.
_TERMINAL_DECISIONS = ("succeeded", "failed")


class RecoveryDisposition(str, Enum):
    """Read-only classification of a committed dispatch attempt during recovery.
The three states stay distinct and are never collapsed into one another:

* ``TERMINAL_AUDIT_PRESENT`` — a committed terminal execution_log row references
this attempt's ``attempt_id`` and shares its ``execution_id`` + ``approval_id``
(all three immutable facts must agree). The dispatch audit is settled
(``succeeded`` / ``failed``), but this is an audit fact about what the service
recorded, not a confirmation of the external world's effect. A ``failed``
terminal is never ``confirmed_failure``: the external action may still have
landed (a timeout after the effect applied, a lost response).
* ``DISPATCH_STATUS_UNKNOWN`` — a committed attempt with no terminal row that
agrees on all its immutable facts (execution_id + attempt_id + approval_id):
"emitted but no reliable terminal". The external effect is unknown; this is a
manual, read-only human-reconciliation candidate, never an auto-retry /
re-dispatch / compensation, and never a fabricated ``succeeded`` row.
* ``EXTERNAL_EFFECT_CONFIRMED`` — the external effect was authoritatively
confirmed. This state lives only in the Outcome layer (``confirmed_success`` /
``confirmed_failure``), produced only by the authoritative manual reconcile /
trusted-reader proof path (``verify_creation_effect``) with a verified external
reference. The recovery read never produces it: neither a durable attempt, nor
a terminal audit, nor any external JSON / ordinary internal object can
authorize a confirmed effect here.
"""

    TERMINAL_AUDIT_PRESENT = "terminal_audit_present"
    DISPATCH_STATUS_UNKNOWN = "dispatch_status_unknown"
    EXTERNAL_EFFECT_CONFIRMED = "external_effect_confirmed"


@dataclass(frozen=True, slots=True)
class AttemptRecovery:
    """The read-only recovery classification of one committed dispatch attempt.

The identity facts (``adapter`` / ``action`` / ``target``) are the durable
attempt's immutable snapshot, never back-filled from the current config. This
record carries no authorization power: it is evidence for a human operator,
who reconciles through the existing manual reconcile path (operator auth +
RBAC + append-only Outcome + whitelist audit) — it can never itself authorize
a ``confirmed_success`` / ``confirmed_failure``.
"""

    attempt_id: uuid.UUID
    execution_id: uuid.UUID
    approval_id: uuid.UUID
    adapter: str
    action: str
    target: str
    disposition: RecoveryDisposition
    # The terminal audit decision (``succeeded`` / ``failed``) when a terminal agrees
    # on all this attempt's immutable facts (execution_id + attempt_id + approval_id),
    # else ``None``. An audit fact only — never an external-effect confirmation (a
    # ``failed`` audit is not ``confirmed_failure``).
    audit_decision: str | None


@dataclass(frozen=True, slots=True)
class _TerminalRef:
    """One committed terminal execution_log row's immutable correlation facts, as read
for recovery: the ``execution_id`` / ``approval_id`` the row was written under and its
terminal ``decision``. The referenced ``attempt_id`` (the dict key carrying this ref)
is validated at parse time; whether the ref actually settles a given
``DispatchAttempt`` is decided by :func:`_settling_decision`, which also requires the
``execution_id`` + ``approval_id`` to equal the attempt's own immutable facts."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID | None
    decision: str


def _terminal_refs_by_attempt(session: Session) -> dict[str, list[_TerminalRef]]:
    """Group every committed terminal execution_log row that references an attempt (via
``TERMINAL_REFERENCE_KEY``) by its canonical referenced ``attempt_id`` (str).

Read-only. The dict key is only the referenced attempt_id the service stamps on the
terminal row (``detail["dispatch_attempt_id"] = binding.attempt_id``); whether that
reference actually settles a given ``DispatchAttempt`` is decided by
:func:`_settling_decision`, which also requires the terminal's ``execution_id`` (and
``approval_id``) to equal the attempt's immutable facts. A non-str / malformed
reference is skipped (fail-closed — settles nothing). Rows scan oldest-first so the
latest matching terminal wins (an attempt carries at most one terminal in practice —
the service writes exactly one — but a corrupted history may carry several).
"""
    refs: dict[str, list[_TerminalRef]] = {}
    terminals = session.scalars(
        select(ExecutionLog)
        .where(ExecutionLog.decision.in_(_TERMINAL_DECISIONS))
        .order_by(ExecutionLog.created_at, ExecutionLog.id)
    ).all()
    for row in terminals:
        detail = row.detail if isinstance(row.detail, dict) else {}
        reference = detail.get(TERMINAL_REFERENCE_KEY)
        if not isinstance(reference, str):
            continue
        try:
            key = str(uuid.UUID(reference))  # canonicalize the reference
        except (ValueError, AttributeError, TypeError):
            continue  # a malformed reference settles nothing (fail-closed)
        refs.setdefault(key, []).append(
            _TerminalRef(
                execution_id=row.execution_id,
                approval_id=row.approval_id,
                decision=row.decision,
            )
        )
    return refs


def _settling_decision(
    attempt: DispatchAttempt, refs: dict[str, list[_TerminalRef]]
) -> str | None:
    """The terminal audit decision that settles ``attempt``, else ``None``.

A terminal settles the attempt only when all of the attempt's immutable durable facts
agree with the terminal row:

* ``terminal.execution_id == attempt.execution_id`` — a cross-execution terminal that
merely references this ``attempt_id`` cannot settle it;
* the referenced ``attempt_id`` equals ``attempt.attempt_id`` (the dict key); and
* when the terminal carries an ``approval_id`` (a committed ``execution_log`` row
always does — it is non-nullable), ``terminal.approval_id == attempt.approval_id``.

Any missing / malformed / cross-execution / cross-approval / wrong-attempt_id
reference is fail-closed -> ``None`` -> DISPATCH_STATUS_UNKNOWN (the safe direction).
The facts come from the immutable durable attempt and the committed terminal row only
— never back-filled from the current config or another log. Oldest-first scan, so the
latest fully-matching terminal's decision wins.
"""
    candidates = refs.get(str(attempt.attempt_id))
    if not candidates:
        return None
    decision: str | None = None
    for ref in candidates:
        if ref.execution_id != attempt.execution_id:
            continue  # a cross-execution mis-reference cannot settle
        if ref.approval_id is not None and ref.approval_id != attempt.approval_id:
            continue  # a cross-approval mis-reference cannot settle
        decision = ref.decision  # all immutable facts agree; latest match wins
    return decision


def _committed_attempts(session: Session) -> Sequence[DispatchAttempt]:
    """Every committed durable attempt, oldest-first (a stable recovery order)."""
    return session.scalars(
        select(DispatchAttempt).order_by(
            DispatchAttempt.recorded_at, DispatchAttempt.id
        )
    ).all()


def find_unreconciled_attempts(session: Session) -> Sequence[DispatchAttempt]:
    """Committed pre-dispatch attempts with no committed terminal execution_log row that
agrees on all their immutable facts — ``execution_id`` + ``attempt_id`` +
``approval_id``.

Recovery read. After a crash / lost response / terminal-write failure / caller
rollback, the durably committed ``DispatchAttempt`` survives while the caller's
execution_log terminal (``succeeded`` / ``failed``) may never have committed. A
terminal settles an attempt only when every immutable fact agrees (see
:func:`_settling_decision`) — never by ``attempt_id`` or ``execution_id`` alone — so a
stale / wrong-attempt / cross-execution / cross-approval terminal cannot mask a
still-pending attempt. An attempt with no such terminal is "emitted but no reliable
terminal" -> DISPATCH_STATUS_UNKNOWN, surfaced for manual human reconciliation.

It never re-dispatches, retries or compensates: the external effect of such an
attempt is unknown, and an absent terminal is not proof the external call failed.
Pure read of committed data on the caller's session.
"""
    refs = _terminal_refs_by_attempt(session)
    return [
        attempt
        for attempt in _committed_attempts(session)
        if _settling_decision(attempt, refs) is None
    ]


def classify_attempt_recovery(session: Session) -> Sequence[AttemptRecovery]:
    """Classify every committed dispatch attempt (read-only) into its disposition.

Surfaces the controlled, read-only manual-recovery view: each attempt is
TERMINAL_AUDIT_PRESENT (a terminal agrees on all its immutable facts —
execution_id + attempt_id + approval_id; ``audit_decision`` carries the
succeeded/failed audit) or DISPATCH_STATUS_UNKNOWN (no terminal agrees on all of
them -> a human-check candidate). It never yields EXTERNAL_EFFECT_CONFIRMED and
never interprets a ``failed`` audit as ``confirmed_failure`` — external-effect
confirmation is the Outcome layer's, reachable only through the authoritative
reconcile / trusted-reader proof path.

Pure read: no write, no re-dispatch, no retry, no compensation, no Outcome fact,
no fabricated ``succeeded`` row. Recovery identity comes from the immutable
durable attempt, never back-filled from the current config.
"""
    refs = _terminal_refs_by_attempt(session)
    classified: list[AttemptRecovery] = []
    for attempt in _committed_attempts(session):
        decision = _settling_decision(attempt, refs)
        disposition = (
            RecoveryDisposition.TERMINAL_AUDIT_PRESENT
            if decision is not None
            else RecoveryDisposition.DISPATCH_STATUS_UNKNOWN
        )
        classified.append(
            AttemptRecovery(
                attempt_id=attempt.attempt_id,
                execution_id=attempt.execution_id,
                approval_id=attempt.approval_id,
                adapter=attempt.adapter,
                action=attempt.action,
                target=attempt.target,
                disposition=disposition,
                audit_decision=decision,
            )
        )
    return classified
