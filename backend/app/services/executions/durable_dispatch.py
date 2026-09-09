"""Durable pre-dispatch attempt store (M4-F §1 — "flush 不等于持久提交" fix).

THE PROBLEM. M4-A persisted the forward dispatch binding inside the ``dispatched``
execution_log row and flushed it BEFORE ``executor.execute()``. But the Execution
Service NEVER commits (frozen discipline in ``service.py``: ``add() + flush()``
only — the API caller owns the ONE business transaction and commits AFTER the
external request returns). A flush is NOT a durable commit: if the process
crashes, the terminal write fails, or the caller rolls back AFTER the external
request already fired, the flushed binding vanishes with the aborted transaction.

THE FIX. This store commits the dispatch intent + target binding on its OWN
transaction (a SEPARATE Session/connection derived from the caller's bind)
BEFORE the external request is sent. Because it is committed independently of the
caller's execution_log transaction, it SURVIVES a caller rollback, a terminal-write
failure or a process crash. Recovery then correlates a committed attempt that has
no terminal execution_log row -> a MANUAL reconciliation candidate (NEVER an
auto-retry: constraint 5 — an "emitted but no reliable terminal" attempt keeps its
uncertainty and a human-check path).

FROZEN-CONTRACT SAFE. This does NOT violate "the Service NEVER calls commit()":
that clause protects the CALLER's business transaction. This store owns a
SEPARATE session and commits ONLY that one — the exact precedent already set by
the outcomes services (webhook / manual_reconcile / manual_persist /
verified_proof), each of which manages its own flush+commit+rollback. The caller's
execution_log transaction is untouched; its commit boundary stays in the API layer.

SECRET-GATED. The binding projection passes ``redact_detail`` at this single write
point, and no binding field IS a credential (the endpoint is the validated
secret-free base URL; the version is a config declaration, never a liveness proof).
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import DispatchAttempt
from app.models.execution_log import ExecutionLog
from app.services.executions.binding import DispatchBinding
from app.services.executions.secrets import redact_detail


class DurableDispatchAttemptStore:
    """Commits the pre-dispatch attempt binding on its OWN durable transaction.

    Constructed with a SQLAlchemy ``bind`` (an Engine — in production the API
    layer passes ``db.get_bind()``; in tests a file-backed engine). ``record``
    opens an INDEPENDENT Session on that bind, INSERTs the append-only
    ``DispatchAttempt`` row and COMMITS it, then closes. A duplicate
    ``execution_id`` (a replay/concurrent race) raises ``IntegrityError`` — the
    caller MUST treat that as "do not emit the external request".
    """

    def __init__(self, bind) -> None:
        self._bind = bind

    def record(self, binding: DispatchBinding) -> None:
        """Durably commit ``binding`` BEFORE the external request is sent.

        Returns ``None`` (the row is committed and the session closed, so there is
        deliberately no ORM object handed back — reading it after close would
        raise ``DetachedInstanceError``). On ANY failure the independent session
        is rolled back and the exception propagates, so the caller NEVER proceeds
        to the external adapter when the durable pre-dispatch fact did not commit.
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
        # An INDEPENDENT Session on its own connection: committing HERE (not on the
        # caller's session) is what makes the attempt durable across the caller's
        # rollback / terminal-write failure / crash. The original IntegrityError is
        # re-raised UNWRAPPED so the Execution Service can translate a duplicate
        # execution_id into its typed 409 conflict (D14) — the store never hides it.
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


#: execution_log decisions that SETTLE an attempt's external outcome. A committed
#: attempt whose execution_id has NO such terminal row is "emitted but no reliable
#: terminal" — a MANUAL reconciliation candidate, NEVER an auto-retry (M4-F §1/§2,
#: constraint 5).
_TERMINAL_DECISIONS = ("succeeded", "failed")


def find_unreconciled_attempts(session: Session) -> Sequence[DispatchAttempt]:
    """Committed pre-dispatch attempts with NO committed terminal execution_log row.

    RECOVERY READ (M4-F §1/§2). After a crash / lost response / terminal-write
    failure / caller rollback, the durably committed ``DispatchAttempt`` SURVIVES
    while the caller's execution_log terminal (``succeeded`` / ``failed``) may never
    have committed. This correlates a committed attempt against a terminal row on
    the SAME ``execution_id``: an attempt with none is "emitted but no reliable
    terminal" — surfaced for MANUAL human reconciliation.

    It NEVER re-dispatches, retries or compensates (constraint 5): the external
    effect of such an attempt is UNKNOWN, and an absent terminal is NOT proof the
    external call failed. Pure read of committed data on the caller's session.
    """
    # A correlated NOT EXISTS: keep every committed attempt whose execution_id has
    # NO terminal (succeeded/failed) execution_log row. ``requested`` / ``dispatched``
    # rows do NOT settle an attempt — only a terminal proves the external outcome was
    # recorded — so an attempt with merely a dispatched row is still unreconciled.
    terminal_exists = (
        select(ExecutionLog.id)
        .where(
            ExecutionLog.execution_id == DispatchAttempt.execution_id,
            ExecutionLog.decision.in_(_TERMINAL_DECISIONS),
        )
        .correlate(DispatchAttempt)
        .exists()
    )
    stmt = (
        select(DispatchAttempt)
        .where(~terminal_exists)
        .order_by(DispatchAttempt.recorded_at, DispatchAttempt.id)
    )
    return session.scalars(stmt).all()
