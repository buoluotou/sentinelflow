"""Durable pre-dispatch attempt record (M4-F §1, Amendment §12.2 A1-revised durability).

THE PROBLEM. M4-A persisted the forward dispatch binding inside the ``dispatched``
execution_log row and flushed it BEFORE ``executor.execute()``. But the Execution
Service NEVER commits (frozen discipline: the API caller owns the ONE business
transaction and commits AFTER the external request returns). A flush is NOT a
durable commit: if the process crashes, the terminal write fails, or the caller
rolls back AFTER the external request already fired, the flushed binding row
vanishes with the aborted transaction — exactly when the durable proof of "what
was dispatched, where, when, under which approval" is most needed (M4 review
finding: "flush 不等于持久提交").

THE FIX. ``dispatch_attempt`` is an INDEPENDENT, append-only durable record of the
dispatch intent + target binding, committed on its OWN transaction (a separate
Session/connection) BEFORE the external request is sent. Committed independently of
the caller's execution_log transaction, it SURVIVES a caller rollback, a
terminal-write failure or a process crash. The terminal execution_log row still
references the SAME ``attempt_id``; recovery correlates a committed attempt with no
terminal row -> a MANUAL reconciliation candidate (never an auto-retry: constraint 5).

WHAT IT RECORDS — AND NEVER RECORDS. The immutable target identity of THIS attempt
(execution / approval / adapter / action / target, the server-clock dispatch start,
the unique attempt id) plus the full binding projection in ``detail``. It NEVER
records a secret: every field passes ``redact_detail`` at the single write point and
no field IS a credential (the endpoint is the validated secret-free base URL; the
version is a config declaration, never a liveness proof — constraint 3).

NO FOREIGN KEY, deliberately (same precedent as execution_outcome and
execution_log.compensates_execution_id): execution_id / approval_id are
caller-supplied chain keys, not primary keys; the durable attempt must NOT cascade
away and is read-only evidence. Append-only: INSERT only, never UPDATE, never DELETE.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import JSONVariant


class DispatchAttempt(Base):
    """One append-only durable pre-dispatch attempt (M4-F, migration 0011)."""

    __tablename__ = "dispatch_attempt"
    __table_args__ = (
        # The unique dispatch-attempt identifier the terminal execution_log row
        # references (detail["dispatch_attempt_id"]).
        Index("ux_dispatch_attempt_attempt_id", "attempt_id", unique=True),
        # ONE durable attempt per execution_id — the race/idempotency guard that
        # refuses a second committed attempt for a duplicate/concurrent replay
        # BEFORE any external request (mirrors execution_log's D14 last line).
        Index("ux_dispatch_attempt_execution_id", "execution_id", unique=True),
        # M4-G §1: ONE execute dispatch attempt per approval_id — the durable
        # reservation that closes the same-approval concurrent race BEFORE any
        # external request. Two DIFFERENT execution_ids sharing one approval_id
        # (the M4-F review finding) both pass the G3 pre-check (each reads an
        # empty prior_approval_rows) and would both fire the adapter; the
        # execution_log partial approval index only bites at caller-commit AFTER
        # the wire call, so the reservation must live HERE, ahead of the dispatch.
        # Every dispatch_attempt row is execute-direction (compensate_response
        # never records one), so a plain unique index carries the exact D14 "one
        # execute per approval" semantics without a direction qualifier.
        Index("ux_dispatch_attempt_approval_id", "approval_id", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The binding's unique attempt id — the correlation handle the terminal
    # execution_log row references; never re-minted, never reused.
    attempt_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # Caller-supplied execution identity (the D14 idempotency key). UNIQUE here so
    # a concurrent replay cannot commit a second durable attempt (the last line
    # against a duplicate external request, ahead of the adapter call).
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The approval this dispatch belongs to (correlation only, no FK — see module
    # docstring). UNIQUE (M4-G §1): the durable approval-slot reservation that
    # refuses a second execute attempt for the same approval BEFORE the external
    # request — see ux_dispatch_attempt_approval_id above.
    approval_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # Server-side target identity snapshot (never client-supplied).
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)

    # Server-clock dispatch START (the binding's fact) — NOT the created_at audit
    # column of execution_log; recorded here so the durable attempt carries the
    # instant the external request was about to be sent.
    dispatch_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # The full binding projection (binding.to_detail()), secret-gated through
    # redact_detail at the single write point. Redundant with the columns above by
    # design: the columns serve the recovery query, the detail preserves the exact
    # immutable binding for audit.
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only (constraint 8): when the durable record was committed.
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<DispatchAttempt id={self.id} execution={self.execution_id} "
            f"attempt={self.attempt_id} adapter={self.adapter}>"
        )
