"""Durable pre-dispatch attempt record.

A forward dispatch writes its binding into the ``dispatched`` execution_log row
and flushes it before ``executor.execute()`` is called. The execution Service
never commits: the API caller owns the single business transaction and commits
after the external request returns, so a flush is not a durable commit. If the
process crashes, the terminal write fails, or the caller rolls back after the
external request has already fired, the flushed binding row disappears with the
aborted transaction — exactly when the durable proof of what was dispatched,
where, when and under which approval is most needed.

``dispatch_attempt`` is therefore an independent, append-only durable record of
the dispatch intent and target binding, committed on its own transaction (a
separate Session/connection) before the external request is sent. Because it
commits independently of the caller's execution_log transaction, it survives a
caller rollback, a terminal-write failure or a process crash. The terminal
execution_log row still references the same ``attempt_id``, so recovery
correlates a committed attempt that has no terminal row into a manual
reconciliation candidate; it never triggers an automatic retry.

What it records: the immutable target identity of this attempt (execution /
approval / adapter / action / target, the server-clock dispatch start, the
unique attempt id) plus the full binding projection in ``detail``. It records no
secret: every field passes ``redact_detail`` at the single write point, and no
field is a credential — the endpoint is the validated secret-free base URL, and
the version is a config declaration rather than proof that the target is live.

No foreign key, for the same reason as execution_outcome and
execution_log.compensates_execution_id: execution_id and approval_id are
caller-supplied chain keys, not primary keys, and the durable attempt must not
cascade away — it is read-only evidence. Append-only: INSERT only, never UPDATE,
never DELETE.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import JSONVariant


class DispatchAttempt(Base):
    """One append-only durable pre-dispatch attempt record (migration 0011)."""

    __tablename__ = "dispatch_attempt"
    __table_args__ = (
        # The unique dispatch-attempt identifier the terminal execution_log row
        # references (detail["dispatch_attempt_id"]).
        Index("ux_dispatch_attempt_attempt_id", "attempt_id", unique=True),
        # One durable attempt per execution_id — the race and idempotency
        # guard that refuses a second committed attempt for a duplicate or
        # concurrent replay before any external request is sent, mirroring
        # execution_log's idempotency index.
        Index("ux_dispatch_attempt_execution_id", "execution_id", unique=True),
        # One execute dispatch attempt per approval_id — the durable
        # reservation that closes the same-approval concurrent race before any
        # external request. Two different execution_ids sharing one approval_id
        # both pass the pre-check (each reads an empty prior_approval_rows) and
        # would both fire the adapter, while the execution_log partial approval
        # index only bites at caller commit, after the wire call; so the
        # reservation must live here, ahead of the dispatch. Every
        # dispatch_attempt row is execute-direction (compensate_response never
        # records one), so a plain unique index carries the "one execute per
        # approval" semantics without a direction qualifier.
        Index("ux_dispatch_attempt_approval_id", "approval_id", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The binding's unique attempt id — the correlation handle the terminal
    # execution_log row references; never re-minted, never reused.
    attempt_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # Caller-supplied execution identity, i.e. the idempotency key. Unique here
    # so a concurrent replay cannot commit a second durable attempt — the last
    # line against a duplicate external request, ahead of the adapter call.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The approval this dispatch belongs to (correlation only, no FK — see the
    # module docstring). Unique: the durable approval-slot reservation that
    # refuses a second execute attempt for the same approval before the
    # external request — see ux_dispatch_attempt_approval_id above.
    approval_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # Server-side target identity snapshot (never client-supplied).
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)

    # Server-clock dispatch start (the binding's fact), not the created_at
    # audit column of execution_log; recorded here so the durable attempt
    # carries the instant the external request was about to be sent.
    dispatch_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # The full binding projection (binding.to_detail()), secret-gated through
    # redact_detail at the single write point. It is redundant with the columns
    # above on purpose: the columns serve the recovery query, while the detail
    # preserves the exact immutable binding for audit.
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only: when the durable record was committed.
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<DispatchAttempt id={self.id} execution={self.execution_id} "
            f"attempt={self.attempt_id} adapter={self.adapter}>"
        )
