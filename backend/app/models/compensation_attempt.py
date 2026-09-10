"""Durable pre-compensation attempt record (RC2 / C-1 production debt fix).

THE PROBLEM (C-1). Forward dispatch received its durable pre-dispatch
reservation in M4-F §1 / M4-G §2: the immutable binding commits on its OWN
transaction BEFORE the external request fires. The reverse (compensation) path
never got the same protection — ``compensate_response`` flushed the
``compensation_requested`` row, called ``executor.compensate()`` and only then
appended the terminal, all inside the caller's ONE business transaction. The
SAME "flush 不等于持久提交" gap applies: a caller rollback / terminal-write
failure / process crash AFTER the external reverse request already fired erases
every durable trace of the attempt, and a later retry has no committed
reservation to refuse it (the partial unique index on
``execution_log.compensates_execution_id`` only bites at caller COMMIT — AFTER
the wire call).

THE FIX. ``compensation_attempt`` is an INDEPENDENT, append-only durable record
of the compensation intent + reverse binding, committed on its OWN transaction
(a separate Session/connection) BEFORE the external compensation request is
sent. Committed independently of the caller's execution_log transaction, it
SURVIVES a caller rollback, a terminal-write failure or a process crash. The
terminal compensation row still REFERENCES the same ``compensation_attempt_id``;
recovery correlates a committed attempt with no terminal row -> a MANUAL
reconciliation candidate (never an auto-retry).

WHAT IT RECORDS — AND NEVER RECORDS. The immutable reverse identity of THIS
compensation attempt: the compensation chain's execution identity, the original
(compensated) execution identity, the original's forward durable-attempt
reference when it exists, approval, adapter, the reversed action / target, the
adapter-declared endpoint (validated secret-free base URL), the operator
principal, the server-clock prepared / dispatch-start instants, the original
outcome state being undone, and the full binding projection in ``detail``
(authoritative instance / tenant only when an adapter contributor provides
them; otherwise honest UNKNOWN). It NEVER records a secret: every field passes
``redact_detail`` at the single write point and no field IS a credential.

NO FOREIGN KEY, deliberately (same precedent as dispatch_attempt /
execution_outcome / execution_log.compensates_execution_id): execution ids are
caller-supplied chain keys, not primary keys; the durable attempt must NOT
cascade away and is read-only evidence. Append-only: INSERT only, never UPDATE,
never DELETE.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import JSONVariant


class CompensationAttempt(Base):
    """One append-only durable pre-compensation attempt (RC2 C-1, migration 0013)."""

    __tablename__ = "compensation_attempt"
    __table_args__ = (
        # The unique compensation-attempt identifier the terminal compensation
        # row references (detail["compensation_attempt_id"]).
        Index(
            "ux_compensation_attempt_compensation_attempt_id",
            "compensation_attempt_id",
            unique=True,
        ),
        # ONE durable compensation attempt per COMPENSATION execution_id — the
        # replay guard: a duplicate request for the same compensation chain can
        # never commit a second durable attempt BEFORE any external request.
        Index(
            "ux_compensation_attempt_execution_id",
            "execution_id",
            unique=True,
        ),
        # THE C-1 RESERVATION: ONE durable compensation per ORIGINAL execution.
        # The durable refill of "at most one compensation per original" —
        # enforced at the independent commit BEFORE the reverse adapter runs,
        # so a caller rollback / crash (which erases the flushed
        # compensation_requested row) cannot open a retry path that fires the
        # external reverse request twice.
        Index(
            "ux_compensation_attempt_original_execution_id",
            "original_execution_id",
            unique=True,
        ),
        # Recovery / manual-reconciliation lookup by approval.
        Index("ix_compensation_attempt_approval_id", "approval_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The binding's unique attempt id — the correlation handle the terminal
    # compensation row references; never re-minted, never reused.
    compensation_attempt_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The COMPENSATION chain's own execution_id (a FRESH identity undoing the
    # original). UNIQUE here so a replay cannot commit a second durable attempt.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The compensated forward execution. UNIQUE (see the reservation index
    # above): the durable last line against a second external compensation for
    # the same original execution.
    original_execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The original forward chain's durable attempt reference
    # (detail["dispatch_attempt_id"] on its terminal row) when the original
    # executed through a durable store; NULL for old history / store-less mock
    # runs — an honest UNKNOWN, never back-filled.
    original_dispatch_attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, nullable=True
    )

    # The approval this compensation belongs to (inherited server-side from the
    # original chain; correlation only, no FK — see module docstring).
    approval_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # Server-side reverse identity snapshot (never client-supplied).
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    reverse_action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)

    # Adapter-declared endpoint (validated secret-free base URL) when an
    # adapter contributor provides one — None for a non-contributor (honest
    # UNKNOWN, never a substitute).
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # The authenticated operator principal that requested the compensation
    # (the API derives it from the token; never from the request body).
    operator: Mapped[str] = mapped_column(String(128), nullable=False)

    # The operator's comment / reason, when provided.
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # The ORIGINAL chain's derived state being undone ("succeeded" / "failed")
    # — the immutable "what was being reversed" fact (never re-derived at
    # reconciliation time).
    original_outcome_state: Mapped[str] = mapped_column(String(32), nullable=False)

    # Server-clock instants: when the binding was prepared, and the last
    # instant before the durable commit at which no external request could have
    # fired (the binding commits BEFORE the wire call — same precedent as the
    # forward binding's dispatch_started_at).
    prepared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    dispatch_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # The full binding projection (binding.to_detail()), secret-gated through
    # redact_detail at the single write point. Redundant with the columns above
    # by design: the columns serve the recovery query, the detail preserves the
    # exact immutable binding for audit (version evidence / instance / tenant
    # ride here).
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only: when the durable record was committed.
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<CompensationAttempt id={self.id} execution={self.execution_id} "
            f"original={self.original_execution_id} "
            f"attempt={self.compensation_attempt_id} adapter={self.adapter}>"
        )
