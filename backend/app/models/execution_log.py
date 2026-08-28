import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import JSONVariant

# Execution vocabulary (Phase 3.1, frozen — design doc
# docs/design/phase3-response-execution.md §6): decision is APPEND-ONLY
# audit fact, never UPDATEd. Every decision belongs to exactly one
# direction; cross-direction words are rejected by the CHECK below.
EXECUTE_DECISIONS = frozenset(
    {"requested", "guard_rejected", "dispatched", "succeeded", "failed"}
)
COMPENSATE_DECISIONS = frozenset(
    {"compensation_requested", "compensation_succeeded", "compensation_failed"}
)
EXECUTION_DECISIONS = EXECUTE_DECISIONS | COMPENSATE_DECISIONS
EXECUTION_DIRECTIONS = frozenset({"execute", "compensate"})

# Legal decision x direction combinations only — the single source of truth
# shared by the DB CHECK and the future Service state machine (3.1.3).
EXECUTION_LEGAL_COMBINATIONS = frozenset(
    {(decision, "execute") for decision in EXECUTE_DECISIONS}
    | {(decision, "compensate") for decision in COMPENSATE_DECISIONS}
)


class ExecutionLog(Base):
    """One append-only execution-audit row (Phase 3.1, migration 0009).

    Pure append log (design decision D7): execution state is NEVER stored —
    it is DERIVED as the latest row per execution_id (created_at DESC,
    id DESC). INSERT only: no UPDATE, no DELETE, ever.

    The client only expresses Intent (execution_id / approval_id /
    operator): action and target are a SERVER-SIDE snapshot assembled from
    the approved recommendation — the request schema never accepts them.

    `requested` semantics (D12): the row lands as soon as Auth + Schema
    pass and a legal Execute Intent is formed — NOT "all guards passed".
    Guards run AFTER requested and append guard_rejected / dispatched in
    the same transaction (D13), so business rejections stay auditable.
    """

    __tablename__ = "execution_log"
    __table_args__ = (
        # Constraint 9: storage-level guard — only legal decision x
        # direction combinations persist. Sequencing rules (terminal
        # states, transition order) are the Service state machine's job;
        # the CHECK is the last integrity line (project-wide principle).
        CheckConstraint(
            "(direction = 'execute' AND decision IN ("
            "'requested', 'guard_rejected', 'dispatched', 'succeeded', 'failed'))"
            " OR "
            "(direction = 'compensate' AND decision IN ("
            "'compensation_requested', 'compensation_succeeded', 'compensation_failed'))",
            name="ck_execution_log_decision_direction",
        ),
        # Constraint 1: idempotency key + execution identity (D14). Partial
        # UNIQUE INDEX (not a table constraint) so both SQLite and
        # PostgreSQL enforce it; the Service pre-check is the first line,
        # this index is the last line against concurrent replays.
        Index(
            "ux_execution_log_execution_id_requested",
            "execution_id",
            unique=True,
            postgresql_where=text("decision = 'requested'"),
            sqlite_where=text("decision = 'requested'"),
        ),
        # Constraint 2 — “占位行唯一约束” (placeholder-row uniqueness,
        # frozen wording, migration-review 2026-08-28): one approval -> at
        # most ONE forward execution over the whole lifecycle. Every legal
        # direction='execute' chain holds EXACTLY ONE requested row, and it
        # must be the FIRST row of the chain (Service invariant enforced by
        # the 3.1.3 state machine — the DB only counts requested rows).
        # That row is the lifecycle slot-holder: later chain rows
        # (guard_rejected / dispatched / succeeded / failed) share
        # approval_id but fall out of the partial index, while any
        # RE-execution must insert a fresh requested row and is blocked
        # here — even after terminal failed (no retry, only compensation).
        # Approval forward-execution eligibility is guaranteed JOINTLY by
        # the Service state machine and this partial unique index.
        Index(
            "ux_execution_log_approval_id_execute",
            "approval_id",
            unique=True,
            postgresql_where=text("direction = 'execute' AND decision = 'requested'"),
            sqlite_where=text("direction = 'execute' AND decision = 'requested'"),
        ),
        # Constraint 3: one original execution -> at most one compensation
        # request (compensation is a fresh execution_id of its own).
        Index(
            "ux_execution_log_compensates_requested",
            "compensates_execution_id",
            unique=True,
            postgresql_where=text("decision = 'compensation_requested'"),
            sqlite_where=text("decision = 'compensation_requested'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # Caller-supplied idempotency key AND execution identity (design §4):
    # the first request binds it to approval_id / direction / server-side
    # action+target snapshot; any replay with different facts is a 409.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)

    # The approval this execution belongs to. execute direction: supplied
    # by the request and validated; compensate direction: inherited by the
    # server from the original execution (D11) — the client never sends it.
    # NO ACTION on delete (migration-review 2026-08-28): execution_log is
    # append-only audit; it must never disappear along with a deleted
    # approval. The project has no approval deletion path today (all
    # approval endpoints are GET/POST), so NO ACTION changes nothing
    # operationally — it just stops the audit trail from inheriting a
    # CASCADE behaviour copied unexamined from business-relation FKs.
    approval_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("ai_response_approvals.id", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Frozen audit vocabulary (see module constants); CHECK above limits it
    # to the legal decision x direction combinations.
    decision: Mapped[str] = mapped_column(String(32), nullable=False)

    # Which way the log reads: forward execution or compensating execution.
    direction: Mapped[str] = mapped_column(String(16), nullable=False)

    # SERVER-SIDE snapshot of the approved recommendation's action/target —
    # never accepted from the request body (fact-smuggling is a 422).
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)

    # Compensation rows link back to the original execution's execution_id
    # (bidirectionally traceable); execute rows leave it NULL. Plain column,
    # not an FK: execution_id is a caller-supplied key, not a primary key.
    compensates_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, nullable=True, index=True
    )

    # Who executed. Free-form operator identifier (shared-secret platform,
    # no user system — D4), recorded verbatim for the audit trail; separate
    # from the approval reviewer by design.
    operator: Mapped[str] = mapped_column(String(128), nullable=False)

    # Guard rejection reasons / dispatch echo / adapter raw responses /
    # failure classification. NEVER contains the execution token (frozen
    # security discipline, design §10).
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only (constraint 8 + design precedent of reviewed_at):
    # the audit trail cannot be backdated from the client. Append-only rows
    # never update, so there is deliberately no updated_at.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    approval: Mapped["AIResponseApproval"] = relationship(back_populates="executions")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ExecutionLog id={self.id} execution={self.execution_id} "
            f"decision={self.decision} direction={self.direction}>"
        )


# Avoid circular import at module load time
from app.models.ai_response_approval import AIResponseApproval  # noqa: E402,F401
