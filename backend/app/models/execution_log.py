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
from app.core.ids import uuid7
from app.models.types import JSONVariant

# Execution vocabulary: `decision` is an append-only audit fact and is never
# updated. Every decision belongs to exactly one direction; cross-direction
# words are rejected by the CHECK below.
EXECUTE_DECISIONS = frozenset(
    {"requested", "guard_rejected", "dispatched", "succeeded", "failed"}
)
COMPENSATE_DECISIONS = frozenset(
    {"compensation_requested", "compensation_succeeded", "compensation_failed"}
)
EXECUTION_DECISIONS = EXECUTE_DECISIONS | COMPENSATE_DECISIONS
EXECUTION_DIRECTIONS = frozenset({"execute", "compensate"})

# Legal decision x direction combinations only — the single source of truth
# shared by the DB CHECK and the execution Service state machine.
EXECUTION_LEGAL_COMBINATIONS = frozenset(
    {(decision, "execute") for decision in EXECUTE_DECISIONS}
    | {(decision, "compensate") for decision in COMPENSATE_DECISIONS}
)


class ExecutionLog(Base):
    """One row of the append-only execution audit log (migration 0009).

Execution state is not stored: it is derived as the latest row per
execution_id, ordered by (created_at DESC, id DESC). Rows are inserted
only — no UPDATE, no DELETE.

The client expresses an intent (execution_id / approval_id / operator);
action and target are a server-side snapshot assembled from the approved
recommendation, and the request schema never accepts them.

A `requested` row is written as soon as authentication and schema
validation pass and a legal execute intent exists — it does not mean all
guards passed. Guards run after it and append guard_rejected /
dispatched in the same transaction, so business rejections stay
auditable.
"""

    __tablename__ = "execution_log"
    __table_args__ = (
        # Storage-level guard: only legal decision x direction combinations
        # persist. Sequencing rules (terminal states, transition order) are
        # the Service state machine's job; this CHECK is the last line of
        # defence.
        CheckConstraint(
            "(direction = 'execute' AND decision IN ("
            "'requested', 'guard_rejected', 'dispatched', 'succeeded', 'failed'))"
            " OR "
            "(direction = 'compensate' AND decision IN ("
            "'compensation_requested', 'compensation_succeeded', 'compensation_failed'))",
            name="ck_execution_log_decision_direction",
        ),
        # Idempotency key and execution identity. A partial unique index
        # rather than a table constraint, so both SQLite and PostgreSQL
        # enforce it; the Service pre-check is the first line, this index the
        # last against concurrent replays.
        Index(
            "ux_execution_log_execution_id_requested",
            "execution_id",
            unique=True,
            postgresql_where=text("decision = 'requested'"),
            sqlite_where=text("decision = 'requested'"),
        ),
        # One approval maps to at most one forward execution over the whole
        # lifecycle. Every legal direction='execute' chain holds exactly one
        # requested row, and it must be the first row of the chain (a Service
        # invariant enforced by the state machine — the DB only counts
        # requested rows). That row holds the lifecycle slot: later chain rows
        # (guard_rejected / dispatched / succeeded / failed) share
        # approval_id but fall outside the partial index, while any
        # re-execution would need a fresh requested row and is blocked here —
        # even after a terminal failed (no retry, only compensation).
        # Forward-execution eligibility is therefore guaranteed jointly by the
        # Service state machine and this partial unique index.
        Index(
            "ux_execution_log_approval_id_execute",
            "approval_id",
            unique=True,
            postgresql_where=text("direction = 'execute' AND decision = 'requested'"),
            sqlite_where=text("direction = 'execute' AND decision = 'requested'"),
        ),
        # One original execution maps to at most one compensation request
        # (a compensation runs under a fresh execution_id of its own).
        Index(
            "ux_execution_log_compensates_requested",
            "compensates_execution_id",
            unique=True,
            postgresql_where=text("decision = 'compensation_requested'"),
            sqlite_where=text("decision = 'compensation_requested'"),
        ),
    )

    # Insert-ordered UUIDv7 — the deterministic tie-break of the
    # (created_at DESC, id DESC) derived-state ordering. It is strictly
    # increasing within the writing process (one writer per chain), so a
    # created_at tie resolves to the true insertion order.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)

    # Caller-supplied idempotency key and execution identity: the first
    # request binds it to the approval_id / direction / server-side
    # action+target snapshot, and a replay carrying different facts is a 409.
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)

    # The approval this execution belongs to. For the execute direction it is
    # supplied by the request and validated; for compensation the server
    # inherits it from the original execution and the client never sends it.
    # ON DELETE NO ACTION: execution_log is append-only audit and must never
    # disappear along with a deleted approval. The project has no approval
    # deletion path today (all approval endpoints are GET/POST), so NO ACTION
    # changes nothing operationally — it only keeps the audit trail from
    # inheriting the CASCADE behaviour that fits business-relation FKs.
    approval_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("ai_response_approvals.id", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Audit vocabulary (see the module constants); the CHECK above limits it
    # to the legal decision x direction combinations.
    decision: Mapped[str] = mapped_column(String(32), nullable=False)

    # Which way the log reads: forward execution or compensating execution.
    direction: Mapped[str] = mapped_column(String(16), nullable=False)

    # Server-side snapshot of the approved recommendation's action and
    # target — never accepted from the request body, where a client-supplied
    # value is rejected with a 422.
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)

    # Compensation rows link back to the original execution's execution_id
    # (bidirectionally traceable); execute rows leave it NULL. Plain column,
    # not an FK: execution_id is a caller-supplied key, not a primary key.
    compensates_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, nullable=True, index=True
    )

    # Who executed: a free-form operator identifier (the platform is
    # protected by a shared secret and has no user system), recorded verbatim
    # for the audit trail and kept distinct from the approval reviewer.
    operator: Mapped[str] = mapped_column(String(128), nullable=False)

    # Guard rejection reasons, dispatch echo, adapter raw responses and
    # failure classification. It never contains the execution token.
    detail: Mapped[dict] = mapped_column(JSONVariant, nullable=False, default=dict)

    # Server clock only (as on AIResponseApproval.reviewed_at): the audit
    # trail cannot be backdated from the client. Append-only rows are never
    # updated, so there is no updated_at column.
    # Stamped by the database at INSERT, never by a Python process. SQLite
    # keeps CURRENT_TIMESTAMP; PostgreSQL production uses clock_timestamp()
    # (migration 0014). Ties are broken by the insert-ordered uuid7 id, so
    # chain ordering is deterministic on every dialect.
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
