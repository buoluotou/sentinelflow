"""add execution_log table

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-28

Phase 3.1.2: append-only execution audit log (design decision D7,
docs/design/phase3-response-execution.md §4). State is never stored —
it is DERIVED as the latest row per execution_id (created_at DESC,
id DESC). INSERT only: no UPDATE, no DELETE, ever.

Constraints mirrored 1:1 from app/models/execution_log.py:
- CHECK ck_execution_log_decision_direction: legal decision x direction
  combinations only (constraint 9).
- Partial unique index ux_execution_log_execution_id_requested: the
  idempotency key + execution identity (constraint 1, D14).
- Partial unique index ux_execution_log_approval_id_execute: at most one
  forward execution per approval — the single `requested` row of each
  chain (D12) is the lifecycle slot-holder; re-execution must insert a
  fresh requested row and is blocked here (constraint 2, frozen wording).
- Partial unique index ux_execution_log_compensates_requested: at most
  one compensation per original execution (constraint 3).

FK deletion behaviour (migration review 2026-08-28): approval_id uses
NO ACTION instead of CASCADE. execution_log is append-only audit and
must never be deleted along with an approval. Verified project reality:
no approval deletion path exists (all approval endpoints are GET/POST,
zero db.delete calls anywhere), so NO ACTION changes nothing
operationally — it only stops the audit trail from inheriting a CASCADE
behaviour copied unexamined from business-relation FKs. If an approval
deletion feature is ever added, it must be refused while executions
reference the approval.

The three partial unique indexes are emitted as raw SQL in both dialects:
alembic's create_index carries no SQLite partial-index support, so raw
CREATE UNIQUE INDEX ... WHERE ... is the only path that keeps SQLite
tests and PostgreSQL production byte-for-byte equivalent.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("approval_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("compensates_execution_id", sa.Uuid(), nullable=True),
        sa.Column("operator", sa.String(length=128), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("detail", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["approval_id"],
            ["ai_response_approvals.id"],
            name=op.f("fk_execution_log_approval_id"),
            ondelete="NO ACTION",
        ),
        sa.CheckConstraint(
            "(direction = 'execute' AND decision IN ("
            "'requested', 'guard_rejected', 'dispatched', 'succeeded', 'failed'))"
            " OR "
            "(direction = 'compensate' AND decision IN ("
            "'compensation_requested', 'compensation_succeeded', 'compensation_failed'))",
            name="ck_execution_log_decision_direction",
        ),
    )
    op.create_index(
        op.f("ix_execution_log_execution_id"),
        "execution_log",
        ["execution_id"],
    )
    op.create_index(
        op.f("ix_execution_log_approval_id"),
        "execution_log",
        ["approval_id"],
    )
    op.create_index(
        op.f("ix_execution_log_compensates_execution_id"),
        "execution_log",
        ["compensates_execution_id"],
    )
    # Partial unique indexes (constraints 1 / 2 / 3) — raw SQL so SQLite
    # and PostgreSQL enforce the exact same predicate.
    op.execute(
        "CREATE UNIQUE INDEX ux_execution_log_execution_id_requested "
        "ON execution_log (execution_id) WHERE decision = 'requested'"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_execution_log_approval_id_execute "
        "ON execution_log (approval_id) "
        "WHERE direction = 'execute' AND decision = 'requested'"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_execution_log_compensates_requested "
        "ON execution_log (compensates_execution_id) "
        "WHERE decision = 'compensation_requested'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX ux_execution_log_compensates_requested")
    op.execute("DROP INDEX ux_execution_log_approval_id_execute")
    op.execute("DROP INDEX ux_execution_log_execution_id_requested")
    op.drop_index(
        op.f("ix_execution_log_compensates_execution_id"),
        table_name="execution_log",
    )
    op.drop_index(op.f("ix_execution_log_approval_id"), table_name="execution_log")
    op.drop_index(op.f("ix_execution_log_execution_id"), table_name="execution_log")
    op.drop_table("execution_log")
