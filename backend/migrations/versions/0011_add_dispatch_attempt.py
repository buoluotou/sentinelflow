"""add dispatch_attempt table

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-09

M4-F §1: durable pre-dispatch attempt record. The M4 review found
"flush 不等于持久提交" — M4-A persisted the forward dispatch binding inside
the ``dispatched`` execution_log row with ``session.flush()`` BEFORE the
external request, but the Execution Service NEVER commits (the API caller
owns the ONE business transaction and commits AFTER the external request
returns). A flush is not a durable commit: a caller rollback / terminal-write
failure / process crash AFTER the external request already fired could erase
the binding exactly when the proof of "what was dispatched, where, when, under
which approval" is most needed.

This table is an INDEPENDENT, append-only durable record committed on its OWN
transaction (a separate Session/connection) BEFORE the external request is
sent, so it survives the caller's transaction outcome. The terminal
execution_log row still references the SAME attempt_id; recovery correlates a
committed attempt with no terminal row -> a MANUAL reconciliation candidate
(never an auto-retry).

Constraints mirrored 1:1 from app/models/dispatch_attempt.py:
- Index ux_dispatch_attempt_attempt_id (UNIQUE): the correlation handle the
  terminal execution_log row references (detail["dispatch_attempt_id"]).
- Index ux_dispatch_attempt_execution_id (UNIQUE): ONE durable attempt per
  execution_id — the race/idempotency guard that refuses a second committed
  attempt for a duplicate/concurrent replay BEFORE any external request
  (mirrors execution_log's D14 last line).
- Index ix_dispatch_attempt_approval_id: the recovery / manual-reconciliation
  lookup path.

No foreign keys, deliberately (same precedent as execution_outcome and
execution_log.compensates_execution_id): execution_id / approval_id are
caller-supplied chain keys, not primary keys; the durable attempt must NOT
cascade away and is read-only evidence. Append-only: INSERT only, never UPDATE,
never DELETE. This migration touches ONLY the new table — execution_log's shape
and its eight decision words are NOT altered (D3.4-05).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dispatch_attempt",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("approval_id", sa.Uuid(), nullable=False),
        sa.Column("adapter", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("dispatch_started_at", sa.DateTime(timezone=True), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("detail", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # The unique dispatch-attempt identifier the terminal execution_log row
    # references. UNIQUE: an attempt_id is never re-minted or reused.
    op.create_index(
        "ux_dispatch_attempt_attempt_id",
        "dispatch_attempt",
        ["attempt_id"],
        unique=True,
    )
    # ONE durable attempt per execution_id — the last line against a
    # duplicate/concurrent external request, enforced BEFORE the adapter runs.
    op.create_index(
        "ux_dispatch_attempt_execution_id",
        "dispatch_attempt",
        ["execution_id"],
        unique=True,
    )
    # Recovery / manual-reconciliation lookup by approval.
    op.create_index(
        op.f("ix_dispatch_attempt_approval_id"),
        "dispatch_attempt",
        ["approval_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_dispatch_attempt_approval_id"),
        table_name="dispatch_attempt",
    )
    op.drop_index(
        "ux_dispatch_attempt_execution_id",
        table_name="dispatch_attempt",
    )
    op.drop_index(
        "ux_dispatch_attempt_attempt_id",
        table_name="dispatch_attempt",
    )
    op.drop_table("dispatch_attempt")
