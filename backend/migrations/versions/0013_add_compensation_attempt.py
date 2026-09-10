"""add compensation_attempt table

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-10

RC2 / C-1 production debt fix: durable pre-compensation attempt record.

The forward dispatch path received its durable pre-dispatch reservation in
M4-F §1 / M4-G §2 (migration 0011/0012): the immutable binding commits on its
OWN transaction BEFORE the external request fires. The reverse (compensation)
path never got the same protection — ``compensate_response`` flushed the
``compensation_requested`` row, called ``executor.compensate()`` and only then
appended the terminal, all inside the caller's ONE business transaction. A
caller rollback / terminal-write failure / process crash AFTER the external
reverse request already fired could erase every durable trace of the attempt,
and a later retry had no committed reservation to refuse it (the partial
unique index on execution_log.compensates_execution_id only bites at caller
COMMIT — AFTER the wire call).

This table is an INDEPENDENT, append-only durable record committed on its OWN
transaction (a separate Session/connection) BEFORE the external compensation
request is sent, so it survives the caller's transaction outcome. The terminal
compensation row still references the SAME compensation_attempt_id; recovery
correlates a committed attempt with no terminal row -> a MANUAL reconciliation
candidate (never an auto-retry).

Constraints mirrored 1:1 from app/models/compensation_attempt.py:
- Index ux_compensation_attempt_compensation_attempt_id (UNIQUE): the
  correlation handle the terminal compensation row references
  (detail["compensation_attempt_id"]).
- Index ux_compensation_attempt_execution_id (UNIQUE): ONE durable attempt per
  compensation-chain execution_id — the replay guard.
- Index ux_compensation_attempt_original_execution_id (UNIQUE): ONE durable
  compensation per ORIGINAL execution — the C-1 durable reservation, enforced
  BEFORE the reverse adapter runs.
- Index ix_compensation_attempt_approval_id: the recovery /
  manual-reconciliation lookup path.

No foreign keys, deliberately (same precedent as dispatch_attempt /
execution_outcome / execution_log.compensates_execution_id): execution ids are
caller-supplied chain keys, not primary keys; the durable attempt must NOT
cascade away and is read-only evidence. Append-only: INSERT only, never UPDATE,
never DELETE. This migration touches ONLY the new table — execution_log's shape
and its decision words are NOT altered.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compensation_attempt",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("compensation_attempt_id", sa.Uuid(), nullable=False),
        # The COMPENSATION chain's own execution_id (fresh identity).
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        # The compensated forward execution (the reservation key).
        sa.Column("original_execution_id", sa.Uuid(), nullable=False),
        # The original chain's forward durable-attempt reference, when it
        # exists (NULL for old history / store-less mock runs).
        sa.Column("original_dispatch_attempt_id", sa.Uuid(), nullable=True),
        sa.Column("approval_id", sa.Uuid(), nullable=False),
        sa.Column("adapter", sa.String(length=64), nullable=False),
        sa.Column("reverse_action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("endpoint", sa.String(length=512), nullable=True),
        sa.Column("operator", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=True),
        sa.Column("original_outcome_state", sa.String(length=32), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
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
    # The unique compensation-attempt identifier the terminal compensation row
    # references. UNIQUE: an attempt_id is never re-minted or reused.
    op.create_index(
        "ux_compensation_attempt_compensation_attempt_id",
        "compensation_attempt",
        ["compensation_attempt_id"],
        unique=True,
    )
    # ONE durable attempt per compensation-chain execution_id — the replay
    # guard, enforced BEFORE the reverse adapter runs.
    op.create_index(
        "ux_compensation_attempt_execution_id",
        "compensation_attempt",
        ["execution_id"],
        unique=True,
    )
    # THE C-1 reservation: ONE durable compensation per ORIGINAL execution —
    # the durable refill of the "at most one compensation per original"
    # invariant, enforced BEFORE the reverse adapter runs.
    op.create_index(
        "ux_compensation_attempt_original_execution_id",
        "compensation_attempt",
        ["original_execution_id"],
        unique=True,
    )
    # Recovery / manual-reconciliation lookup by approval.
    op.create_index(
        op.f("ix_compensation_attempt_approval_id"),
        "compensation_attempt",
        ["approval_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_compensation_attempt_approval_id"),
        table_name="compensation_attempt",
    )
    op.drop_index(
        "ux_compensation_attempt_original_execution_id",
        table_name="compensation_attempt",
    )
    op.drop_index(
        "ux_compensation_attempt_execution_id",
        table_name="compensation_attempt",
    )
    op.drop_index(
        "ux_compensation_attempt_compensation_attempt_id",
        table_name="compensation_attempt",
    )
    op.drop_table("compensation_attempt")
