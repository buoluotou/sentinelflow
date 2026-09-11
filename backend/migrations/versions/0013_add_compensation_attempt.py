"""add compensation_attempt table

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-10

Durable pre-compensation attempt record.

The forward dispatch path already has its durable pre-dispatch reservation
(migrations 0011 and 0012): the immutable binding commits on its own
transaction before the external request fires. The reverse (compensation) path
had no such protection — ``compensate_response`` flushed the
``compensation_requested`` row, called ``executor.compensate()`` and only then
appended the terminal row, all inside the caller's single business
transaction. A caller rollback, a terminal-write failure or a process crash
after the external reverse request had fired could erase every durable trace
of the attempt, and a later retry had no committed reservation to refuse it:
the partial unique index on execution_log.compensates_execution_id only bites
at caller COMMIT, after the wire call.

This table is an independent, append-only durable record committed on its own
transaction (a separate Session/connection) before the external compensation
request is sent, so it survives the caller's transaction outcome. The terminal
compensation row references the same compensation_attempt_id; recovery pairs a
committed attempt with no terminal row into a manual reconciliation candidate,
never an automatic retry.

Constraints mirrored 1:1 from app/models/compensation_attempt.py:
- Index ux_compensation_attempt_compensation_attempt_id (unique): the
correlation handle the terminal compensation row references
(detail["compensation_attempt_id"]).
- Index ux_compensation_attempt_execution_id (unique): one durable attempt per
compensation-chain execution_id — the replay guard.
- Index ux_compensation_attempt_original_execution_id (unique): one durable
compensation per original execution — the durable form of the "at most one
compensation per original" invariant, enforced before the reverse adapter
runs.
- Index ix_compensation_attempt_approval_id: the recovery /
manual-reconciliation lookup path.

No foreign keys, following the same precedent as dispatch_attempt,
execution_outcome and execution_log.compensates_execution_id: execution ids are
caller-supplied chain keys, not primary keys, and the durable attempt must not
cascade away because it is read-only evidence. Append-only: INSERT only, never
UPDATE, never DELETE. This migration touches only the new table —
execution_log's shape and its decision words are unaltered.
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
        # The compensation chain's own execution_id (fresh identity).
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
    # references. An attempt_id is never re-minted or reused.
    op.create_index(
        "ux_compensation_attempt_compensation_attempt_id",
        "compensation_attempt",
        ["compensation_attempt_id"],
        unique=True,
    )
    # One durable attempt per compensation-chain execution_id — the replay
    # guard, enforced before the reverse adapter runs.
    op.create_index(
        "ux_compensation_attempt_execution_id",
        "compensation_attempt",
        ["execution_id"],
        unique=True,
    )
    # One durable compensation per original execution — the durable form of the
    # "at most one compensation per original" invariant, enforced before the
    # reverse adapter runs.
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
