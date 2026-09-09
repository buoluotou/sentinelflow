"""dispatch_attempt: unique approval-slot reservation

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-09

M4-G §1: close the same-approval concurrent dispatch race BEFORE any external
request. Migration 0011 created ``dispatch_attempt`` with a NON-unique
``ix_dispatch_attempt_approval_id`` (a recovery lookup path only). That left a
hole the M4-F review flagged: two DIFFERENT execution_ids sharing ONE
approval_id both pass the G3 lifecycle pre-check (each reads an empty
prior_approval_rows), both commit their durable attempt (only execution_id was
unique), and both fire the adapter — the execution_log partial approval index
(``ux_execution_log_approval_id_execute``) only bites at caller-commit, AFTER the
wire call already went out. D14's last line arrives too late to prevent the
second external action.

This migration promotes the approval lookup index to a UNIQUE reservation so the
second same-approval attempt is refused at its own independent commit, ahead of
the dispatch, and translated by the Execution Service into the SAME typed 409
(``ApprovalAlreadyExecuted``) the pre-check raises. Every ``dispatch_attempt``
row is execute-direction (``compensate_response`` never records one), so a plain
unique index carries the exact D14 "one execute per approval" semantics without a
direction qualifier.

SAFETY (M4-G §1, frozen): the migration NEVER silently deletes duplicate rows.
It first checks for existing approval_id collisions and REFUSES loudly if any are
found — a duplicate means durable append-only evidence that must be reconciled
out of band, never discarded by an upgrade. The append-only ``dispatch_attempt``
table is otherwise untouched: no row is UPDATEd or DELETEd, only the index shape
changes. execution_log's shape and its decision words are NOT altered (D3.4-05).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # M4-G §1 SAFETY: check for pre-existing approval_id collisions FIRST and
    # refuse to proceed if any exist. Creating a UNIQUE index over duplicated
    # data would fail anyway, but the requirement is explicit — never silently
    # drop or overwrite durable append-only evidence to make the upgrade "work".
    bind = op.get_bind()
    duplicates = bind.execute(
        sa.text(
            "SELECT approval_id, COUNT(*) AS n FROM dispatch_attempt "
            "GROUP BY approval_id HAVING COUNT(*) > 1"
        )
    ).fetchall()
    if duplicates:
        offending = ", ".join(f"{row[0]}x{row[1]}" for row in duplicates)
        raise RuntimeError(
            "Migration 0012 refused: dispatch_attempt already holds multiple "
            f"execute attempts for the same approval_id ({offending}). The unique "
            "approval-slot reservation cannot be created without discarding "
            "durable append-only evidence, which this migration NEVER does. "
            "Reconcile the duplicate attempts manually (out of band) before "
            "upgrading."
        )
    # Promote the non-unique recovery lookup index to the UNIQUE reservation.
    op.drop_index(
        op.f("ix_dispatch_attempt_approval_id"),
        table_name="dispatch_attempt",
    )
    op.create_index(
        "ux_dispatch_attempt_approval_id",
        "dispatch_attempt",
        ["approval_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ux_dispatch_attempt_approval_id",
        table_name="dispatch_attempt",
    )
    op.create_index(
        op.f("ix_dispatch_attempt_approval_id"),
        "dispatch_attempt",
        ["approval_id"],
    )
