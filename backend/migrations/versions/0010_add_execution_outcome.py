"""add execution_outcome table

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-03

Phase 3.4.1: append-only external-outcome fact layer (design doc
docs/design/phase3.4-execution-outcome-lifecycle.md §4, adjudications
O1/O2/O5). INDEPENDENT layer over execution_log — the dispatch log's
eight decision words and its table shape are NOT touched by this
migration (D3.4-05: dispatch history semantics never change).

Constraints mirrored 1:1 from app/models/execution_outcome.py:
- CHECK ck_execution_outcome_status: the five frozen outcome words
  (unknown / pending / confirmed_success / confirmed_failure /
  reconciliation_failed). Dispatch words like 'succeeded' / 'failed'
  are deliberately NOT legal here — the two vocabularies never
  cross-contaminate (D3.4-04).
- CHECK ck_execution_outcome_source: exactly the two frozen ingress
  channels (webhook / manual_reconcile). No third channel exists —
  background polling is forbidden (D3.4-03).
- Index ix_execution_outcome_execution_id: chain lookup.
- Index ix_execution_outcome_execution_id_observed_at: the derivation
  query path (O2 — latest observation wins). NON-unique BY DESIGN:
  multiple facts per execution form the append-only time series
  (D3.4-06); late/reordered facts are appended, never rejected.

No foreign keys, deliberately: execution_id is a caller-supplied chain
key spread over multiple dispatch-log rows, not a primary key (same
precedent as execution_log.compensates_execution_id, which is a plain
column too). The link is read-only — outcome facts never write back
into the dispatch log, and no deletion semantics exist between the two
tables (both are append-only audit; neither is ever deleted).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_outcome",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column("outcome_status", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("operator", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("detail", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "outcome_status IN ("
            "'unknown', 'pending', 'confirmed_success', "
            "'confirmed_failure', 'reconciliation_failed')",
            name="ck_execution_outcome_status",
        ),
        sa.CheckConstraint(
            "source IN ('webhook', 'manual_reconcile')",
            name="ck_execution_outcome_source",
        ),
    )
    op.create_index(
        op.f("ix_execution_outcome_execution_id"),
        "execution_outcome",
        ["execution_id"],
    )
    # Derivation query path (O2). Plain index — uniqueness would forbid
    # the append-only time series and is deliberately absent.
    op.create_index(
        "ix_execution_outcome_execution_id_observed_at",
        "execution_outcome",
        ["execution_id", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_outcome_execution_id_observed_at",
        table_name="execution_outcome",
    )
    op.drop_index(
        op.f("ix_execution_outcome_execution_id"),
        table_name="execution_outcome",
    )
    op.drop_table("execution_outcome")
