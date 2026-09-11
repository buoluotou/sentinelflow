"""add execution_outcome table

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-03

Append-only external-outcome fact layer, independent of the dispatch log:
the dispatch log's eight decision words and its table shape are untouched
by this migration, and dispatch history semantics never change.

Constraints mirrored 1:1 from app/models/execution_outcome.py:
- CHECK ck_execution_outcome_status: the five outcome words
(unknown / pending / confirmed_success / confirmed_failure /
reconciliation_failed). Dispatch words such as 'succeeded' / 'failed'
are not legal here, so the two vocabularies cannot cross-contaminate.
- CHECK ck_execution_outcome_source: exactly the two ingress channels
(webhook / manual_reconcile). There is no third channel — background
polling is forbidden.
- Index ix_execution_outcome_execution_id: chain lookup.
- Index ix_execution_outcome_execution_id_observed_at: the derivation
query path; the latest observation wins. Non-unique, because multiple
facts per execution form the append-only time series and late or
reordered facts are appended, never rejected.

No foreign keys: execution_id is a caller-supplied chain key spread over
multiple dispatch-log rows, not a primary key — the same precedent as
execution_log.compensates_execution_id, which is a plain column too. The
link is read-only: outcome facts never write back into the dispatch log,
and neither table is ever deleted.
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
    # Derivation query path. Plain index — uniqueness would forbid the
    # append-only time series.
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
