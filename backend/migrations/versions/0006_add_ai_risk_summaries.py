"""add ai_risk_summaries table

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-26

Phase 2 Step 11: AI risk-summary history. alert_group_id is indexed but
NOT unique — every summary run appends a record (models/prompts change,
re-summarising is expected), exactly like ai_analyses. analyst_priority is
advisory only; event_risk stays the single source of truth for scores.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_risk_summaries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("key_findings", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("risk_drivers", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("analyst_priority", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["alert_group_id"],
            ["alert_groups.id"],
            name=op.f("fk_ai_risk_summaries_alert_group_id"),
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        op.f("ix_ai_risk_summaries_alert_group_id"), "ai_risk_summaries", ["alert_group_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_risk_summaries_alert_group_id"), table_name="ai_risk_summaries")
    op.drop_table("ai_risk_summaries")
