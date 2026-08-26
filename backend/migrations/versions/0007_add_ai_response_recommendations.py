"""add ai_response_recommendations table

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-26

Phase 2 Step 12: AI response-recommendation history. Advisory only —
this table stores suggestions, never executed actions (Step 13 keeps
human approval between a recommendation and anything executable).
alert_group_id is indexed but NOT unique — every recommendation run
appends a record, exactly like ai_analyses / ai_risk_summaries. An empty
recommendations JSON array is a valid record ("no action warranted").
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_response_recommendations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("overall_rationale", sa.Text(), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column(
            "recommendations",
            sa.JSON().with_variant(JSONB(), "postgresql"),
            nullable=False,
        ),
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
            name=op.f("fk_ai_response_recommendations_alert_group_id"),
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        op.f("ix_ai_response_recommendations_alert_group_id"),
        "ai_response_recommendations",
        ["alert_group_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_ai_response_recommendations_alert_group_id"),
        table_name="ai_response_recommendations",
    )
    op.drop_table("ai_response_recommendations")
