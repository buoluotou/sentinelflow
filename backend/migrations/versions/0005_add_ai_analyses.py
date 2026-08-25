"""add ai_analyses table

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-25

Phase 2 Step 10: AI alert-explanation history. alert_group_id is indexed
but NOT unique — every analysis run appends a record (models change,
re-analysis is expected), unlike event_risk/incidents which are 1:1
"current state" rows.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("attack_type", sa.String(length=128), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("why_risky", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
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
            name=op.f("fk_ai_analyses_alert_group_id"),
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        op.f("ix_ai_analyses_alert_group_id"), "ai_analyses", ["alert_group_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_analyses_alert_group_id"), table_name="ai_analyses")
    op.drop_table("ai_analyses")
