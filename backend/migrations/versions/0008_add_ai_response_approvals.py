"""add ai_response_approvals table

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-26

Human decisions over AI response recommendations. An approval is not an
execution: this table only records what a human decided, and no response
action is performed here. At most one approval per recommendation (unique
recommendation_id), and a decision is final (INSERT-only, no state-machine
UPDATEs). "pending" is a derived queue state and is never persisted: the
CHECK constraint restricts stored status to the terminal decisions
approved and rejected.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_response_approvals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("recommendation_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=128), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_comment", sa.Text(), nullable=True),
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
            ["recommendation_id"],
            ["ai_response_recommendations.id"],
            name=op.f("fk_ai_response_approvals_recommendation_id"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "status IN ('approved', 'rejected')",
            name="ck_ai_response_approvals_status",
        ),
        sa.UniqueConstraint(
            "recommendation_id", name="uq_ai_response_approvals_recommendation_id"
        ),
    )
    op.create_index(
        op.f("ix_ai_response_approvals_status"),
        "ai_response_approvals",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_ai_response_approvals_status"),
        table_name="ai_response_approvals",
    )
    op.drop_table("ai_response_approvals")
