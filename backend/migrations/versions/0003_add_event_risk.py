"""add event risk table

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-24

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "event_risk",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        # JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
        sa.Column("factors", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=True),
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
            name=op.f("fk_event_risk_alert_group_id"),
            ondelete="CASCADE",
        ),
        # One "current risk" per event: rescoring updates this row in place.
        sa.UniqueConstraint("alert_group_id", name=op.f("uq_event_risk_alert_group_id")),
    )
    op.create_index(
        op.f("ix_event_risk_alert_group_id"), "event_risk", ["alert_group_id"]
    )
    op.create_index(op.f("ix_event_risk_level"), "event_risk", ["level"])


def downgrade() -> None:
    op.drop_index(op.f("ix_event_risk_level"), table_name="event_risk")
    op.drop_index(op.f("ix_event_risk_alert_group_id"), table_name="event_risk")
    op.drop_table("event_risk")
