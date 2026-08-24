"""add alert groups table

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-24

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alert_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        # SHA256 hex digest; NOT unique on purpose — the same fingerprint may
        # open a new group once the aggregation window expires.
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
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
    )
    op.create_index(op.f("ix_alert_groups_fingerprint"), "alert_groups", ["fingerprint"])
    op.create_index(op.f("ix_alert_groups_status"), "alert_groups", ["status"])
    op.create_index(op.f("ix_alert_groups_last_seen"), "alert_groups", ["last_seen"])

    # Nullable link: legacy alerts keep alert_group_id = NULL until Step 4.4.
    # batch_alter_table keeps this portable across PostgreSQL and SQLite.
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.add_column(sa.Column("alert_group_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            op.f("fk_alerts_alert_group_id"),
            "alert_groups",
            ["alert_group_id"],
            ["id"],
        )
        batch_op.create_index(op.f("ix_alerts_alert_group_id"), ["alert_group_id"])


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_index(op.f("ix_alerts_alert_group_id"))
        batch_op.drop_constraint(op.f("fk_alerts_alert_group_id"), type_="foreignkey")
        batch_op.drop_column("alert_group_id")
    op.drop_index(op.f("ix_alert_groups_last_seen"), table_name="alert_groups")
    op.drop_index(op.f("ix_alert_groups_status"), table_name="alert_groups")
    op.drop_index(op.f("ix_alert_groups_fingerprint"), table_name="alert_groups")
    op.drop_table("alert_groups")
