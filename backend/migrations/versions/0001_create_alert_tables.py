"""create alert tables

Revision ID: 0001
Revises:
Create Date: 2026-08-24

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# JSONB on PostgreSQL, JSON elsewhere
json_variant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("host_name", sa.String(length=255), nullable=True),
        sa.Column("host_ip", sa.String(length=64), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
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
    op.create_index(op.f("ix_alerts_source"), "alerts", ["source"])
    op.create_index(op.f("ix_alerts_event_type"), "alerts", ["event_type"])
    op.create_index(op.f("ix_alerts_severity"), "alerts", ["severity"])
    op.create_index(op.f("ix_alerts_status"), "alerts", ["status"])
    op.create_index(op.f("ix_alerts_host_name"), "alerts", ["host_name"])
    op.create_index(op.f("ix_alerts_host_ip"), "alerts", ["host_ip"])
    op.create_index(op.f("ix_alerts_source_ip"), "alerts", ["source_ip"])
    op.create_index(op.f("ix_alerts_last_seen_at"), "alerts", ["last_seen_at"])

    op.create_table(
        "alert_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_data", json_variant, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alert_events_alert_id"), "alert_events", ["alert_id"])
    op.create_index(
        op.f("ix_alert_events_event_timestamp"), "alert_events", ["event_timestamp"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_events_event_timestamp"), table_name="alert_events")
    op.drop_index(op.f("ix_alert_events_alert_id"), table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_index(op.f("ix_alerts_last_seen_at"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_source_ip"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_host_ip"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_host_name"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_status"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_severity"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_event_type"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_source"), table_name="alerts")
    op.drop_table("alerts")
