import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# JSONB on PostgreSQL, plain JSON on other dialects (e.g. SQLite in tests)
JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class Alert(Base):
    """Aggregated, normalized security alert.

    Multiple raw security events may be deduplicated / aggregated into one
    Alert (Phase 1 Step 4). Each contributing event is stored as AlertEvent.
    """

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(32), nullable=False, default="medium", index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", index=True
    )

    title: Mapped[str | None] = mapped_column(String(512))
    message: Mapped[str | None] = mapped_column(Text)

    host_name: Mapped[str | None] = mapped_column(String(255), index=True)
    host_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64))
    user_name: Mapped[str | None] = mapped_column(String(255))

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(), index=True
    )
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    events: Mapped[list["AlertEvent"]] = relationship(
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertEvent.event_timestamp",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert id={self.id} type={self.event_type} severity={self.severity}>"


# Avoid circular import at module load time
from app.models.alert_event import AlertEvent  # noqa: E402,F401
