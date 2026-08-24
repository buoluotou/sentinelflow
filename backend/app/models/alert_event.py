import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.alert import JSONVariant


class AlertEvent(Base):
    """Raw security event as received from a data source.

    Keeps the original payload (JSONB) so future adapters (Wazuh, Simulator,
    ...) can always be audited back to the source event.
    """

    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    raw_data: Mapped[dict | None] = mapped_column(JSONVariant)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    alert: Mapped["Alert"] = relationship(back_populates="events")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AlertEvent id={self.id} alert_id={self.alert_id}>"


from app.models.alert import Alert  # noqa: E402,F401
