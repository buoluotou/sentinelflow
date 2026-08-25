import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Incident(Base):
    """SOC case opened for one aggregated security event (AlertGroup).

    Phase 1 Step 7: an Incident is NOT an AlertGroup — it is the
    human-driven investigation/disposition context layered on top of it:

        Alert -> AlertGroup (event) -> EventRisk (automatic assessment)
              -> Incident (analyst case: investigate, resolve, close)

    One current Incident per event (unique alert_group_id), mirroring the
    event_risk design. ``risk_score`` is COPIED from EventRisk at creation
    time (a snapshot for the case record); EventRisk remains the live
    automatic assessment and the two never share computation logic.

    Status vocabulary (state machine enforced in Step 7.2, not here):
    open / in_progress / resolved / closed / false_positive.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("alert_group_id", name="uq_incidents_alert_group_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The event this case investigates — an event IS an AlertGroup.
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Case record fields, auto-filled from the event/risk at creation time.
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    # Snapshot of EventRisk.score when the incident was opened.
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Lifecycle position; allowed values and transitions live in the
    # Step 7.2 state machine, the model only stores the current value.
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", index=True
    )

    # Analyst's final call on the case (e.g. "contained", "benign"), set
    # together with a terminal status transition (Step 7.2).
    disposition: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    # Lifecycle checkpoints (nullable until the matching transition happens).
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    alert_group: Mapped["AlertGroup"] = relationship(back_populates="incident")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident id={self.id} group={self.alert_group_id} status={self.status}>"


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
