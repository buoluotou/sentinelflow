import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Uuid, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.alert import JSONVariant


class EventRisk(Base):
    """Explainable risk assessment of one aggregated security event.

    Phase 1 Step 5: the Risk Engine scores every AlertGroup ("event") with a
    rule-based, fully explainable model — `factors` keeps the itemized
    breakdown (e.g. "+30 high frequency", "+20 external source") so SOC
    analysts can audit why a score was assigned, before any AI analysis is
    introduced.

    One row per event (unique alert_group_id): rescoring updates this row in
    place, keeping "current risk" a cheap O(1) join for the Events API.
    """

    __tablename__ = "event_risk"
    __table_args__ = (
        UniqueConstraint("alert_group_id", name="uq_event_risk_alert_group_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The "event_id" of the risk design — an event IS an AlertGroup.
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 0-100 composite score produced by the rule engine (Step 5.2).
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Derived from score: low (0-30) / medium (31-70) / high (71-90) /
    # critical (91-100). Thresholds live in the risk rules, not here.
    level: Mapped[str] = mapped_column(
        String(16), nullable=False, default="low", index=True
    )

    # Itemized, human-readable score breakdown, e.g.:
    # {"base": 40, "external_source": 20, "high_frequency": 30, "critical_asset": 10}
    factors: Mapped[dict | None] = mapped_column(JSONVariant)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    alert_group: Mapped["AlertGroup"] = relationship(back_populates="risk")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<EventRisk group={self.alert_group_id} score={self.score} level={self.level}>"


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
