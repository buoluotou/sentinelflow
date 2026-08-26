import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AlertGroup(Base):
    """Deduplicated group of alerts sharing the same fingerprint.

    Phase 1 Step 4: repeated normalized alerts with the same fingerprint
    inside the aggregation window are collapsed into one AlertGroup, while
    every individual alert is kept as evidence (alerts.alert_group_id).
    """

    __tablename__ = "alert_groups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # SHA256 hex digest (64 chars) of source + category + title + asset + actor.
    # Intentionally NOT unique: after the aggregation window expires, the same
    # fingerprint may open a brand new group.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", index=True
    )

    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(), index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    alerts: Mapped[list["Alert"]] = relationship(back_populates="alert_group")

    # Current risk assessment (Phase 1 Step 5), at most one per group.
    risk: Mapped["EventRisk | None"] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        uselist=False,
    )

    # Current SOC case (Phase 1 Step 7), at most one per group.
    incident: Mapped["Incident | None"] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        uselist=False,
    )

    # AI analysis history (Phase 2 Step 10): many per group, newest last.
    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        order_by="AIAnalysis.created_at",
    )

    # AI risk-summary history (Phase 2 Step 11): many per group, newest last.
    ai_risk_summaries: Mapped[list["AIRiskSummary"]] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        order_by="AIRiskSummary.created_at",
    )

    # AI response-recommendation history (Phase 2 Step 12): many per group,
    # newest last. Advisory only — nothing here ever executes an action.
    ai_response_recommendations: Mapped[list["AIResponseRecommendation"]] = relationship(
        back_populates="alert_group",
        cascade="all, delete-orphan",
        order_by="AIResponseRecommendation.created_at",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AlertGroup id={self.id} fingerprint={self.fingerprint[:12]}..."
            f" count={self.alert_count}>"
        )


# Avoid circular import at module load time
from app.models.ai_analysis import AIAnalysis  # noqa: E402,F401
from app.models.ai_response_recommendation import AIResponseRecommendation  # noqa: E402,F401
from app.models.ai_risk_summary import AIRiskSummary  # noqa: E402,F401
from app.models.alert import Alert  # noqa: E402,F401
from app.models.event_risk import EventRisk  # noqa: E402,F401
from app.models.incident import Incident  # noqa: E402,F401
