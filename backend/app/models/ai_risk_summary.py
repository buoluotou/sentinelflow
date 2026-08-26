import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import JSONVariant


class AIRiskSummary(Base):
    """One AI risk summary of an event (Phase 2 Step 11).

    Fourth advisory artefact next to EventRisk / AIAnalysis / Incident —
    responsibilities stay isolated, nothing overwrites anything else:

        EventRisk     = the rule engine's objective score (ONLY official score)
        AIAnalysis    = the AI's explanation of the event (Step 10)
        AIRiskSummary = the AI's SOC-level synthesis: what deserves attention
        Incident      = the SOC's human case

    analyst_priority is advisory triage guidance, never a recomputed risk
    score. History, not a snapshot: alert_group_id is indexed but NOT unique,
    so every summary run (model/prompt/event-state changes) appends a record.
    """

    __tablename__ = "ai_risk_summaries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The "event_id" of the summary — an event IS an AlertGroup. No unique
    # constraint: repeated summaries are kept as a history.
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Which provider/model produced this summary (e.g. "mock", "ollama").
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)

    # Frozen risk-summary protocol (Step 11): summary / key_findings /
    # risk_drivers / analyst_priority / confidence — exactly what the
    # RiskSummary pydantic model validated.
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    key_findings: Mapped[list] = mapped_column(JSONVariant, nullable=False)
    risk_drivers: Mapped[list] = mapped_column(JSONVariant, nullable=False)
    analyst_priority: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    alert_group: Mapped["AlertGroup"] = relationship(back_populates="ai_risk_summaries")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AIRiskSummary group={self.alert_group_id} provider={self.provider}"
            f" priority={self.analyst_priority!r}>"
        )


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
