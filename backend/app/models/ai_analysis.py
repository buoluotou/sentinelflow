import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import JSONVariant


class AIAnalysis(Base):
    """One AI alert-explanation of an event (Phase 2 Step 10).

    Deliberately separate from EventRisk and Incident — the three never
    overwrite each other:

        EventRisk   = the rule engine's objective score
        AIAnalysis  = the AI's explanation of the event
        Incident    = the SOC's human case

    History, not a snapshot: alert_group_id is indexed but NOT unique, so
    every analysis run (model changes, re-analysis) appends a record.
    AI output is advisory only — nothing here ever alters risk or status.
    """

    __tablename__ = "ai_analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The "event_id" of the analysis — an event IS an AlertGroup. No unique
    # constraint: repeated analyses are kept as an analysis history.
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Which provider/model produced this analysis (e.g. "mock", "ollama").
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)

    # Frozen structured-output protocol (Step 9): summary / attack_type /
    # why_risky / confidence — exactly what AIAnalysis validated.
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(128), nullable=False)
    why_risky: Mapped[list] = mapped_column(JSONVariant, nullable=False)
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

    alert_group: Mapped["AlertGroup"] = relationship(back_populates="ai_analyses")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AIAnalysis group={self.alert_group_id} provider={self.provider}"
            f" attack_type={self.attack_type!r}>"
        )


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
