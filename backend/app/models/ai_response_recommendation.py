import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import JSONVariant


class AIResponseRecommendation(Base):
    """One AI response recommendation of an event (Phase 2 Step 12).

    Fifth advisory artefact next to EventRisk / AIAnalysis / AIRiskSummary /
    Incident — advisory only end-to-end: nothing in this layer ever
    executes, and Step 13 keeps human approval between a recommendation and
    any action:

        EventRisk              = the rule engine's objective score (ONLY official score)
        AIAnalysis             = the AI's explanation of the event (Step 10)
        AIRiskSummary          = the AI's SOC-level synthesis (Step 11)
        AIResponseRecommendation = the AI's suggested response posture (Step 12)
        Incident               = the SOC's human case

    An EMPTY recommendations list is a valid record: it means the AI
    advises no response action right now. History, not a snapshot:
    alert_group_id is indexed but NOT unique, so every recommendation run
    appends a record, exactly like ai_analyses / ai_risk_summaries.
    """

    __tablename__ = "ai_response_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The "event_id" of the recommendation — an event IS an AlertGroup. No
    # unique constraint: repeated runs are kept as a history.
    alert_group_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("alert_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Which provider/model produced this recommendation (e.g. "mock", "ollama").
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)

    # Frozen response-recommendation protocol (Step 12): overall_rationale /
    # recommendations [{action, target, rationale}] / confidence — exactly
    # what the ResponseRecommendation pydantic model validated. actions come
    # from the frozen RESPONSE_ACTIONS vocabulary; targets are analyst-facing
    # strings, never executable payloads.
    overall_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSONVariant, nullable=False)
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

    alert_group: Mapped["AlertGroup"] = relationship(back_populates="ai_response_recommendations")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AIResponseRecommendation group={self.alert_group_id} provider={self.provider}"
            f" actions={len(self.recommendations or [])}>"
        )


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
