import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import JSONVariant


class AIResponseRecommendation(Base):
    """One AI response recommendation of an event.

Fifth advisory artefact next to EventRisk / AIAnalysis / AIRiskSummary /
Incident; it is advisory throughout, nothing in this layer executes, and
a human approval sits between a recommendation and any action:

EventRisk              = the rule engine's objective score (the official score)
AIAnalysis             = the AI's explanation of the event
AIRiskSummary          = the AI's SOC-level synthesis
AIResponseRecommendation = the AI's suggested response posture
Incident               = the SOC's human case

An empty recommendations list is a valid record: it means the AI advises
no response action right now. History, not a snapshot: alert_group_id is
indexed but not unique, so every recommendation run appends a record, as
with ai_analyses and ai_risk_summaries.
"""

    __tablename__ = "ai_response_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The "event_id" of the recommendation — an event is an AlertGroup. No
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

    # Response-recommendation protocol: overall_rationale /
    # recommendations [{action, target, rationale}] / confidence, as
    # validated by the ResponseRecommendation schema. Actions are limited to
    # the RESPONSE_ACTIONS vocabulary; targets are analyst-facing strings,
    # not executable payloads.
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

    # The single human decision about this recommendation, if any: 1:1 and
    # final — at most one approval row per recommendation, and a decision is
    # not re-judged. None means the item is still "pending" in the approval
    # queue (a derived state, never persisted).
    approval: Mapped["AIResponseApproval | None"] = relationship(
        back_populates="recommendation", uselist=False
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AIResponseRecommendation group={self.alert_group_id} provider={self.provider}"
            f" actions={len(self.recommendations or [])}>"
        )


# Avoid circular import at module load time
from app.models.alert_group import AlertGroup  # noqa: E402,F401
from app.models.ai_response_approval import AIResponseApproval  # noqa: E402,F401
