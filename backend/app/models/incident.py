import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Incident(Base):
    """SOC case opened for one aggregated security event (AlertGroup).

An Incident is not an AlertGroup: it is the human-driven
investigation/disposition context layered on top of it:

Alert -> AlertGroup (event) -> EventRisk (automatic assessment)
-> Incident (analyst case: investigate, resolve, close)

One current Incident per event (unique alert_group_id), as with
EventRisk. ``risk_score`` is copied from EventRisk at creation time (a
snapshot for the case record); EventRisk remains the live automatic
assessment and the two do not share computation logic.

Status vocabulary: open / in_progress / resolved / closed /
false_positive. The allowed transitions are enforced by the service
layer, not by this model.

The incident-centric case view: the AI results are not properties of the
incident, they remain the AlertGroup's append-only AI history. The
Incident connects the chain without owning it:

Incident -> alert_group -> ai_analyses
-> ai_risk_summaries
-> ai_response_recommendations
-> approval

The convenience traversals below are viewonly read projections over the
same alert_group_id — no new foreign key, no cascade, no write path.
Two boundaries hold:
- ``risk_score`` stays the creation-time snapshot of EventRisk.score; no
AI result writes it back
- an ``approved`` decision is displayed and audited, not consumed
automatically — the incident view performs no external execution
(no Shuffle / Wazuh / TheHive calls)
"""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("alert_group_id", name="uq_incidents_alert_group_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The event this case investigates — an event is an AlertGroup.
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

    # Lifecycle position; the allowed values and transitions are enforced by
    # the service layer, the model only stores the current value.
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open", index=True
    )

    # Analyst's final call on the case (e.g. "contained", "benign"), set
    # together with a terminal status transition.
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

    # Read-only case-view traversals (see class docstring). They join on the
    # same alert_group_id the AlertGroup relationships use, are viewonly
    # (not persisted or cascaded through the Incident) and mirror the
    # AlertGroup ordering: history, oldest first.
    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(
        "AIAnalysis",
        primaryjoin="Incident.alert_group_id == foreign(AIAnalysis.alert_group_id)",
        viewonly=True,
        order_by="AIAnalysis.created_at",
    )
    ai_risk_summaries: Mapped[list["AIRiskSummary"]] = relationship(
        "AIRiskSummary",
        primaryjoin="Incident.alert_group_id == foreign(AIRiskSummary.alert_group_id)",
        viewonly=True,
        order_by="AIRiskSummary.created_at",
    )
    ai_response_recommendations: Mapped[list["AIResponseRecommendation"]] = relationship(
        "AIResponseRecommendation",
        primaryjoin=(
            "Incident.alert_group_id == "
            "foreign(AIResponseRecommendation.alert_group_id)"
        ),
        viewonly=True,
        order_by="AIResponseRecommendation.created_at",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident id={self.id} group={self.alert_group_id} status={self.status}>"


# Avoid circular import at module load time
from app.models.ai_analysis import AIAnalysis  # noqa: E402,F401
from app.models.ai_response_recommendation import AIResponseRecommendation  # noqa: E402,F401
from app.models.ai_risk_summary import AIRiskSummary  # noqa: E402,F401
from app.models.alert_group import AlertGroup  # noqa: E402,F401
