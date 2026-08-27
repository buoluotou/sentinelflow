import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# Approval vocabulary (Phase 2 Step 13.1, frozen): the queue STATES an item
# can show are pending / approved / rejected — but "pending" is DERIVED
# (a recommendation with no approval row), it is NEVER persisted. The only
# rows ever written carry a terminal human decision, hence the DB-level
# CHECK below. Execution-layer states (executing / executed / failed /
# rolled_back) are explicitly OUT of scope until Step 14 / Phase 3.
APPROVAL_STATUSES = frozenset({"pending", "approved", "rejected"})

# The only values a persisted AIResponseApproval.status may hold.
APPROVAL_DECISIONS = frozenset({"approved", "rejected"})


class AIResponseApproval(Base):
    """One human decision about one AI response recommendation (Step 13).

    Separation of concerns, frozen in 13.1:

        AIResponseRecommendation = what the AI suggested
        AIResponseApproval       = what a human decided about it

    Approve ≠ Execute: writing this row only records the decision. It never
    blocks an IP, isolates a host, creates an Incident, calls Shuffle or
    touches EventRisk — actual execution stays behind Step 14 / Phase 3.

    At most ONE approval per recommendation (unique recommendation_id) and a
    decision is final: no re-judging; a fresh recommendation means a fresh
    approval. Pending is derived, not stored — rows are INSERT-only, never
    UPDATEd through a state machine, mirroring the append-only discipline
    of Steps 10–12.
    """

    __tablename__ = "ai_response_approvals"
    __table_args__ = (
        UniqueConstraint(
            "recommendation_id", name="uq_ai_response_approvals_recommendation_id"
        ),
        # Storage-level guard: only terminal human decisions ever persist —
        # "pending" (derived) and any execution-layer word are rejected here.
        CheckConstraint(
            "status IN ('approved', 'rejected')",
            name="ck_ai_response_approvals_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    # The recommendation this decision applies to — 1:1 and final.
    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("ai_response_recommendations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Terminal human decision: "approved" or "rejected" (CHECK above).
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Who decided. Free-form operator identifier: the platform has no
    # authentication yet (Phase 1 known limitation), the API requires a
    # non-empty value and records it verbatim for the audit trail.
    reviewer: Mapped[str] = mapped_column(String(128), nullable=False)

    # When the decision was made — server clock at decision time, never
    # accepted from the client (the audit trail cannot be backdated).
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Optional free-text justification; empty/absent is a valid decision.
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=lambda: datetime.now(),
    )

    recommendation: Mapped["AIResponseRecommendation"] = relationship(
        back_populates="approval"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AIResponseApproval id={self.id} "
            f"recommendation={self.recommendation_id} status={self.status}>"
        )


# Avoid circular import at module load time
from app.models.ai_response_recommendation import AIResponseRecommendation  # noqa: E402,F401
