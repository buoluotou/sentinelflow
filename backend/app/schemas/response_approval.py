"""Pydantic schemas of the approval-queue API (Phase 2 Step 13.3).

Approve != Execute surfaces here as well: the decision request carries
ONLY who decided and why — no reviewed_at (the server stamps the audit
clock), no user/role/RBAC fields and nothing executable.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.response_recommendation import RecommendationItemRead


class ApprovalDecisionRequest(BaseModel):
    """Body of POST .../approve and .../reject.

    extra="forbid" is the schema-level guard: clients cannot smuggle
    reviewed_at (server-stamped in the service) or any future field past
    the frozen first-version contract.
    """

    model_config = ConfigDict(extra="forbid")

    reviewer: str = Field(min_length=1, max_length=128)
    review_comment: str | None = None


class AIResponseApprovalRead(BaseModel):
    """One recorded human decision. Approvals are INSERT-only: status is a
    terminal decision (approved / rejected) — "pending" never appears here
    because it is a derived queue state, not a stored value."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    recommendation_id: uuid.UUID
    status: str
    reviewer: str
    reviewed_at: datetime
    review_comment: str | None
    created_at: datetime
    updated_at: datetime


class PendingApprovalRead(BaseModel):
    """One Approval Queue entry: a recommendation with NO approval row yet.

    Embeds the full recommendation (read-only advice) plus the owning
    event id and title so the queue renders without extra round trips.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_id: uuid.UUID
    event_title: str
    provider: str
    model: str
    overall_rationale: str
    recommendations: list[RecommendationItemRead]
    confidence: float
    created_at: datetime
