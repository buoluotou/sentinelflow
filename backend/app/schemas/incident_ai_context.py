"""Read-only Incident AI context DTOs (Phase 2 Step 14.2).

The incident-centric case view is a pure AGGREGATION of existing history —
every AI artifact embeds its frozen protocol schema unchanged (Step 10
explanation, Step 11 risk summary, Step 12 recommendation, Step 13
approval); this file defines no second AI protocol and no writable field.
"""
import uuid

from pydantic import BaseModel, ConfigDict

from app.schemas.ai_analysis import AIAnalysisRead
from app.schemas.ai_risk_summary import AIRiskSummaryRead
from app.schemas.response_approval import AIResponseApprovalRead
from app.schemas.response_recommendation import AIResponseRecommendationRead


class IncidentSnapshot(BaseModel):
    """The case record, read-only.

    ``risk_score_snapshot`` is the creation-time COPY of EventRisk.score
    (Step 7 freeze) — the context service never recomputes, refreshes or
    exposes any live score.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    severity: str
    risk_score_snapshot: int


class RecommendationWithApproval(BaseModel):
    """One Step 12 recommendation plus its Step 13 audit trail.

    ``approval`` is None exactly when the recommendation is still pending —
    a DERIVED state that is never written to the database by the context
    service (or anywhere else).
    """

    recommendation: AIResponseRecommendationRead
    approval: AIResponseApprovalRead | None = None


class IncidentAIContext(BaseModel):
    """The complete AI context of one incident.

    Histories are complete (never truncated) and ordered created_at ASC,
    mirroring the Step 14.1 viewonly traversals they are composed from.
    """

    incident: IncidentSnapshot
    analyses: list[AIAnalysisRead]
    risk_summaries: list[AIRiskSummaryRead]
    response_recommendations: list[RecommendationWithApproval]
