"""Read-only Incident AI context DTOs.

The incident-centric case view is composed from the incident's view-only
traversals, so it introduces no second AI protocol and no writable field:
each embedded AI artifact (explanation, risk summary, recommendation,
approval) keeps the protocol schema it was written with.
"""
import uuid

from pydantic import BaseModel, ConfigDict

from app.schemas.ai_analysis import AIAnalysisRead
from app.schemas.ai_risk_summary import AIRiskSummaryRead
from app.schemas.response_approval import AIResponseApprovalRead
from app.schemas.response_recommendation import AIResponseRecommendationRead


class IncidentSnapshot(BaseModel):
    """The case record, read-only.

``risk_score_snapshot`` is the copy of EventRisk.score taken when the
incident was created; the context service neither recomputes nor
refreshes it, so no live score is exposed here.
"""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    severity: str
    risk_score_snapshot: int


class RecommendationWithApproval(BaseModel):
    """One response recommendation plus the approval recorded for it.

``approval`` is None while the recommendation is still pending: the
context service derives that state from the absent audit row instead of
storing a "pending" value in the database.
"""

    recommendation: AIResponseRecommendationRead
    approval: AIResponseApprovalRead | None = None


class IncidentAIContext(BaseModel):
    """The complete AI context of one incident.

Each history is returned in full, ordered by created_at ascending to
match the view-only traversals it is composed from.
"""

    incident: IncidentSnapshot
    analyses: list[AIAnalysisRead]
    risk_summaries: list[AIRiskSummaryRead]
    response_recommendations: list[RecommendationWithApproval]
