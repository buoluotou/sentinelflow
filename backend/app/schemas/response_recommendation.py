"""Pydantic schemas of the AI response-recommendation API (Phase 2 Step 12.3)."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RecommendationItemRead(BaseModel):
    """One recommended action as returned by the API.

    Advisory only: action comes from the frozen RESPONSE_ACTIONS
    vocabulary and target is an analyst-facing string — never an
    executable payload.
    """

    action: str
    target: str
    rationale: str


class AIResponseRecommendationRead(BaseModel):
    """One AI response recommendation as returned by the API.

    Mirrors the ai_response_recommendations row field-for-field; the frozen
    output protocol (overall_rationale / recommendations / confidence)
    surfaces unchanged. No risk score is ever included — EventRisk.score
    stays the only official score.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_group_id: uuid.UUID
    provider: str
    model: str
    overall_rationale: str
    recommendations: list[RecommendationItemRead]
    confidence: float
    created_at: datetime
    updated_at: datetime
