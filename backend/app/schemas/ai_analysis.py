"""Pydantic schemas of the AI analysis API."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AIAnalysisRead(BaseModel):
    """One AI alert-explanation as returned by the API.

Mirrors the ai_analyses row field-for-field, so the response carries the
structured-output protocol (summary / attack_type / why_risky /
confidence) that every provider must produce.
"""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_group_id: uuid.UUID
    provider: str
    model: str
    summary: str
    attack_type: str
    why_risky: list[str]
    confidence: float
    created_at: datetime
