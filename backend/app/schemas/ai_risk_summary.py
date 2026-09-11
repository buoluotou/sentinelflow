"""Pydantic schemas of the AI risk-summary API."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AIRiskSummaryRead(BaseModel):
    """One AI risk summary as returned by the API.

Mirrors the ai_risk_summaries row field-for-field, so the response
carries the structured-output protocol (summary / key_findings /
risk_drivers / analyst_priority / confidence) that every provider must
produce. The payload holds no risk score: EventRisk.score remains the
authoritative one.
"""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_group_id: uuid.UUID
    provider: str
    model: str
    summary: str
    key_findings: list[str]
    risk_drivers: list[str]
    analyst_priority: str
    confidence: float
    created_at: datetime
    updated_at: datetime
