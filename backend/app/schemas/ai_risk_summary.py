"""Pydantic schemas of the AI risk-summary API (Phase 2 Step 11.4)."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AIRiskSummaryRead(BaseModel):
    """One AI risk summary as returned by the API.

    Mirrors the ai_risk_summaries row field-for-field; the frozen output
    protocol (summary / key_findings / risk_drivers / analyst_priority /
    confidence) surfaces unchanged. No risk score is ever included —
    EventRisk.score stays the only official score.
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
