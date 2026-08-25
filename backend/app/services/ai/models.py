"""Typed input/output models of the AI layer (Phase 2 Step 9).

AIRequest is the provider-agnostic description of an analysis job, built by
the caller from an Event + its EventRisk + evidence. AIAnalysis is the
frozen structured-output protocol every provider must produce.
"""
from pydantic import BaseModel, ConfigDict, Field


class AIRequest(BaseModel):
    """What the caller wants analysed; providers turn this into a prompt."""

    #: Which analysis capability is requested (Step 10 starts with
    #: "alert_explanation"; later steps add "risk_summary", "recommendation").
    task: str
    event_title: str
    event_category: str
    severity: str
    risk_score: int
    risk_level: str
    #: Frozen Risk Engine factor breakdown [{name, score, reason}].
    risk_factors: list[dict]
    #: Bounded evidence sample (raw payloads / alert summaries).
    evidence: list[str]


class AIAnalysis(BaseModel):
    """Frozen structured-output protocol (Step 9):

    {"summary": str, "attack_type": str, "why_risky": [str], "confidence": 0..1}

    Strict mode: unknown fields fail validation so provider drift is caught
    at the boundary instead of polluting downstream consumers.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    attack_type: str
    why_risky: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
