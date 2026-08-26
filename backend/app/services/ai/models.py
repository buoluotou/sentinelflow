"""Typed input/output models of the AI layer (Phase 2 Step 9).

AIRequest is the provider-agnostic description of an analysis job, built by
the caller from an Event + its EventRisk + evidence. AIAnalysis is the
frozen structured-output protocol every provider must produce for
alert_explanation; RiskSummary is the Step 11 protocol for risk_summary;
ResponseRecommendation is the Step 12 protocol for response_recommendation.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: Task vocabulary: providers are task-aware but task-agnostic in transport.
TASK_ALERT_EXPLANATION = "alert_explanation"
TASK_RISK_SUMMARY = "risk_summary"
TASK_RESPONSE_RECOMMENDATION = "response_recommendation"


class AIRequest(BaseModel):
    """What the caller wants analysed; providers turn this into a prompt."""

    #: Which analysis capability is requested — the provider picks the prompt
    #: and output protocol from this, never from caller-specific code paths.
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
    #: Optional Step 10 alert explanation, so risk_summary can synthesise on
    #: top of it instead of re-deriving everything (never a hard dependency).
    #: Structured projection {summary, attack_type, why_risky, confidence}
    #: or None; stays absent from the alert_explanation prompt (exclude_none).
    prior_explanation: dict | str | None = None
    #: Optional Step 11 risk summary, so response_recommendation can build on
    #: the SOC-level synthesis (never a hard dependency). Structured
    #: projection {summary, key_findings, risk_drivers, analyst_priority,
    #: confidence} or None; absent from the other tasks' prompts.
    prior_summary: dict | None = None


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


#: Frozen analyst-priority vocabulary (Step 11). NOT a risk-score rewrite:
#: EventRisk.score stays the only official score; this only expresses how
#: urgently the AI thinks an analyst should look at the event.
ANALYST_PRIORITIES = ("low", "medium", "high", "critical")
AnalystPriority = Literal["low", "medium", "high", "critical"]

#: Frozen risk-driver vocabulary v1 (Step 11): structured factor names, not
#: free text. Extensible in later steps — extending means updating this set.
RISK_DRIVERS = frozenset(
    {
        "high_frequency",
        "severity",
        "public_source",
        "high_risk_score",
        "suspicious_process",
        "authentication_abuse",
        "file_integrity_change",
        "web_anomaly",
        "malicious_ioc",
        "multiple_observables",
    }
)


class RiskSummary(BaseModel):
    """Frozen risk-summary protocol (Step 11):

    {"summary": str, "key_findings": [1..5 str], "risk_drivers": [vocabulary],
     "analyst_priority": low|medium|high|critical, "confidence": 0..1}

    Strict mode like AIAnalysis: unknown fields, out-of-vocabulary drivers or
    priorities fail validation and surface as AIResponseParseError (502).
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    key_findings: list[str] = Field(min_length=1, max_length=5)
    risk_drivers: list[str] = Field(min_length=1)
    analyst_priority: AnalystPriority
    confidence: float = Field(ge=0.0, le=1.0)


#: Frozen response-action vocabulary v1 (Step 12): what the AI is ALLOWED TO
#: SUGGEST. Advisory only end-to-end — nothing in this layer executes, and
#: Step 13 keeps human approval between a recommendation and any action.
#: "monitor_only" lets the AI say "watch, don't act". Extending means
#: updating this set (and the parser rejects anything else).
RESPONSE_ACTIONS = frozenset(
    {
        "block_source_ip",
        "isolate_host",
        "disable_account",
        "hunt_related_activity",
        "escalate_to_incident",
        "monitor_only",
    }
)


class RecommendationItem(BaseModel):
    """One frozen recommended action (Step 12).

    action comes from RESPONSE_ACTIONS (checked by the parser, like risk
    drivers); target is a structured analyst-facing string (e.g. the source
    IP or hostname — may be empty when nothing specific applies, e.g.
    monitor_only); rationale explains WHY in analyst terms. Never an
    executable payload: no commands, no API calls, no parameters for
    automation.
    """

    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1)
    target: str
    rationale: str = Field(min_length=1)


class ResponseRecommendation(BaseModel):
    """Frozen response-recommendation protocol (Step 12):

    {"overall_rationale": str, "recommendations": [0..5 RecommendationItem],
     "confidence": 0..1}

    An EMPTY recommendations list is a first-class answer: it means the AI
    advises no response action right now (the model must never invent
    actions to fill space). Strict mode like the other protocols: unknown
    fields, empty rationales or out-of-vocabulary actions fail validation
    and surface as AIResponseParseError (502, never persisted).
    """

    model_config = ConfigDict(extra="forbid")

    overall_rationale: str = Field(min_length=1)
    recommendations: list[RecommendationItem] = Field(max_length=5)
    confidence: float = Field(ge=0.0, le=1.0)
