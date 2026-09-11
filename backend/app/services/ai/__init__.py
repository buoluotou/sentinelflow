"""AI provider layer and alert explanation.

Unified interface for AI analysis behind one contract — Incident and Risk
Engine code only ever sees AIProvider.explain(AIRequest) -> AIAnalysis.

AIProvider
├── MockProvider              deterministic, default (tests/demo/offline)
├── OllamaProvider            local model via /api/chat
└── OpenAICompatibleProvider  /chat/completions; "cloud" is an alias

This package owns the contract, the structured-output protocol (AIAnalysis),
the error taxonomy, the settings-based registry, the Event -> AIRequest
translation (build_alert_explanation) and the AIAnalysisService that
persists explanations as ai_analyses history. No provider executes any
response — AI output is advisory only and needs human approval through
AIResponseApprovalService before any action follows from it.
"""

from app.services.ai.base import AIProvider
from app.services.ai.exceptions import (
    AIProviderConfigError,
    AIProviderError,
    AIProviderUnavailable,
    AIResponseParseError,
)
from app.services.ai.mock import MockProvider
from app.services.ai.models import (
    RESPONSE_ACTIONS,
    RISK_DRIVERS,
    TASK_ALERT_EXPLANATION,
    TASK_RESPONSE_RECOMMENDATION,
    TASK_RISK_SUMMARY,
    AIAnalysis,
    AIRequest,
    RecommendationItem,
    ResponseRecommendation,
    RiskSummary,
)
from app.services.ai.ollama import OllamaProvider
from app.services.ai.openai_compatible import OpenAICompatibleProvider
from app.services.ai.protocol import (
    parse_analysis,
    parse_response_recommendation,
    parse_risk_summary,
    parse_task_output,
)
from app.services.ai.registry import create_provider
from app.services.ai.request_builder import (
    MAX_EVIDENCE,
    build_alert_explanation,
    build_response_recommendation_request,
    build_risk_summary_request,
)
from app.services.ai.response_approval_service import (
    AIResponseAlreadyReviewed,
    AIResponseApprovalNotFound,
    AIResponseApprovalService,
)
from app.services.ai.response_recommendation_service import AIResponseRecommendationService
from app.services.ai.risk_summary_service import AIRiskSummaryService, latest_summary_for
from app.services.ai.service import AIAnalysisService, AIEventNotFound

__all__ = [
    "AIAnalysis",
    "AIAnalysisService",
    "AIEventNotFound",
    "AIProvider",
    "AIProviderConfigError",
    "AIProviderError",
    "AIProviderUnavailable",
    "AIRequest",
    "AIResponseAlreadyReviewed",
    "AIResponseApprovalNotFound",
    "AIResponseApprovalService",
    "AIResponseParseError",
    "AIResponseRecommendationService",
    "AIRiskSummaryService",
    "MAX_EVIDENCE",
    "MockProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "RESPONSE_ACTIONS",
    "RISK_DRIVERS",
    "RecommendationItem",
    "ResponseRecommendation",
    "RiskSummary",
    "TASK_ALERT_EXPLANATION",
    "TASK_RESPONSE_RECOMMENDATION",
    "TASK_RISK_SUMMARY",
    "build_alert_explanation",
    "build_response_recommendation_request",
    "build_risk_summary_request",
    "create_provider",
    "latest_summary_for",
    "parse_analysis",
    "parse_response_recommendation",
    "parse_risk_summary",
    "parse_task_output",
]
