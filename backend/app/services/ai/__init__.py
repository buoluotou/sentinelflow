"""AI provider layer (Phase 2 Step 9) + alert explanation (Step 10).

Unified interface for AI analysis behind one contract — Incident and Risk
Engine code only ever sees AIProvider.explain(AIRequest) -> AIAnalysis.

    AIProvider
    ├── MockProvider              deterministic, default (tests/demo/offline)
    ├── OllamaProvider            local model via /api/chat
    └── OpenAICompatibleProvider  /chat/completions; "cloud" is an alias

Frozen here: the contract, the structured-output protocol (AIAnalysis),
the error taxonomy and the settings-based registry. Step 10 adds the
Event -> AIRequest translation (build_alert_explanation) and the
AIAnalysisService that persists explanations as ai_analyses history.
No provider executes any response — AI output is advisory only
(approval gate lands in Step 13).
"""

from app.services.ai.base import AIProvider
from app.services.ai.exceptions import (
    AIProviderConfigError,
    AIProviderError,
    AIProviderUnavailable,
    AIResponseParseError,
)
from app.services.ai.mock import MockProvider
from app.services.ai.models import AIAnalysis, AIRequest
from app.services.ai.ollama import OllamaProvider
from app.services.ai.openai_compatible import OpenAICompatibleProvider
from app.services.ai.protocol import parse_analysis
from app.services.ai.registry import create_provider
from app.services.ai.request_builder import MAX_EVIDENCE, build_alert_explanation
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
    "AIResponseParseError",
    "MAX_EVIDENCE",
    "MockProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "build_alert_explanation",
    "create_provider",
    "parse_analysis",
]
