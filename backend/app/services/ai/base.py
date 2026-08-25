"""AIProvider contract (Phase 2 Step 9).

One method — explain(request) -> AIAnalysis — shared by every provider, so
swapping Ollama for a cloud model never touches Incident or Risk Engine
code. The prompt is built HERE once and shared by all real providers: one
frozen prompt contract, one frozen output protocol.
"""
import json
from abc import ABC, abstractmethod

from app.services.ai.models import AIAnalysis, AIRequest

#: Frozen system prompt: identity + the structured-output contract. Real
#: providers must answer with JSON only; parsing stays strict regardless.
SYSTEM_PROMPT = (
    "You are a security operations analyst assistant. Analyse the provided "
    "security event and answer ONLY with a JSON object — no markdown, no "
    "prose — using exactly these fields:\n"
    '{"summary": string, "attack_type": string, "why_risky": array of '
    'strings, "confidence": number between 0 and 1}.'
)


def build_user_prompt(request: AIRequest) -> str:
    """Serialise the analysis job as JSON context for the model."""
    return json.dumps(request.model_dump(), ensure_ascii=False, indent=2)


class AIProvider(ABC):
    """Uniform contract: name/model for observability + explain()."""

    name: str = "base"

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def explain(self, request: AIRequest) -> AIAnalysis:
        """Run one analysis; raises AIProviderError subclasses on failure.
        Never returns a fabricated analysis for a broken provider output."""
