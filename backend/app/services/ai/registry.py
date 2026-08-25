"""Provider registry: settings -> configured AIProvider (Phase 2 Step 9).

Business code calls create_provider(settings) and only ever sees the
AIProvider contract — the concrete model (mock / local Ollama / any cloud
endpoint) is a deployment decision living in .env:

    AI_PROVIDER=mock|ollama|openai_compatible|cloud
    AI_MODEL, AI_BASE_URL, AI_API_KEY

"cloud" is an alias of openai_compatible (same protocol, different
deployment). Defaults to mock so the platform always runs, even air-gapped.
"""
from app.core.config import Settings
from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIProviderConfigError
from app.services.ai.mock import MockProvider
from app.services.ai.ollama import OllamaProvider
from app.services.ai.openai_compatible import OpenAICompatibleProvider

#: Names accepted in AI_PROVIDER; "cloud" is a deployment alias of the
#: OpenAI-compatible protocol, not a separate implementation.
PROVIDER_NAMES = ("mock", "ollama", "openai_compatible", "cloud")


def create_provider(settings: Settings) -> AIProvider:
    name = settings.AI_PROVIDER.strip().lower()
    if name == "mock":
        return MockProvider()
    if name == "ollama":
        return OllamaProvider(model=settings.AI_MODEL, base_url=settings.AI_BASE_URL)
    if name in ("openai_compatible", "cloud"):
        return OpenAICompatibleProvider(
            name=name,
            model=settings.AI_MODEL,
            base_url=settings.AI_BASE_URL,
            api_key=settings.AI_API_KEY,
        )
    raise AIProviderConfigError(
        f"Unknown AI_PROVIDER '{settings.AI_PROVIDER}' (expected one of {', '.join(PROVIDER_NAMES)})"
    )
