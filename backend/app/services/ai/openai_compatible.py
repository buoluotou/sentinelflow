"""OpenAI-compatible provider (Phase 2 Step 9).

Covers every endpoint speaking the /chat/completions protocol — this is also
the frozen path for "CloudProvider": a cloud model is a deployment-time
configuration (AI_PROVIDER=cloud + AI_BASE_URL + AI_API_KEY), not a separate
code path, so switching local/cloud models never touches business code.
"""
import json

from app.services.ai.base import AIProvider, SYSTEM_PROMPT, build_user_prompt
from app.services.ai.exceptions import (
    AIProviderConfigError,
    AIProviderUnavailable,
    AIResponseParseError,
)
from app.services.ai.models import AIAnalysis, AIRequest
from app.services.ai.protocol import parse_analysis
from app.services.ai.transport import Transport, http_post_json


class OpenAICompatibleProvider(AIProvider):
    name = "openai_compatible"

    def __init__(
        self,
        model: str,
        api_key: str | None,
        base_url: str = "",
        name: str | None = None,
        transport: Transport = http_post_json,
    ):
        if not model:
            raise AIProviderConfigError("OpenAICompatibleProvider requires AI_MODEL to be set")
        if not api_key:
            raise AIProviderConfigError("OpenAICompatibleProvider requires AI_API_KEY to be set")
        if not base_url:
            raise AIProviderConfigError("OpenAICompatibleProvider requires AI_BASE_URL to be set")
        super().__init__(model)
        if name:
            self.name = name
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._transport = transport

    def explain(self, request: AIRequest) -> AIAnalysis:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(request)},
            ],
            # OpenAI-native JSON mode; providers without it still get caught
            # by the strict output parsing.
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            body = self._transport(f"{self._base_url}/chat/completions", payload, headers)
        except AIProviderUnavailable:
            raise
        except Exception as exc:  # injected transports may raise raw types
            raise AIProviderUnavailable(f"Cannot reach {self.name} endpoint: {exc}") from exc

        try:
            envelope = json.loads(body)
            content = envelope["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise AIResponseParseError(f"Unexpected chat/completions response shape: {exc}") from exc
        return parse_analysis(content)
