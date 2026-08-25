"""Ollama provider — local model via the /api/chat endpoint (Phase 2 Step 9).

Interface only at this step: the provider speaks Ollama's HTTP protocol and
parses its answer through the frozen structured-output protocol, but no
Ollama instance is exercised until Step 10. The transport is injectable so
tests replace the network wholesale.
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

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"


class OllamaProvider(AIProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        transport: Transport = http_post_json,
        timeout: float | None = None,
    ):
        if not model:
            raise AIProviderConfigError("OllamaProvider requires AI_MODEL to be set")
        super().__init__(model)
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._timeout = timeout

    def explain(self, request: AIRequest) -> AIAnalysis:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(request)},
            ],
            # Ollama-native JSON mode: the model is constrained to emit JSON.
            "format": "json",
            "stream": False,
        }
        try:
            kwargs = {} if self._timeout is None else {"timeout": self._timeout}
            body = self._transport(f"{self._base_url}/api/chat", payload, None, **kwargs)
        except AIProviderUnavailable:
            raise
        except Exception as exc:  # injected transports may raise raw types
            raise AIProviderUnavailable(f"Cannot reach Ollama: {exc}") from exc

        try:
            envelope = json.loads(body)
            content = envelope["message"]["content"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AIResponseParseError(f"Unexpected Ollama response shape: {exc}") from exc
        return parse_analysis(content)
