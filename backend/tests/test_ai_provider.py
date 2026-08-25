"""Step 9: AI Provider Architecture — contract tests, written red-first.

Scope frozen by the user: unified interface, configuration, error handling,
the structured-output protocol and a Mock Provider. No real model is called
anywhere in these tests: network providers run against an injected fake
transport. Ollama stays an interface target until Step 10.
"""
import json

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.services.ai import (
    AIAnalysis,
    AIProviderConfigError,
    AIProviderError,
    AIProviderUnavailable,
    AIRequest,
    AIResponseParseError,
    MockProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    create_provider,
    parse_analysis,
)


def _request(**overrides) -> AIRequest:
    base = dict(
        task="alert_explanation",
        event_title="Malicious IOC match detected",
        event_category="intrusion",
        severity="critical",
        risk_score=90,
        risk_level="high",
        risk_factors=[
            {"name": "severity", "score": 70, "reason": "critical severity base"},
            {"name": "frequency", "score": 20, "reason": "21-50 alerts"},
        ],
        evidence=["alert 1 raw payload", "alert 2 raw payload"],
    )
    base.update(overrides)
    return AIRequest(**base)


def _analysis_dict(**overrides) -> dict:
    base = {
        "summary": "IOC match with repeated hits.",
        "attack_type": "intrusion",
        "why_risky": ["known malicious indicator", "high frequency"],
        "confidence": 0.86,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- protocol


class TestProtocol:
    def test_valid_payload_parses(self):
        analysis = parse_analysis(json.dumps(_analysis_dict()))
        assert analysis.summary == "IOC match with repeated hits."
        assert analysis.attack_type == "intrusion"
        assert analysis.why_risky == ["known malicious indicator", "high frequency"]
        assert analysis.confidence == 0.86

    def test_json_fenced_output_is_unwrapped(self):
        fenced = "```json\n" + json.dumps(_analysis_dict()) + "\n```"
        assert parse_analysis(fenced).confidence == 0.86

    def test_surrounding_prose_is_tolerated(self):
        noisy = "Here is my analysis:\n" + json.dumps(_analysis_dict()) + "\nThanks!"
        assert parse_analysis(noisy).attack_type == "intrusion"

    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(AIResponseParseError):
            parse_analysis("definitely not json")

    def test_schema_violation_raises_parse_error(self):
        with pytest.raises(AIResponseParseError):
            parse_analysis(json.dumps(_analysis_dict(confidence=1.5)))

    def test_missing_field_raises_parse_error(self):
        payload = _analysis_dict()
        del payload["attack_type"]
        with pytest.raises(AIResponseParseError):
            parse_analysis(json.dumps(payload))

    def test_analysis_schema_is_strict(self):
        with pytest.raises(ValidationError):
            AIAnalysis(summary="s", attack_type="t", why_risky=[], confidence=0.5, extra=1)


# ------------------------------------------------------------- mock provider


class TestMockProvider:
    def test_name_and_model(self):
        provider = MockProvider()
        assert provider.name == "mock"
        assert provider.model == "mock-deterministic"

    def test_deterministic_shape(self):
        analysis = MockProvider().explain(_request())
        assert isinstance(analysis, AIAnalysis)
        assert 0.0 <= analysis.confidence <= 1.0
        assert analysis.why_risky  # non-empty
        # Same input -> identical output (tests and demos stay stable).
        assert analysis == MockProvider().explain(_request())

    def test_scripted_failure(self):
        provider = MockProvider(fail_with=AIProviderUnavailable("simulated outage"))
        with pytest.raises(AIProviderUnavailable):
            provider.explain(_request())


# ----------------------------------------------------------- ollama provider


class FakeTransport:
    """Injected stand-in for the HTTP layer: captures the request, returns
    a canned body or raises. Contract: (url, payload, headers) -> body str."""

    def __init__(self, body: str | None = None, exc: Exception | None = None):
        self.body = body
        self.exc = exc
        self.calls: list[tuple[str, dict]] = []
        self.last_headers: dict[str, str] = {}

    def __call__(self, url: str, payload: dict, headers: dict[str, str] | None = None) -> str:
        self.calls.append((url, payload))
        self.last_headers = headers or {}
        if self.exc is not None:
            raise self.exc
        assert self.body is not None
        return self.body


class TestOllamaProvider:
    def test_requires_model(self):
        with pytest.raises(AIProviderConfigError):
            OllamaProvider(model="")

    def test_request_shape(self):
        transport = FakeTransport(body=json.dumps({"message": {"content": json.dumps(_analysis_dict())}}))
        provider = OllamaProvider(model="llama3", transport=transport)
        analysis = provider.explain(_request())

        assert analysis.confidence == 0.86
        url, payload = transport.calls[0]
        assert url == "http://localhost:11434/api/chat"
        assert payload["model"] == "llama3"
        assert payload["format"] == "json"
        roles = [m["role"] for m in payload["messages"]]
        assert roles == ["system", "user"]
        # The prompt carries event context + factors + evidence.
        user_text = payload["messages"][1]["content"]
        assert "Malicious IOC match detected" in user_text
        assert "risk_factors" in user_text or "severity" in user_text

    def test_connection_failure_maps_to_unavailable(self):
        transport = FakeTransport(exc=ConnectionError("refused"))
        provider = OllamaProvider(model="llama3", transport=transport)
        with pytest.raises(AIProviderUnavailable):
            provider.explain(_request())

    def test_http_error_maps_to_unavailable(self):
        class Boom(RuntimeError):
            status = 500

        transport = FakeTransport(exc=Boom())
        provider = OllamaProvider(model="llama3", transport=transport)
        with pytest.raises(AIProviderUnavailable):
            provider.explain(_request())

    def test_bad_model_output_maps_to_parse_error(self):
        transport = FakeTransport(body=json.dumps({"message": {"content": "no json here"}}))
        provider = OllamaProvider(model="llama3", transport=transport)
        with pytest.raises(AIResponseParseError):
            provider.explain(_request())


# -------------------------------------------------- openai-compatible provider


class TestOpenAICompatibleProvider:
    def test_requires_api_key(self):
        with pytest.raises(AIProviderConfigError):
            OpenAICompatibleProvider(model="gpt-x", api_key=None)

    def test_request_shape_and_auth(self):
        transport = FakeTransport(
            body=json.dumps({"choices": [{"message": {"content": json.dumps(_analysis_dict())}}]})
        )
        provider = OpenAICompatibleProvider(
            name="cloud",
            model="gpt-x",
            base_url="https://api.example.com/v1",
            api_key="sk-test",
            transport=transport,
        )
        assert provider.name == "cloud"
        analysis = provider.explain(_request())
        assert analysis.attack_type == "intrusion"

        url, payload = transport.calls[0]
        assert url == "https://api.example.com/v1/chat/completions"
        assert payload["model"] == "gpt-x"
        assert payload["response_format"] == {"type": "json_object"}
        assert transport.last_headers["Authorization"] == "Bearer sk-test"

    def test_connection_failure_maps_to_unavailable(self):
        transport = FakeTransport(exc=ConnectionError("refused"))
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url="https://api.example.com/v1", transport=transport
        )
        with pytest.raises(AIProviderUnavailable):
            provider.explain(_request())

    def test_requires_base_url(self):
        with pytest.raises(AIProviderConfigError):
            OpenAICompatibleProvider(model="m", api_key="k")


# ------------------------------------------------------------------ registry


class TestRegistry:
    def test_default_is_mock(self):
        settings = Settings(_env_file=None)
        provider = create_provider(settings)
        assert provider.name == "mock"

    def test_explicit_mock(self):
        settings = Settings(_env_file=None, AI_PROVIDER="mock")
        assert create_provider(settings).name == "mock"

    def test_unknown_provider_rejected(self):
        settings = Settings(_env_file=None, AI_PROVIDER="nope")
        with pytest.raises(AIProviderConfigError):
            create_provider(settings)

    def test_ollama_from_settings(self):
        settings = Settings(_env_file=None, AI_PROVIDER="ollama", AI_MODEL="llama3")
        provider = create_provider(settings)
        assert isinstance(provider, OllamaProvider)
        assert provider.model == "llama3"

    def test_openai_compatible_needs_api_key(self):
        settings = Settings(_env_file=None, AI_PROVIDER="openai_compatible", AI_API_KEY=None)
        with pytest.raises(AIProviderConfigError):
            create_provider(settings)

    def test_cloud_is_openai_compatible_configuration(self):
        # CloudProvider is a deployment-time configuration of the
        # OpenAI-compatible endpoint, not a separate code path.
        settings = Settings(
            _env_file=None,
            AI_PROVIDER="cloud",
            AI_MODEL="gpt-x",
            AI_BASE_URL="https://api.example.com/v1",
            AI_API_KEY="sk-test",
        )
        provider = create_provider(settings)
        assert provider.name == "cloud"
        assert isinstance(provider, OpenAICompatibleProvider)

    def test_error_hierarchy(self):
        assert issubclass(AIProviderConfigError, AIProviderError)
        assert issubclass(AIProviderUnavailable, AIProviderError)
        assert issubclass(AIResponseParseError, AIProviderError)
