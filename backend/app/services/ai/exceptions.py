"""Exception hierarchy of the AI provider layer.

All AI-layer failures are AIProviderError; callers catch the base class.
An unavailable model or a broken output surfaces as a typed exception
instead of being swallowed.
"""


class AIProviderError(Exception):
    """Base class for every AI-layer failure."""


class AIProviderConfigError(AIProviderError):
    """Misconfiguration: unknown provider, missing model/api_key."""


class AIProviderUnavailable(AIProviderError):
    """The provider cannot be reached (connection refused, HTTP error,
timeout). The caller may retry later; nothing was computed."""


class AIResponseParseError(AIProviderError):
    """The provider answered, but the output is not the structured protocol
(invalid JSON or schema violation). A broken response is rejected, never
replaced by a fabricated fallback analysis."""
