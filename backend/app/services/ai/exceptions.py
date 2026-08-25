"""Exception hierarchy of the AI provider layer (Phase 2 Step 9).

All AI-layer failures are AIProviderError; callers catch the base class.
Nothing here is ever swallowed silently — an unavailable model or a broken
output surfaces as a typed exception.
"""


class AIProviderError(Exception):
    """Base class for every AI-layer failure."""


class AIProviderConfigError(AIProviderError):
    """Misconfiguration: unknown provider, missing model/api_key."""


class AIProviderUnavailable(AIProviderError):
    """The provider cannot be reached (connection refused, HTTP error,
    timeout). The caller may retry later; nothing was computed."""


class AIResponseParseError(AIProviderError):
    """The provider answered, but the output is not the frozen structured
    protocol (invalid JSON or schema violation). Never fabricate a fallback
    analysis from a broken response."""
