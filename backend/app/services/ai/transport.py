"""Minimal HTTP transport for the AI providers (Phase 2 Step 9).

Stdlib urllib only — no new dependency. Every provider takes an injectable
``transport`` callable ``(url, payload, headers) -> body str`` so tests and
future clients replace the network layer wholesale; the default is
``http_post_json``.
"""
import json
import urllib.error
import urllib.request
from collections.abc import Callable

from app.services.ai.exceptions import AIProviderUnavailable

DEFAULT_TIMEOUT_SECONDS = 60.0

#: Injectable HTTP layer: (url, json payload, optional headers) -> body text.
Transport = Callable[[str, dict, "dict[str, str] | None"], str]


def http_post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> str:
    """POST JSON and return the response body as text.

    All network-layer failures (refused, DNS, HTTP >= 400, timeout) map to
    AIProviderUnavailable — callers never see raw urllib types.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise AIProviderUnavailable(f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        raise AIProviderUnavailable(f"Cannot reach {url}: {exc}") from exc
