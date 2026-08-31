"""Credential / Secret Boundary (Phase 3.2.2, frozen design §8).

One independent, auditable boundary for every external-adapter
credential. The ONLY legal life of a secret is this chain:

    .env -> Settings -> AdapterCredentials -> Authorization header
                                              -> external request

Everywhere else the secret must appear as ``***`` and nowhere else:

    ❌ execution_log.detail     (redact gate in service._append)
    ❌ API response             (static error details; 503 mapping)
    ❌ exception string         (key names only; values never echoed)
    ❌ repr / str               (masked Settings + AdapterCredentials)
    ❌ URL / query string       (query strings & userinfo rejected)
    ❌ browser storage          (no secret is ever serialized out)
    ❌ audit detail             (redact gate, same as execution_log)
    ❌ Python logging           (SecretRedactionFilter)

Header-only discipline (frozen): credentials travel exclusively in the
``Authorization`` request header — ``Bearer <key>`` for api-key
adapters, ``Basic <b64>`` for the Wazuh user/password pair (3.2.4) —
never in the URL, a query string or a request body.

This module knows NO adapter business semantics — 3.2.3/3.2.4/3.2.5
build their HTTP calls ON this boundary, never around it.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.config import settings
from app.services.executions.exceptions import ExecutorConfigError

MASK = "***"

#: Detail keys (lowercased substring match) that are ALWAYS masked by
#: redact_detail regardless of value — the audit gate never trusts the
#: *name* a third party gave a field.
_SENSITIVE_DETAIL_KEY_MARKERS = (
    "authorization",
    "token",
    "key",
    "password",
    "secret",
    "credential",
)

#: Minimum length for value-based redaction: below this a "secret" is
#: too likely to be ordinary text (e.g. "id") and blind replacement
#: would corrupt legitimate detail.
_MIN_REDACTABLE_LENGTH = 4


def _is_sensitive_key(name: object) -> bool:
    lowered = str(name).lower()
    return any(marker in lowered for marker in _SENSITIVE_DETAIL_KEY_MARKERS)


# --------------------------------------------------------------------------
# URL / key validation (no secret may ever ride inside a URL)
# --------------------------------------------------------------------------
def validate_base_url(adapter: str, raw: str) -> str:
    """Validate and normalize an adapter BASE_URL.

    Accepted: http/https with a host. Rejected outright: query strings
    (``https://host/api?token=...`` is the classic secret-in-URL leak),
    fragments, userinfo (embedded ``user:pass@``), other schemes.
    Error messages name the setting and the REASON — never the value.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL is empty (value is never reported)")
    split = urlsplit(candidate)
    if split.scheme not in ("http", "https"):
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL must be an http(s) URL "
            "(value is never reported)")
    if not split.netloc:
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL must include a host "
            "(value is never reported)")
    if split.query:
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL must not contain a query string — "
            "secrets are NEVER allowed in URLs")
    if split.fragment:
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL must not contain a fragment")
    if split.username is not None or split.password is not None:
        raise ExecutorConfigError(
            f"{adapter.upper()}_BASE_URL must not embed userinfo "
            "(credentials belong in the Authorization header only)")
    return candidate.rstrip("/")


def validate_api_key(adapter: str, raw: str) -> str:
    """Validate one adapter API key: present and non-blank. Error
    messages never echo the key — key NAME only."""
    if not raw or not raw.strip():
        raise ExecutorConfigError(
            f"{adapter.upper()}_API_KEY is empty (value is never reported)")
    return raw.strip()


def validate_secret_field(setting_name: str, raw: str) -> str:
    """Generic non-blank gate for any credential field (3.2.4: Wazuh
    user/password). Error names the SETTING, never the value."""
    if not raw or not raw.strip():
        raise ExecutorConfigError(
            f"{setting_name} is empty (value is never reported)")
    return raw.strip()


@dataclass(frozen=True)
class AdapterCredentials:
    """One adapter's validated credential set.

    Immutable and repr-masked: str()/repr() can never surface a secret,
    so accidental interpolation into logs/exceptions/audit stays safe.
    Two shapes share the SAME lineage (.env -> Settings -> here ->
    Authorization header):
      * api_key adapters  -> ``Authorization: Bearer <key>``
      * user/password (3.2.4 Wazuh) -> ``Authorization: Basic <b64>``
    """

    adapter: str
    base_url: str
    api_key: str = ""
    username: str = ""
    password: str = ""

    def __repr__(self) -> str:
        return (
            f"AdapterCredentials(adapter={self.adapter!r}, "
            f"base_url={self.base_url!r}, api_key='{MASK}', "
            f"username={self.username!r}, password='{MASK}')"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def auth_headers(self) -> dict[str, str]:
        """Header-only discipline: the secret rides exclusively here."""
        if self.username and self.password:
            token = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            return {"Authorization": f"Basic {token}"}
        return {"Authorization": f"Bearer {self.api_key}"}


def credentials_from_settings(adapter: str, settings_obj=None) -> AdapterCredentials:
    """Assemble validated credentials for one adapter from Settings.

    Uses the registry's ADAPTER_REQUIRED_SETTINGS pairing, so each
    adapter validates EXACTLY its own two settings. Raises
    ExecutorConfigError with key names + reason only.
    """
    source = settings_obj if settings_obj is not None else settings
    pairs = {
        "shuffle": ("SHUFFLE_BASE_URL", "SHUFFLE_API_KEY"),
        "thehive": ("THEHIVE_BASE_URL", "THEHIVE_API_KEY"),
    }
    if adapter == "wazuh":
        # 3.2.4: user/password pair instead of an API key — same chain,
        # same fail-closed validation, Basic Authorization header.
        base_url = validate_base_url(adapter, getattr(source, "WAZUH_BASE_URL"))
        username = validate_secret_field(
            "WAZUH_API_USER", getattr(source, "WAZUH_API_USER"))
        password = validate_secret_field(
            "WAZUH_API_PASSWORD", getattr(source, "WAZUH_API_PASSWORD"))
        return AdapterCredentials(
            adapter=adapter, base_url=base_url, username=username, password=password
        )
    if adapter not in pairs:
        raise ExecutorConfigError(
            f"Unknown adapter '{adapter}' for credential assembly (selection error)")
    url_name, key_name = pairs[adapter]
    base_url = validate_base_url(adapter, getattr(source, url_name))
    api_key = validate_api_key(adapter, getattr(source, key_name))
    return AdapterCredentials(adapter=adapter, base_url=base_url, api_key=api_key)


# --------------------------------------------------------------------------
# Redaction (the platform-wide *** gate, frozen design §8)
# --------------------------------------------------------------------------
def current_secret_values(settings_obj=None) -> tuple[str, ...]:
    """Every live secret value held by Settings (empty values dropped).

    This is the substitution set for all redaction paths. Memory-only,
    process-lifetime — the same exposure class as holding the settings
    themselves, never widened."""
    source = settings_obj if settings_obj is not None else settings
    candidates = (
        source.SHUFFLE_API_KEY,
        source.WAZUH_API_PASSWORD,
        source.THEHIVE_API_KEY,
        source.EXECUTION_TOKEN,
    )
    return tuple(value.strip() for value in candidates if value and value.strip())


def redact_text(text: str, secrets_values: tuple[str, ...] | None = None) -> str:
    """Replace every known secret value in ``text`` with ``***``."""
    values = current_secret_values() if secrets_values is None else secrets_values
    redacted = text
    for value in values:
        if len(value) >= _MIN_REDACTABLE_LENGTH and value in redacted:
            redacted = redacted.replace(value, MASK)
    return redacted


def redact_detail(
    detail: dict,
    secrets_values: tuple[str, ...] | None = None,
) -> dict:
    """Project one audit-detail dict through the *** gate.

    Two independent masks:
    1. key-based — any key whose name smells like a credential
       (token / key / password / secret / authorization / credential)
       has its value replaced unconditionally, and
    2. value-based — any value equal to a known secret becomes ``***``.
    Nested dicts are projected recursively. Never mutates the input.
    """
    values = current_secret_values() if secrets_values is None else secrets_values
    return _redact_node(detail, values)  # type: ignore[return-value]


def _redact_node(node: object, values: tuple[str, ...]) -> object:
    if isinstance(node, dict):
        projected: dict = {}
        for key, value in node.items():
            if _is_sensitive_key(key):
                projected[key] = MASK
            else:
                projected[key] = _redact_node(value, values)
        return projected
    if isinstance(node, (list, tuple)):
        return [_redact_node(item, values) for item in node]
    if isinstance(node, str):
        return redact_text(node, values)
    return node


class SecretRedactionFilter(logging.Filter):
    """Logging-discipline filter: masks known secrets in every record.

    Constructed with an explicit secret set (typically
    ``current_secret_values()`` at startup) so the filter itself never
    re-reads Settings mid-request."""

    def __init__(self, secrets_values: tuple[str, ...] | None = None):
        super().__init__()
        self._secrets = (
            current_secret_values() if secrets_values is None else secrets_values
        )

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(str(record.msg), self._secrets)
        if record.args:
            record.args = tuple(
                redact_text(str(arg), self._secrets)
                if isinstance(arg, str)
                else arg
                for arg in (
                    record.args if isinstance(record.args, tuple) else (record.args,)
                )
            )
        return True
