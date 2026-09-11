"""Executor registry: settings -> configured ResponseExecutor
(the same registry pattern the AI provider lineage uses).

Business code calls create_executor(settings) and only ever sees the
ResponseExecutor contract — which adapter runs is a deployment decision
living in .env:

    EXECUTION_ADAPTER=mock          (default; offline DryRun)

The registry knows shuffle / wazuh / thehive as recognized architecture
slots and validates their configuration fail-closed; shuffle implements
the workflow trigger only, wazuh the active response only, thehive case
creation. Selecting a slot without an implementation raises
ExecutorConfigError: never a silent mock fallback, never a fake adapter.

Single-Active-Adapter invariant: EXECUTION_ADAPTER names exactly ONE
adapter. Multi-values ("shuffle,wazuh", ...) are a configuration error —
the platform never fans out; cross-system coordination lives inside
Shuffle workflows, not here.

Error taxonomy (stable, sanitized — config errors name SETTINGS KEYS,
never values):
- configuration selection error: unknown / multi-valued adapter name;
- missing credential: a real adapter selected with incomplete config;
- invalid credential shape: a BASE_URL with a query string / userinfo /
  non-http(s) scheme — secrets must never ride in URLs;
- not-yet-implemented: a recognized slot with no implementation yet.
"""
from app.core.config import Settings
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.mock import MockExecutor
from app.services.executions.secrets import (
    credentials_from_settings,
    validate_base_url,
)
from app.services.executions.shuffle import (
    ShuffleExecutor,
    reverse_workflow_map_from_settings,
    workflow_map_from_settings,
)
from app.services.executions.thehive import TheHiveExecutor
from app.services.executions.wazuh import WazuhExecutor

# The adapters that have an implementation.
ADAPTER_NAMES = ("mock", "shuffle", "wazuh", "thehive")

# Recognized architecture slots: known names validated fail-closed on their
# configuration; all three now have implementations.
RECOGNIZED_ADAPTER_NAMES = ("shuffle", "wazuh", "thehive")

# Backwards-compatible alias kept for older tests/imports — same tuple, but a
# name in it now means a "recognized slot" rather than an "unknown" one.
RESERVED_ADAPTER_NAMES = RECOGNIZED_ADAPTER_NAMES

# Release that first shipped each adapter — informational only; every
# recognized slot has an implementation now.
_ADAPTER_LANDINGS = {"shuffle": "3.2.3", "wazuh": "3.2.4", "thehive": "3.2.5"}

# Per-adapter required settings names (one flat credential pair per adapter).
# mock requires nothing — local development must never be hostage to external
# credentials. Each real adapter validates only its own pair, never another
# adapter's.
ADAPTER_REQUIRED_SETTINGS = {
    "mock": (),
    "shuffle": ("SHUFFLE_BASE_URL", "SHUFFLE_API_KEY"),
    "wazuh": ("WAZUH_BASE_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"),
    "thehive": ("THEHIVE_BASE_URL", "THEHIVE_API_KEY"),
}

# Value separators that betray a multi-adapter attempt. A multi-value is
# never split or auto-picked — it is a hard configuration error.
_MULTI_SEPARATORS = (",", "+", "|", ";", " ")

# Every name the registry knows (deduped: shuffle is both an implemented
# adapter and a recognized slot, so it appears in both tuples).
KNOWN_ADAPTER_NAMES = ADAPTER_NAMES + tuple(
    name for name in RECOGNIZED_ADAPTER_NAMES if name not in ADAPTER_NAMES
)


def _normalized_adapter_name(settings: Settings) -> str:
    """Lower-cased adapter selection; refuses empty and multi-values
    (Single-Active-Adapter invariant). The raw value is never echoed in
    full — only the normalized token-safe form survives into errors."""
    name = settings.EXECUTION_ADAPTER.strip().lower()
    if not name:
        raise ExecutorConfigError(
            "EXECUTION_ADAPTER is empty — configuration selection error; "
            f"expected exactly one of {', '.join(KNOWN_ADAPTER_NAMES)}"
        )
    if any(sep in name for sep in _MULTI_SEPARATORS):
        raise ExecutorConfigError(
            "EXECUTION_ADAPTER must name exactly ONE adapter "
            "(Single-Active-Adapter invariant, frozen) — multi-value "
            "selections are never split or auto-picked; the platform "
            f"never fans out. Expected exactly one of "
            f"{', '.join(KNOWN_ADAPTER_NAMES)}"
        )
    return name


def validate_adapter_config(settings: Settings) -> None:
    """Startup fail-closed gate: selection + credentials only.

    No adapter construction, no network, no database. Error messages are
    stable and sanitized: they name missing SETTINGS KEYS, never values.
    Order matters: selection error (unknown / multi) -> missing
    credentials -> credential shape (BASE_URL must be http(s) without a
    query string / userinfo, so a secret can never ride in a URL).
    Implementation availability stays create_executor's job (a recognized
    slot with complete config still refuses when its implementation is
    missing — but that is "not implemented", not "missing credential")."""
    name = _normalized_adapter_name(settings)
    if name not in KNOWN_ADAPTER_NAMES:
        raise ExecutorConfigError(
            f"Unknown EXECUTION_ADAPTER '{name}' — configuration "
            f"selection error; expected exactly one of "
            f"{', '.join(KNOWN_ADAPTER_NAMES)}"
        )
    missing = [
        key
        for key in ADAPTER_REQUIRED_SETTINGS[name]
        if not str(getattr(settings, key, "") or "").strip()
    ]
    if missing:
        raise ExecutorConfigError(
            f"EXECUTION_ADAPTER '{name}' is missing required "
            f"configuration: {', '.join(missing)} (key names only — "
            "values are never reported). Refusing to start fail-closed."
        )
    # Shape gate: every present BASE_URL of the selected adapter must be a
    # clean http(s) base — query strings / userinfo are the classic
    # secret-in-URL leak and are rejected fail-closed.
    for key in ADAPTER_REQUIRED_SETTINGS[name]:
        if key.endswith("_BASE_URL"):
            validate_base_url(name, str(getattr(settings, key, "") or ""))
    # Fail-closed gate for real-adapter compensation: it is experimental and
    # not production-certified. The reverse path now has the durable
    # pre-dispatch reservation the forward path has (``compensation_attempt``,
    # migration 0013: the reverse binding commits on its own transaction BEFORE
    # the external request, with a durable one-compensation-per-original
    # reservation), but the reverse path still requires end-to-end lab
    # validation and a broader safety review before it leaves experimental. A
    # configured reverse workflow therefore requires the explicit
    # EXECUTION_COMPENSATION_EXPERIMENTAL acknowledgment; without it we refuse
    # to boot rather than silently enable a path that is not yet certified.
    # Only shuffle has reverse slots today; the offline mock is exempt (DryRun)
    # so demo compensation stays available regardless of the flag.
    if (
        name == "shuffle"
        and not settings.EXECUTION_COMPENSATION_EXPERIMENTAL
        and reverse_workflow_map_from_settings(settings)
    ):
        raise ExecutorConfigError(
            "EXECUTION_ADAPTER 'shuffle' has a REVERSE (compensation) workflow "
            "configured, but real-adapter compensation is EXPERIMENTAL / NOT "
            "PRODUCTION-CERTIFIED: the C-1 durable compensation reservation is "
            "implemented (migration 0013), but the reverse path still requires "
            "end-to-end lab validation before certification. Refusing to start "
            "fail-closed. For a lab only, acknowledge with "
            "EXECUTION_COMPENSATION_EXPERIMENTAL="
            "true; otherwise leave SHUFFLE_WORKFLOW_REVERSE_* empty (key names "
            "only — values are never reported)."
        )


def create_executor(settings: Settings) -> ResponseExecutor:
    validate_adapter_config(settings)
    name = settings.EXECUTION_ADAPTER.strip().lower()
    if name == "mock":
        return MockExecutor()
    if name == "shuffle":
        # Workflow-trigger adapter. Credentials ride the Secret Boundary; the
        # action -> workflow mapping is fail-closed (any empty workflow id is
        # a ConfigError naming keys only).
        return ShuffleExecutor(
            credentials_from_settings("shuffle", settings),
            workflow_map_from_settings(settings),
            reverse_workflows=reverse_workflow_map_from_settings(settings),
            timeout=settings.SHUFFLE_TIMEOUT_SECONDS,
        )
    if name == "wazuh":
        # Endpoint response provider. The action vocabulary
        # (isolate / disable / block) is fixed inside the adapter —
        # credentials + timeout are the whole configuration surface.
        return WazuhExecutor(
            credentials_from_settings("wazuh", settings),
            timeout=settings.WAZUH_TIMEOUT_SECONDS,
        )
    if name == "thehive":
        # Case creation provider (escalate_to_incident only). Credentials +
        # timeout are the whole configuration surface; the adapter never
        # compensates (case lifecycle is human-led).
        return TheHiveExecutor(
            credentials_from_settings("thehive", settings),
            timeout=settings.THEHIVE_TIMEOUT_SECONDS,
        )
    # Defensive tail — every recognized slot has an implementation today, so
    # this only fires for a future registered slot or code drift.
    raise ExecutorConfigError(
        f"EXECUTION_ADAPTER '{name}' is recognized but not implemented "
        f"yet; available: {', '.join(ADAPTER_NAMES)}. The platform never "
        "falls back to mock and never fakes an external adapter."
    )
