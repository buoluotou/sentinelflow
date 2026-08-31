"""Executor registry: settings -> configured ResponseExecutor
(Phase 3.1.5 core + Phase 3.2.1 architecture, mirrors the AI provider
registry lineage).

Business code calls create_executor(settings) and only ever sees the
ResponseExecutor contract — which adapter runs is a deployment decision
living in .env:

    EXECUTION_ADAPTER=mock          (default; offline DryRun)

3.2.1 evolution (frozen design): shuffle / wazuh / thehive moved from
RESERVED to RECOGNIZED architecture slots — the registry KNOWS them and
validates their configuration fail-closed. Their implementations land in
Phase 3.2.3-3.2.5; until then selecting one raises ExecutorConfigError:
NEVER a silent mock fallback, NEVER a fake adapter.

Single-Active-Adapter invariant (frozen, design §3): EXECUTION_ADAPTER
names exactly ONE adapter. Multi-values ("shuffle,wazuh", ...) are a
configuration error — the platform never fans out; cross-system
coordination lives inside Shuffle workflows, not here.

Error taxonomy (stable, sanitized — config errors name SETTINGS KEYS,
never values):
- configuration selection error: unknown / multi-valued adapter name;
- missing credential: a real adapter selected with incomplete config;
- not-yet-implemented: a recognized slot whose code lands in 3.2.3+.
"""
from app.core.config import Settings
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.mock import MockExecutor

#: The implemented adapters (mock only until the 3.2.3+ adapters land).
ADAPTER_NAMES = ("mock",)

#: Recognized architecture slots (3.2.1): known names with fail-closed
#: configuration validation; implementations land in Phase 3.2.3-3.2.5.
RECOGNIZED_ADAPTER_NAMES = ("shuffle", "wazuh", "thehive")

#: 3.1-era alias kept for frozen 3.1 tests/imports — same tuple, evolved
#: semantics ("recognized-but-unimplemented", not "unknown").
RESERVED_ADAPTER_NAMES = RECOGNIZED_ADAPTER_NAMES

#: Where each recognized slot's implementation lands (frozen design §11).
_ADAPTER_LANDINGS = {"shuffle": "3.2.3", "wazuh": "3.2.4", "thehive": "3.2.5"}

#: Per-adapter REQUIRED settings names (E3 frozen: one flat *_BASE_URL /
#: *_API_KEY pair per adapter). mock requires NOTHING — local development
#: must never be hostage to external credentials. Each real adapter
#: validates ONLY its own pair, never another adapter's.
ADAPTER_REQUIRED_SETTINGS = {
    "mock": (),
    "shuffle": ("SHUFFLE_BASE_URL", "SHUFFLE_API_KEY"),
    "wazuh": ("WAZUH_BASE_URL", "WAZUH_API_KEY"),
    "thehive": ("THEHIVE_BASE_URL", "THEHIVE_API_KEY"),
}

#: Value separators that betray a multi-adapter attempt. A multi-value is
#: NEVER split or auto-picked — it is a hard configuration error.
_MULTI_SEPARATORS = (",", "+", "|", ";", " ")

#: Every name the registry knows (deduped).
KNOWN_ADAPTER_NAMES = ADAPTER_NAMES + tuple(
    name for name in RECOGNIZED_ADAPTER_NAMES if name not in ADAPTER_NAMES
)


def _normalized_adapter_name(settings: Settings) -> str:
    """Lower-cased adapter selection; refuses empty and multi-values
    (Single-Active-Adapter invariant). The RAW value is never echoed in
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
    """Startup fail-closed gate (3.2.1): selection + credentials ONLY.

    No adapter construction, no network, no database. Error messages are
    stable and sanitized: they name missing SETTINGS KEYS, never values.
    Implementation availability stays create_executor's job (a
    recognized slot with COMPLETE config still refuses until its
    3.2.3+ code lands — but that is "not implemented", not "missing
    credential")."""
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


def create_executor(settings: Settings) -> ResponseExecutor:
    validate_adapter_config(settings)
    name = settings.EXECUTION_ADAPTER.strip().lower()
    if name == "mock":
        return MockExecutor()
    # Recognized slot, implementation lands in Phase 3.2.3+. Until then:
    # ConfigError, never a mock fallback, never a fake.
    raise ExecutorConfigError(
        f"EXECUTION_ADAPTER '{name}' is recognized but not implemented "
        f"yet (lands in Phase {_ADAPTER_LANDINGS[name]}); available: "
        f"{', '.join(ADAPTER_NAMES)}. The platform never falls back to "
        "mock and never fakes an external adapter."
    )
