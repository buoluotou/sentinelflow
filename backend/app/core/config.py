from pathlib import Path

from pydantic_settings import BaseSettings

# backend/app/core/config.py -> parents[3] is the monorepo root (.env lives there)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

#: Field names whose VALUES must never surface in repr/str (3.2.1 secret
#: discipline, mirrors the EXECUTION_TOKEN lineage). Names of the keys
#: ARE reportable (config errors name missing keys); values are not.
_SENSITIVE_FIELD_NAMES = frozenset({"DATABASE_URL", "OPERATORS_JSON"})
_SENSITIVE_FIELD_SUFFIXES = ("API_KEY", "TOKEN", "PASSWORD")


def _is_sensitive_field(name: str) -> bool:
    return name in _SENSITIVE_FIELD_NAMES or any(
        name.endswith(suffix) for suffix in _SENSITIVE_FIELD_SUFFIXES
    )


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelFlow"
    API_V1_PREFIX: str = "/api/v1"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    DEBUG: bool = True

    # Phase 1 Step 4: deduplication aggregation window (seconds)
    DEDUP_WINDOW_SECONDS: int = 300

    # Phase 2 Step 9: AI provider selection. Defaults to "mock" so the
    # platform always runs (tests/demo/air-gapped); switch to ollama or
    # cloud via .env without touching business code.
    AI_PROVIDER: str = "mock"
    AI_MODEL: str = ""
    AI_BASE_URL: str = "http://localhost:11434"
    AI_API_KEY: str | None = None
    # Local models can take tens of seconds per analysis (qwen3:4b ~40s);
    # raise for larger models, keep tests/fast providers at the default.
    AI_TIMEOUT_SECONDS: float = 60.0

    # Phase 3.1.5: response-execution adapter selection. Defaults to
    # "mock" (offline DryRun); shuffle / wazuh / thehive are reserved
    # registry values and raise ConfigError until Phase 3.2 implements
    # them — the platform never fakes support.
    EXECUTION_ADAPTER: str = "mock"

    # Phase 3.1.7 / 3.3.1: execution WRITE-path shared secret.
    # Legacy backwards-compatible fallback when OPERATORS_JSON is empty;
    # mapped to a synthetic "legacy-execution" operator with the executor
    # role. Empty stays fail-closed: every write request gets 401 until
    # either OPERATORS_JSON or EXECUTION_TOKEN is configured. The token
    # never enters logs, responses, exception strings, audit detail or
    # the database (frozen security discipline).
    EXECUTION_TOKEN: str = ""

    # Phase 3.3.1: static operator registry. JSON array of
    # {"token": "...", "name": "...", "role": "..."} objects.
    # Each token maps to exactly one Operator (name + role); roles are
    # viewer / reviewer / executor / admin. When empty, the legacy
    # EXECUTION_TOKEN above provides backwards-compatible fallback.
    # When both are empty, every write path stays fully closed (401).
    # Operator tokens never enter logs / responses / audit / DB.
    OPERATORS_JSON: str = ""

    # Phase 3.3.2: execution policy (B-3 — sits AFTER the Guard, BEFORE
    # the Executor). Disabled by default so upgrades keep the exact
    # 3.1/3.2 behavior; enabling NEVER bypasses Auth / RBAC / Approval /
    # Guard — a disabled policy is an ALLOW, not a security bypass.
    # A policy refusal lands as guard_rejected with detail.source=
    # "policy" (no new execution state). Time basis is UTC: the window
    # bounds are judged against the SERVER clock converted to UTC —
    # never the deployment host's local timezone.
    EXECUTION_POLICY_ENABLED: bool = False
    # Window bounds, strict HH:MM, [start, end) UTC (start inclusive,
    # end exclusive). Default = business hours.
    EXECUTION_POLICY_WINDOW_START: str = "09:00"
    EXECUTION_POLICY_WINDOW_END: str = "18:00"
    # Minimum SERVER-SIDE risk score (EventRisk.score — the live
    # authoritative assessment, never recomputed here) each executable
    # action requires; a missing risk fact refuses fail-closed.
    EXECUTION_POLICY_MIN_RISK_BLOCK_SOURCE_IP: int = 70
    EXECUTION_POLICY_MIN_RISK_ISOLATE_HOST: int = 70
    EXECUTION_POLICY_MIN_RISK_DISABLE_ACCOUNT: int = 80
    EXECUTION_POLICY_MIN_RISK_ESCALATE_TO_INCIDENT: int = 50

    # Phase 3.2.1 (E3 frozen): external-adapter credentials, one flat
    # *_BASE_URL / *_API_KEY pair per adapter. Empty defaults stay
    # fail-closed — the registry's startup validation refuses to run a
    # real adapter on half a configuration. mock requires NONE of these
    # (local development is never hostage to external credentials).
    # API keys never enter repr / logs / exceptions / audit / responses.
    SHUFFLE_BASE_URL: str = ""
    SHUFFLE_API_KEY: str = ""
    WAZUH_BASE_URL: str = ""
    # 3.2.4: Wazuh authenticates with a user/password pair (Basic) —
    # still one Authorization header, still .env -> Settings ->
    # AdapterCredentials -> header, never URL/body/query.
    WAZUH_API_USER: str = ""
    WAZUH_API_PASSWORD: str = ""
    THEHIVE_BASE_URL: str = ""
    THEHIVE_API_KEY: str = ""
    # Phase 3.4.5-M2-R §4: TheHive READ-adapter authorization gate. A reader is
    # NOT authorized by mere URL + write-key presence — it needs BOTH (a) an
    # INDEPENDENT read-only key (never the create-capable THEHIVE_API_KEY) and
    # (b) an EXACT certified-version match (THEHIVE_EXPECTED_VERSION must equal
    # the reader's CERTIFIED_THEHIVE_VERSION). Either empty / mismatched -> the
    # factory fails CLOSED (no reader), so a one-line wiring can never apply
    # 4.1.24-1 read semantics to a different version or silently reuse the write
    # credential. THEHIVE_READ_API_KEY ends in API_KEY -> auto-masked in repr;
    # never enters logs / responses / exceptions / audit / DB.
    THEHIVE_READ_API_KEY: str = ""
    THEHIVE_EXPECTED_VERSION: str = ""

    # Phase 3.2.3: Shuffle action -> workflow mapping (frozen §4 column).
    # Each executable action triggers EXACTLY ONE pre-configured workflow;
    # empty ids stay fail-closed (ConfigError at construction). Reverse
    # workflows are OPTIONAL — configured = compensation supported.
    SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP: str = ""
    SHUFFLE_WORKFLOW_ISOLATE_HOST: str = ""
    SHUFFLE_WORKFLOW_DISABLE_ACCOUNT: str = ""
    SHUFFLE_WORKFLOW_ESCALATE_TO_INCIDENT: str = ""
    SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP: str = ""
    SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST: str = ""
    # Adapter-level HTTP timeout; must never exceed the global sync
    # dispatch budget (frozen §6; default stays 30s).
    SHUFFLE_TIMEOUT_SECONDS: float = 30.0

    # Phase 3.2.4: Wazuh adapter-level HTTP timeout (same budget rule).
    # The endpoint-action vocabulary is frozen inside the adapter; no
    # further configuration surface is needed.
    WAZUH_TIMEOUT_SECONDS: float = 30.0

    # Phase 3.2.5: TheHive adapter-level HTTP timeout (same budget
    # rule). The case-creation vocabulary is frozen inside the adapter;
    # no further configuration surface is needed.
    THEHIVE_TIMEOUT_SECONDS: float = 30.0

    # Phase 3.4.4-A: external-adapter CALLBACK (inbound webhook) tokens —
    # one per RECOGNIZED adapter. This is a THIRD trust domain, completely
    # separate from BOTH the outbound *_API_KEY credentials above AND the
    # human-operator registry (design §8 / D3.4-07: External Adapter
    # Callback Identity is never Human Operator Identity). Bound per-route:
    # POST /api/v1/webhooks/{adapter} authenticates ONLY against
    # <ADAPTER>_CALLBACK_TOKEN — never a body field, never another
    # adapter's token. Empty stays fail-closed for THAT adapter's INBOUND
    # channel only (one uniform 401); an unconfigured callback token NEVER
    # blocks app startup and is deliberately NOT wired into
    # validate_adapter_config() (which guards the OUTBOUND dispatch path).
    # Values end in TOKEN, so _SENSITIVE_FIELD_SUFFIXES auto-masks them in
    # repr; they never enter logs / responses / exceptions / audit / DB.
    # mock has NO callback token by design (offline DryRun, no external
    # callback identity) — it is never a webhook channel (spec §5 / §17).
    SHUFFLE_CALLBACK_TOKEN: str = ""
    WAZUH_CALLBACK_TOKEN: str = ""
    THEHIVE_CALLBACK_TOKEN: str = ""

    DATABASE_URL: str = (
        "postgresql+psycopg://sentinelflow:change_me@localhost:5432/sentinelflow"
    )

    model_config = {
        "env_file": str(_PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def __repr__(self) -> str:
        # 3.2.1 secret discipline: the default pydantic repr prints every
        # value — API keys and the DB URL included. Sensitive values are
        # masked; key NAMES stay visible so config debugging still works.
        parts = [
            f"{name}={'***' if _is_sensitive_field(name) else getattr(self, name)!r}"
            for name in type(self).model_fields
        ]
        return f"Settings({', '.join(parts)})"

    def __str__(self) -> str:
        return self.__repr__()


settings = Settings()
