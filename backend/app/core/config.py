from pathlib import Path

from pydantic_settings import BaseSettings

# backend/app/core/config.py -> parents[3] is the monorepo root (.env lives there)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

#: Field names whose VALUES must never surface in repr/str (3.2.1 secret
#: discipline, mirrors the EXECUTION_TOKEN lineage). Names of the keys
#: ARE reportable (config errors name missing keys); values are not.
_SENSITIVE_FIELD_NAMES = frozenset({"DATABASE_URL"})
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

    # Phase 3.1.7: shared secret for the execution WRITE endpoints
    # (POST /executions, POST /executions/compensate). Empty stays
    # fail-closed: every write request gets 401 until a token is
    # configured. The token never enters logs, responses, exception
    # strings, audit detail or the database (frozen security discipline).
    EXECUTION_TOKEN: str = ""

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
