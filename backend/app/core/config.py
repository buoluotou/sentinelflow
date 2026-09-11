from pathlib import Path

from pydantic_settings import BaseSettings

# backend/app/core/config.py -> parents[3] is the monorepo root (.env lives there)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Field names whose values must never surface in repr/str. Key names stay
# reportable (startup config errors name the missing keys); values do not.
_SENSITIVE_FIELD_NAMES = frozenset({"DATABASE_URL", "OPERATORS_JSON"})
_SENSITIVE_FIELD_SUFFIXES = ("API_KEY", "TOKEN", "PASSWORD")


def _is_sensitive_field(name: str) -> bool:
    return name in _SENSITIVE_FIELD_NAMES or any(
        name.endswith(suffix) for suffix in _SENSITIVE_FIELD_SUFFIXES
    )


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelFlow"
    API_V1_PREFIX: str = "/api/v1"
    # Address a native / host-run backend binds to. Loopback by default so a
    # host-run backend is local-only (native uvicorn already defaults to
    # 127.0.0.1). The Docker container binds 0.0.0.0 internally via the compose
    # command, independently of this value; its host-side exposure is governed
    # by BIND_HOST in docker-compose.yml. Set 0.0.0.0 only to expose a host-run
    # backend on purpose (put it behind SSO / a reverse proxy first).
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000
    # Compose-level host-port bind address (published ports use
    # ${BIND_HOST:-127.0.0.1} in docker-compose.yml). The API reads it too so
    # the production startup gate can refuse a non-loopback value: TLS and
    # authentication terminate at a reverse proxy, not at the API port.
    BIND_HOST: str = "127.0.0.1"
    # Verbose logging + debug diagnostics. Defaults to False (safe for
    # production / quickstart); wired to the backend log level (DEBUG when
    # true, INFO otherwise). Exception stack traces stay debug-only.
    DEBUG: bool = False

    # Explicit deployment mode ("demo" | "production"). The default keeps the
    # simple local UX: loopback binding is the exposure control, approval is
    # tokenless-but-display-only, the offline mock adapter is allowed.
    # "production" fails closed at startup — see
    # app.core.runtime_mode.validate_production_mode: OPERATORS_JSON auth is
    # required, PostgreSQL only, a real execution adapter is required,
    # compensation / reverse workflows are refused (not certified) and
    # BIND_HOST is pinned to loopback (terminate TLS and auth at a reverse
    # proxy).
    DEPLOYMENT_MODE: str = "demo"

    # Deduplication aggregation window, in seconds.
    DEDUP_WINDOW_SECONDS: int = 300

    # AI provider selection. Defaults to "mock" so the app runs with no
    # external service (tests, demo, air-gapped hosts); switch to ollama or a
    # cloud provider through .env without touching business code.
    AI_PROVIDER: str = "mock"
    AI_MODEL: str = ""
    AI_BASE_URL: str = "http://localhost:11434"
    AI_API_KEY: str | None = None
    # Local models can take tens of seconds per analysis (qwen3:4b ~40s);
    # raise for larger models, keep tests/fast providers at the default.
    AI_TIMEOUT_SECONDS: float = 60.0

    # Response-execution adapter selection. Defaults to "mock" (offline dry
    # run, no credentials needed). A real adapter needs its own credential
    # pair below; an unknown or multi-valued name, and a real adapter with an
    # incomplete configuration, both raise ConfigError at startup instead of
    # falling back to mock.
    EXECUTION_ADAPTER: str = "mock"

    # Execution write-path shared secret. Backwards-compatible fallback used
    # when OPERATORS_JSON is empty; mapped to a synthetic "legacy-execution"
    # operator with the executor role. An empty value stays fail-closed: every
    # write request gets 401 until either OPERATORS_JSON or EXECUTION_TOKEN is
    # configured. The token lives only in configuration and the outgoing
    # Authorization header, and never enters logs, responses, exception
    # strings, audit detail or the database — a persisted copy would be a
    # durable credential that outlives the configuration it was read from.
    EXECUTION_TOKEN: str = ""

    # Static operator registry: a JSON array of
    # {"token": "...", "name": "...", "role": "..."} objects. Each token maps
    # to one Operator (name + role); roles are viewer / reviewer / executor /
    # admin. When empty, the legacy EXECUTION_TOKEN above provides the
    # backwards-compatible fallback. When both are empty, every write path
    # stays fully closed (401). Operator tokens never enter logs, responses,
    # audit or the DB.
    OPERATORS_JSON: str = ""

    # Execution policy, evaluated after the Guard and before the Executor.
    # Disabled by default, so leaving it off preserves the previous behaviour;
    # enabling it never bypasses auth, RBAC, approval or the Guard — a disabled
    # policy is an allow, not a security bypass. A policy refusal is recorded
    # as guard_rejected with detail.source="policy" (no new execution state).
    # Time basis is UTC: the window bounds are judged against the server clock
    # converted to UTC — never the deployment host's local timezone.
    EXECUTION_POLICY_ENABLED: bool = False
    # Window bounds, strict HH:MM, [start, end) UTC (start inclusive,
    # end exclusive). Default = business hours.
    EXECUTION_POLICY_WINDOW_START: str = "09:00"
    EXECUTION_POLICY_WINDOW_END: str = "18:00"
    # Minimum server-side risk score (EventRisk.score — the live
    # authoritative assessment, never recomputed here) each executable
    # action requires; a missing risk fact refuses fail-closed.
    EXECUTION_POLICY_MIN_RISK_BLOCK_SOURCE_IP: int = 70
    EXECUTION_POLICY_MIN_RISK_ISOLATE_HOST: int = 70
    EXECUTION_POLICY_MIN_RISK_DISABLE_ACCOUNT: int = 80
    EXECUTION_POLICY_MIN_RISK_ESCALATE_TO_INCIDENT: int = 50

    # External-adapter credentials, one flat *_BASE_URL / *_API_KEY pair per
    # adapter. Empty defaults stay fail-closed: startup validation refuses to
    # run a real adapter on half a configuration. The mock adapter requires
    # none of them, so local development needs no external credentials. API
    # keys never enter repr, logs, exceptions, audit or responses.
    SHUFFLE_BASE_URL: str = ""
    SHUFFLE_API_KEY: str = ""
    WAZUH_BASE_URL: str = ""
    # Wazuh authenticates with a user/password pair (Basic auth): still one
    # Authorization header, still .env -> Settings -> AdapterCredentials ->
    # header, never URL, body or query.
    WAZUH_API_USER: str = ""
    WAZUH_API_PASSWORD: str = ""
    THEHIVE_BASE_URL: str = ""
    THEHIVE_API_KEY: str = ""
    # TheHive read-adapter authorization gate. URL and write-key presence do
    # not authorize a reader: it needs both an independent read-only key (never
    # the create-capable THEHIVE_API_KEY) and an exact certified-version match
    # (THEHIVE_EXPECTED_VERSION must equal the reader's
    # CERTIFIED_THEHIVE_VERSION). If either is empty or mismatched, the factory
    # builds no reader, so a wiring change cannot apply the certified version's
    # read semantics to a different version or silently reuse the write
    # credential. THEHIVE_READ_API_KEY ends in API_KEY and is auto-masked in
    # repr; it never enters logs, responses, exceptions, audit or the DB.
    THEHIVE_READ_API_KEY: str = ""
    THEHIVE_EXPECTED_VERSION: str = ""

    # Shuffle action -> workflow mapping. Each executable action triggers one
    # pre-configured workflow; an empty id stays fail-closed (ConfigError when
    # the executor is built). Reverse workflows are optional: configuring one
    # enables compensation, but compensation on a real adapter is experimental
    # and not production-certified — it still needs end-to-end lab validation
    # before it leaves that status. Setting a SHUFFLE_WORKFLOW_REVERSE_* id
    # therefore also requires EXECUTION_COMPENSATION_EXPERIMENTAL=true (below),
    # otherwise validate_adapter_config() refuses to start. The offline mock
    # adapter is exempt because compensation there is a dry run.
    SHUFFLE_WORKFLOW_BLOCK_SOURCE_IP: str = ""
    SHUFFLE_WORKFLOW_ISOLATE_HOST: str = ""
    SHUFFLE_WORKFLOW_DISABLE_ACCOUNT: str = ""
    SHUFFLE_WORKFLOW_ESCALATE_TO_INCIDENT: str = ""
    SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP: str = ""
    SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST: str = ""
    # Explicit acknowledgment, off by default, that compensation on a real
    # adapter is experimental and lab-only. While a reverse workflow is
    # configured, leaving it false refuses the boot. Not required for the mock
    # adapter.
    EXECUTION_COMPENSATION_EXPERIMENTAL: bool = False
    # Adapter-level HTTP timeout. It must stay within the global synchronous
    # dispatch budget, so the default is 30s.
    SHUFFLE_TIMEOUT_SECONDS: float = 30.0

    # Wazuh adapter-level HTTP timeout; same budget rule. The endpoint-action
    # vocabulary is fixed inside the adapter, so the adapter needs no further
    # configuration.
    WAZUH_TIMEOUT_SECONDS: float = 30.0

    # TheHive adapter-level HTTP timeout; same budget rule. The case-creation
    # vocabulary is fixed inside the adapter, so the adapter needs no further
    # configuration.
    THEHIVE_TIMEOUT_SECONDS: float = 30.0

    # External-adapter callback (inbound webhook) tokens, one per recognized
    # adapter. This is a third trust domain, separate from both the outbound
    # *_API_KEY credentials above and the human-operator registry: an external
    # adapter callback identity is never a human operator identity. Bound
    # per-route: POST /api/v1/webhooks/{adapter} authenticates only against
    # <ADAPTER>_CALLBACK_TOKEN, never a body field, never another adapter's
    # token. An empty value stays fail-closed for that adapter's inbound
    # channel only (one uniform 401); an unconfigured callback token never
    # blocks app startup and is intentionally not wired into
    # validate_adapter_config(), which guards the outbound dispatch path.
    # Values end in TOKEN, so _SENSITIVE_FIELD_SUFFIXES auto-masks them in
    # repr; they never enter logs, responses, exceptions, audit or DB.
    # The mock adapter has no callback token: it is an offline dry run with no
    # external callback identity, so it is not a webhook channel.
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
        # The default pydantic repr prints every value — API keys and the DB
        # URL included. Sensitive values are masked here; key names stay
        # visible so config debugging still works.
        parts = [
            f"{name}={'***' if _is_sensitive_field(name) else getattr(self, name)!r}"
            for name in type(self).model_fields
        ]
        return f"Settings({', '.join(parts)})"

    def __str__(self) -> str:
        return self.__repr__()


settings = Settings()
