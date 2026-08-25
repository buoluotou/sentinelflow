from pathlib import Path

from pydantic_settings import BaseSettings

# backend/app/core/config.py -> parents[3] is the monorepo root (.env lives there)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


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

    DATABASE_URL: str = (
        "postgresql+psycopg://sentinelflow:change_me@localhost:5432/sentinelflow"
    )

    model_config = {
        "env_file": str(_PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
