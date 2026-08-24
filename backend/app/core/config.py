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

    DATABASE_URL: str = (
        "postgresql+psycopg://sentinelflow:change_me@localhost:5432/sentinelflow"
    )

    model_config = {
        "env_file": str(_PROJECT_ROOT / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
