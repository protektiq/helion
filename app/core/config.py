"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Allowed URL schemes for DATABASE_URL (module-level so validators can use it).
VALID_DATABASE_URL_PREFIXES = (
    "postgresql://",
    "postgresql+psycopg2://",
    "postgres://",
    "postgres+psycopg2://",
)


class Settings(BaseSettings):
    """Validated application settings from env and optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    APP_ENV: Literal["dev", "prod"] = "dev"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Postgres: required in prod; for dev can use a default if you run Postgres locally
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/helion"

    # Ollama (local LLM): optional; app runs without it if reasoning is not used
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    OLLAMA_REQUEST_TIMEOUT_SEC: float = 120.0

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("DATABASE_URL must be set and non-empty")
        if not any(v.startswith(prefix) for prefix in VALID_DATABASE_URL_PREFIXES):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL (e.g. postgresql:// or postgresql+psycopg2://)"
            )
        return v.strip()

    @field_validator("OLLAMA_BASE_URL")
    @classmethod
    def validate_ollama_base_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("OLLAMA_BASE_URL must be set and non-empty")
        s = v.strip().lower()
        if not (s.startswith("http://") or s.startswith("https://")):
            raise ValueError(
                "OLLAMA_BASE_URL must use http or https (e.g. http://localhost:11434)"
            )
        return v.strip()

    @field_validator("OLLAMA_REQUEST_TIMEOUT_SEC")
    @classmethod
    def validate_ollama_timeout(cls, v: float) -> float:
        if v <= 0 or v > 300:
            raise ValueError(
                "OLLAMA_REQUEST_TIMEOUT_SEC must be greater than 0 and at most 300"
            )
        return v


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (safe to call from dependencies)."""
    return Settings()


settings = get_settings()
