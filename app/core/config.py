"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("DATABASE_URL must be set and non-empty")
        if not v.startswith("postgresql://") and not v.startswith("postgres://"):
            raise ValueError("DATABASE_URL must be a postgresql:// URL")
        return v.strip()


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (safe to call from dependencies)."""
    return Settings()


settings = get_settings()
