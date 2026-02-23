"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
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
    # Deterministic generation (optional; defaults give reproducible outputs)
    OLLAMA_TEMPERATURE: float = 0.0
    OLLAMA_TOP_P: float = 1.0
    OLLAMA_REPEAT_PENALTY: float = 1.0
    OLLAMA_SEED: int = 42

    # Jira Cloud (optional; required only for POST /api/v1/jira/export)
    JIRA_BASE_URL: str | None = None
    JIRA_EMAIL: str | None = None
    JIRA_API_TOKEN: SecretStr | None = None
    JIRA_PROJECT_KEY: str | None = None
    JIRA_EPIC_LINK_FIELD_ID: str | None = None
    JIRA_ISSUE_TYPE: str = "Task"
    JIRA_EPIC_ISSUE_TYPE: str = "Epic"
    JIRA_REQUEST_TIMEOUT_SEC: float = 30.0

    # Data retention: delete findings older than RETENTION_HOURS (run via cron or CLI)
    RETENTION_ENABLED: bool = True
    RETENTION_HOURS: int = 48

    # Enrichment (KEV, EPSS, OSV): timeouts and feature flags
    ENRICHMENT_KEV_ENABLED: bool = True
    ENRICHMENT_EPSS_ENABLED: bool = True
    ENRICHMENT_OSV_ENABLED: bool = True
    ENRICHMENT_REQUEST_TIMEOUT_SEC: float = 15.0
    ENRICHMENT_KEV_CACHE_TTL_SEC: int = 3600  # 1 hour

    # JWT authentication
    JWT_SECRET: SecretStr = SecretStr("change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    # When False, get_current_user returns a synthetic user (no JWT required). Set to True in production.
    AUTH_ENABLED: bool = False

    # Layer B clustering: optional semantic merge via embeddings + Qdrant
    CLUSTER_USE_SEMANTIC: bool = False
    QDRANT_URL: str | None = None
    QDRANT_COLLECTION_PREFIX: str = "helion_findings"
    CLUSTER_SIMILARITY_THRESHOLD: float = 0.85
    CLUSTER_TOP_K: int = 10

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

    @field_validator("OLLAMA_TEMPERATURE")
    @classmethod
    def validate_ollama_temperature(cls, v: float) -> float:
        if v < 0 or v > 2:
            raise ValueError("OLLAMA_TEMPERATURE must be between 0 and 2")
        return v

    @field_validator("OLLAMA_TOP_P")
    @classmethod
    def validate_ollama_top_p(cls, v: float) -> float:
        if v < 0 or v > 1:
            raise ValueError("OLLAMA_TOP_P must be between 0 and 1")
        return v

    @field_validator("OLLAMA_REPEAT_PENALTY")
    @classmethod
    def validate_ollama_repeat_penalty(cls, v: float) -> float:
        if v < 0.5 or v > 2:
            raise ValueError("OLLAMA_REPEAT_PENALTY must be between 0.5 and 2")
        return v

    @field_validator("OLLAMA_SEED")
    @classmethod
    def validate_ollama_seed(cls, v: int) -> int:
        if v < 0 or v > 2147483647:
            raise ValueError(
                "OLLAMA_SEED must be between 0 and 2147483647 (2^31-1)"
            )
        return v

    @field_validator("JIRA_BASE_URL")
    @classmethod
    def validate_jira_base_url(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        s = v.strip().rstrip("/").lower()
        if not (s.startswith("http://") or s.startswith("https://")):
            raise ValueError(
                "JIRA_BASE_URL must use http or https (e.g. https://your-domain.atlassian.net)"
            )
        return v.strip().rstrip("/")

    @field_validator("JIRA_REQUEST_TIMEOUT_SEC")
    @classmethod
    def validate_jira_timeout(cls, v: float) -> float:
        if v <= 0 or v > 120:
            raise ValueError(
                "JIRA_REQUEST_TIMEOUT_SEC must be greater than 0 and at most 120"
            )
        return v

    @field_validator("RETENTION_HOURS")
    @classmethod
    def validate_retention_hours(cls, v: int) -> int:
        if v < 1 or v > 8760:
            raise ValueError(
                "RETENTION_HOURS must be between 1 and 8760 (1 hour to 1 year)"
            )
        return v

    @field_validator("ENRICHMENT_REQUEST_TIMEOUT_SEC")
    @classmethod
    def validate_enrichment_timeout(cls, v: float) -> float:
        if v <= 0 or v > 60:
            raise ValueError(
                "ENRICHMENT_REQUEST_TIMEOUT_SEC must be greater than 0 and at most 60"
            )
        return v

    @field_validator("ENRICHMENT_KEV_CACHE_TTL_SEC")
    @classmethod
    def validate_kev_cache_ttl(cls, v: int) -> int:
        if v < 0 or v > 86400:
            raise ValueError(
                "ENRICHMENT_KEV_CACHE_TTL_SEC must be between 0 and 86400 (0 to 24 hours)"
            )
        return v

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, v: SecretStr) -> SecretStr:
        if not v.get_secret_value() or not v.get_secret_value().strip():
            raise ValueError("JWT_SECRET must be set and non-empty")
        return v

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("JWT_ALGORITHM must be set and non-empty")
        return v.strip()

    @field_validator("JWT_EXPIRE_MINUTES")
    @classmethod
    def validate_jwt_expire_minutes(cls, v: int) -> int:
        if v < 1 or v > 10080:
            raise ValueError(
                "JWT_EXPIRE_MINUTES must be between 1 and 10080 (1 min to 7 days)"
            )
        return v

    @field_validator("CLUSTER_SIMILARITY_THRESHOLD")
    @classmethod
    def validate_similarity_threshold(cls, v: float) -> float:
        if v < 0 or v > 1:
            raise ValueError("CLUSTER_SIMILARITY_THRESHOLD must be between 0 and 1")
        return v

    @field_validator("CLUSTER_TOP_K")
    @classmethod
    def validate_cluster_top_k(cls, v: int) -> int:
        if v < 1 or v > 100:
            raise ValueError("CLUSTER_TOP_K must be between 1 and 100")
        return v


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (safe to call from dependencies)."""
    return Settings()


settings = get_settings()
