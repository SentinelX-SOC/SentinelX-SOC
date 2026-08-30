"""Application settings for API and database configuration."""

from functools import lru_cache

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Load API and database settings from the environment or a `.env` file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- API ---
    app_name: str = "Hackathon API"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False
    secret_key: str = Field(default="change-me-in-production", min_length=8)
    allowed_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    host: str = "0.0.0.0"
    port: int = 8000

    # --- External ML inference service (backend is the client) ---
    ml_service_url: str = "http://127.0.0.1:9000"
    ml_request_timeout_seconds: float = Field(default=2.0, gt=0)
    events_batch_chunk_size: int = Field(default=100, ge=1)
    events_batch_use_multi_agent: bool = True

    # --- Temporary in-memory authentication (replace with a repository later) ---
    auth_dev_username: str = "analyst@example.com"
    auth_dev_password: str = Field(default="change-this-development-password", min_length=8)
    auth_session_ttl_seconds: int = Field(default=3600, ge=60)
    auth_cookie_secure: bool = False

    # --- Investigation agent (LLM-backed, advisory only; no remediation actions) ---
    investigation_llm_enabled: bool = False
    investigation_llm_provider: str = "lmstudio"
    investigation_llm_model: str = "local-model"
    investigation_llm_api_key: str | None = None
    investigation_llm_base_url: str = "http://localhost:1234/v1"
    investigation_llm_timeout_seconds: float = Field(default=8.0, gt=0)

    # --- Database ---
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "hackathon"
    database_url: str | None = "sqlite:///./soc.db"
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sqlalchemy_database_uri(self) -> str:
        """Return an explicit DATABASE_URL, or build one from Postgres parts.

        SQLite is the safe default for local development and tests. If a caller
        explicitly provides a Postgres connection string or overrides the host
        values, the project will use that Postgres URI instead.
        """
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()


settings = get_settings()
