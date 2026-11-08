"""Central configuration for Nyaya.

Rules this file follows:
1. All settings come from environment variables (or a local .env file). No hard-coded secrets.
2. Settings are typed and validated at startup, so a bad config fails fast and loudly.
3. Secrets use SecretStr so they never show up in logs or repr().
4. One cached instance via get_settings(); tests can override it.

Reference version. Verify pydantic-settings usage against its current docs.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="NYAYA_",
        extra="ignore",
    )

    # --- App ---
    env: Literal["local", "test", "prod"] = "local"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- PostgreSQL (plain Postgres, no Supabase auth or RLS) ---
    # Use a direct or session-mode connection, not transaction pooling,
    # because the LangGraph checkpointer can break with it.
    postgres_dsn: SecretStr = SecretStr(
        "postgresql+asyncpg://nyaya_app:change-me@localhost:5432/nyaya"
    )
    postgres_migrator_dsn: SecretStr = SecretStr(
        "postgresql+psycopg://nyaya_migrator:change-me@localhost:5432/nyaya"
    )
    postgres_pool_size: int = Field(default=10, ge=1, le=100)

    # --- MongoDB ---
    mongo_uri: SecretStr = SecretStr("mongodb://localhost:27017")
    mongo_db: str = "nyaya"

    # --- Redis ---
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # --- Search and vectors ---
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: SecretStr | None = None
    # Keyword search runs in Postgres full-text search, so no Elasticsearch setting.

    # --- Object store (MinIO locally, S3 later) ---
    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: SecretStr = SecretStr("minioadmin")
    s3_secret_key: SecretStr = SecretStr("minioadmin")
    s3_bucket: str = "nyaya-files"

    # --- Kafka API (Redpanda) ---
    kafka_bootstrap: str = "localhost:9092"

    # --- Auth ---
    jwt_secret: SecretStr = SecretStr("dev-only-change-me-dev-only-change-me")
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=120)
    refresh_token_ttl_days: int = Field(default=7, ge=1, le=90)
    # Argon2id: OWASP minimum is 19 MiB memory, 2 iterations, 1 lane. Re-check when implementing.
    argon2_memory_kib: int = Field(default=19456, ge=19456)
    argon2_time_cost: int = Field(default=2, ge=2)
    argon2_parallelism: int = Field(default=1, ge=1)

    # --- LLM gateway ---
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    llm_monthly_budget_usd: float = Field(default=10.0, ge=0)
    llm_per_case_budget_usd: float = Field(default=0.50, ge=0)

    # --- Tracing (toggle to protect the free LangSmith quota) ---
    langsmith_enabled: bool = False
    langsmith_api_key: SecretStr | None = None

    @model_validator(mode="after")
    def _check_prod_safety(self) -> "Settings":
        if self.env == "prod":
            secret = self.jwt_secret.get_secret_value()
            if secret.startswith("dev-only") or len(secret) < 32:
                raise ValueError("NYAYA_JWT_SECRET must be a strong, non-default value in prod")
        if self.langsmith_enabled and self.langsmith_api_key is None:
            raise ValueError("NYAYA_LANGSMITH_API_KEY is required when langsmith_enabled is true")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()