from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]


def _default_database_url() -> SecretStr:
    return SecretStr("sqlite+pysqlite:///./coderisk.db")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CODERISK_",
        extra="ignore",
    )

    environment: Environment = "development"
    database_url: SecretStr = Field(default_factory=_default_database_url)
    database_echo: bool = False
    database_auto_create: bool = False
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ]
    )
    scan_timeout_seconds: int = 1800
    scan_heartbeat_seconds: int = 60
    scan_result_limit_bytes: int = 10 * 1024 * 1024
    scan_memory_limit_mb: int = 512
    scan_terminate_grace_seconds: int = 10
    scan_poll_interval_seconds: int = 5
    scan_max_attempts: int = 3
    scan_lease_seconds: int = 120

    # Authentication — leave unset to disable (development/single-user mode)
    api_key: SecretStr | None = None
    jwt_secret_key: SecretStr = Field(default_factory=lambda: SecretStr("super-secret-default-key"))
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60 * 24 * 7  # 7 days

    # GitHub ingestion — base directory for temporary clones
    github_clone_workspace: str | None = None

    @model_validator(mode="after")
    def validate_runtime_configuration(self) -> Self:
        database_url = self.database_url.get_secret_value()
        supported_prefixes = (
            "sqlite://",
            "sqlite+pysqlite://",
            "postgresql+psycopg://",
        )

        if not database_url.startswith(supported_prefixes):
            raise ValueError("Database URL must use SQLite or PostgreSQL with psycopg.")

        if self.database_auto_create and self.environment != "test":
            raise ValueError("Automatic schema creation is restricted to the test environment.")

        if self.environment == "production":
            if not database_url.startswith("postgresql+psycopg://"):
                raise ValueError("Production requires PostgreSQL with the psycopg driver.")
            if "*" in self.cors_origins:
                raise ValueError("Production CORS origins cannot contain a wildcard.")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
