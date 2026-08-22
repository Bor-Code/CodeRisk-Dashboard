from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, text

from app.core.config import Settings
from app.main import create_app


def test_production_requires_postgresql() -> None:
    with pytest.raises(ValidationError, match="Production requires PostgreSQL"):
        Settings(
            environment="production",
            database_url="sqlite+pysqlite:///./production.db",
            _env_file=None,
        )


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="CORS origins cannot contain a wildcard"):
        Settings(
            environment="production",
            database_url="postgresql+psycopg://user:password@database/coderisk",
            cors_origins=["*"],
            _env_file=None,
        )


def test_automatic_schema_creation_is_test_only() -> None:
    with pytest.raises(ValidationError, match="restricted to the test environment"):
        Settings(
            environment="development",
            database_auto_create=True,
            _env_file=None,
        )


def test_application_fails_fast_when_migrations_are_missing(tmp_path: Path) -> None:
    database_path = (tmp_path / "uninitialized.db").as_posix()
    settings = Settings(
        environment="development",
        database_url=f"sqlite+pysqlite:///{database_path}",
        _env_file=None,
    )

    with pytest.raises(RuntimeError, match="Database schema is not initialized"):
        with TestClient(create_app(settings)):
            pass


def test_application_rejects_schema_without_migration_revision(tmp_path: Path) -> None:
    database_path = (tmp_path / "unversioned.db").as_posix()
    database_url = f"sqlite+pysqlite:///{database_path}"
    test_settings = Settings(
        environment="test",
        database_url=database_url,
        database_auto_create=True,
        _env_file=None,
    )

    with TestClient(create_app(test_settings)):
        pass

    development_settings = Settings(
        environment="development",
        database_url=database_url,
        _env_file=None,
    )

    with pytest.raises(RuntimeError, match="Database migration revision is missing"):
        with TestClient(create_app(development_settings)):
            pass


def test_application_rejects_stale_migration_revision(tmp_path: Path) -> None:
    database_path = (tmp_path / "stale.db").as_posix()
    database_url = f"sqlite+pysqlite:///{database_path}"
    test_settings = Settings(
        environment="test",
        database_url=database_url,
        database_auto_create=True,
        _env_file=None,
    )

    with TestClient(create_app(test_settings)):
        pass

    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('stale_revision')")
        )
    engine.dispose()

    development_settings = Settings(
        environment="development",
        database_url=database_url,
        _env_file=None,
    )

    with pytest.raises(RuntimeError, match="expected '20260822_0001'"):
        with TestClient(create_app(development_settings)):
            pass


def test_configuration_errors_redact_database_credentials() -> None:
    password = "private-database-password"

    with pytest.raises(ValidationError) as captured_error:
        Settings(
            environment="production",
            database_url=f"postgresql+psycopg://user:{password}@database/coderisk",
            cors_origins=["*"],
            _env_file=None,
        )

    assert password not in str(captured_error.value)
