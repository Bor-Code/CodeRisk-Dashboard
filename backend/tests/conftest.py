from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    database_path = (tmp_path / "coderisk-test.db").as_posix()
    return Settings(
        environment="test",
        database_url=SecretStr(f"sqlite+pysqlite:///{database_path}"),
        database_auto_create=True,
    )


@pytest.fixture
def application(test_settings: Settings) -> FastAPI:
    return create_app(test_settings)


@pytest.fixture
def client(application: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(application) as test_client:
        yield test_client
