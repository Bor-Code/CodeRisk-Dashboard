from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    database_path = (tmp_path / "coderisk-test.db").as_posix()
    return Settings(
        environment="test",
        database_url=f"sqlite+pysqlite:///{database_path}",
        database_auto_create=True,
        _env_file=None,
    )


@pytest.fixture
def application(test_settings: Settings) -> FastAPI:
    return create_app(test_settings)


@pytest.fixture
def client(application: FastAPI) -> TestClient:
    with TestClient(application) as test_client:
        yield test_client
