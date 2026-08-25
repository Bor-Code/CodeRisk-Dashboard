from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.auth.jwt import require_jwt
from app.core.config import Settings
from app.db.models import UserModel
from app.main import create_app


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    database_path = (tmp_path / "coderisk-test.db").as_posix()
    return Settings(
        environment="test",
        database_url=SecretStr(f"sqlite+pysqlite:///{database_path}"),
        database_auto_create=True,
        jwt_secret_key=SecretStr("testsecret-value-with-at-least-32-chars"),
    )


@pytest.fixture
def application(test_settings: Settings) -> FastAPI:
    app = create_app(test_settings)
    app.dependency_overrides[require_jwt] = lambda: UserModel(
        id="test-id",
        username="test-user",
        first_name="Test",
        last_name="User",
        phone_number="+10000000000",
    )
    return app


@pytest.fixture
def client(application: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(application) as test_client:
        yield test_client
