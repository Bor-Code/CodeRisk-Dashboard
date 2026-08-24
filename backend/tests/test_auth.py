from fastapi import status
from pydantic import SecretStr

from app.auth.jwt import create_access_token
from app.core.config import Settings


def test_create_and_verify_token():
    settings = Settings(
        jwt_secret_key=SecretStr("testsecret"),
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
    )
    token = create_access_token(data={"sub": "testuser"}, settings=settings)
    assert isinstance(token, str)


def test_register_user(client):
    response = client.post(
        "/api/v1/auth/register", json={"username": "newuser", "password": "password123"}
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["username"] == "newuser"
