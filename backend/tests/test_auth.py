from fastapi import status
from pydantic import SecretStr

from app.auth.jwt import create_access_token
from app.core.config import Settings


def test_create_and_verify_token():
    settings = Settings(
        jwt_secret_key=SecretStr("testsecret-value-with-at-least-32-chars"),
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
    )
    token = create_access_token(data={"sub": "testuser"}, settings=settings)
    assert isinstance(token, str)


def test_register_user(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "newuser",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "+15555550100",
            "password": "password123",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["username"] == "newuser"
    assert response.json()["first_name"] == "New"
    assert "password" not in response.text


def test_login_returns_bearer_token(client):
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "loginuser",
            "first_name": "Login",
            "last_name": "User",
            "phone_number": "+15555550101",
            "password": "password123",
        },
    )
    assert register_response.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "loginuser", "password": "password123"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["token_type"] == "bearer"
    assert response.json()["access_token"]
