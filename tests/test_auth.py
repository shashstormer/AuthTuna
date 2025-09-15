import pytest
from fastapi import status
from httpx import AsyncClient
from authtuna.core.exceptions import InvalidCredentialsError

@pytest.mark.asyncio
async def test_signup_and_login(auth_tuna_async):
    """Test user signup and subsequent login."""
    # Signup a new user
    user, _ = await auth_tuna_async.signup(
        username="test_auth_user",
        email="test_auth@example.com",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    assert user is not None
    assert user.email == "test_auth@example.com"

    # Login with correct credentials
    loggedInUser, session = await auth_tuna_async.login(
        username_or_email="test_auth_user",
        password="ValidPassword123",
        ip_address="127.0.0.1",
        region="Test Region",
        device="Test Device"
    )
    assert loggedInUser is not None
    assert session is not None
    assert loggedInUser.id == user.id

    # Attempt login with incorrect password
    with pytest.raises(InvalidCredentialsError):
        await auth_tuna_async.login(
            username_or_email="test_auth_user",
            password="WrongPassword",
            ip_address="127.0.0.1",
            region="Test Region",
            device="Test Device"
        )

@pytest.mark.asyncio
async def test_signup_and_login_endpoints(fastapi_client: AsyncClient):
    # Signup page (GET)
    resp = await fastapi_client.get("/auth/signup")
    assert resp.status_code == status.HTTP_200_OK
    # Signup (POST)
    resp = await fastapi_client.post(
        "/auth/signup",
        json={"username": "testuser1", "email": "testuser1@example.com", "password": "pw123456"},
    )
    assert resp.status_code in (status.HTTP_201_CREATED, status.HTTP_202_ACCEPTED)
    # Duplicate signup
    resp2 = await fastapi_client.post(
        "/auth/signup",
        json={"username": "testuser1", "email": "testuser1@example.com", "password": "pw123456"},
    )
    assert resp2.status_code == status.HTTP_409_CONFLICT
    # Login page (GET)
    resp = await fastapi_client.get("/auth/login")
    assert resp.status_code == status.HTTP_200_OK
    # Login (POST)
    resp = await fastapi_client.post(
        "/auth/login",
        json={"username_or_email": "testuser1", "password": "pw123456"},
    )
    assert resp.status_code == status.HTTP_200_OK
    # Login with wrong password
    resp = await fastapi_client.post(
        "/auth/login",
        json={"username_or_email": "testuser1", "password": "wrongpw"},
    )
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_logout_and_user_info(fastapi_client: AsyncClient):
    # Signup and login
    await fastapi_client.post(
        "/auth/signup",
        json={"username": "testuser2", "email": "testuser2@example.com", "password": "pw123456"},
    )
    resp = await fastapi_client.post(
        "/auth/login",
        json={"username_or_email": "testuser2", "password": "pw123456"},
    )
    token = resp.cookies.get("session_token")
    # User info (GET)
    resp = await fastapi_client.get("/auth/user-info", cookies={"session_token": token})
    assert resp.status_code == status.HTTP_200_OK
    # Logout (POST)
    resp = await fastapi_client.post("/auth/logout", cookies={"session_token": token})
    assert resp.status_code == status.HTTP_200_OK

@pytest.mark.asyncio
async def test_forgot_and_reset_password(fastapi_client: AsyncClient, monkeypatch):
    # Patch email sending to no-op
    monkeypatch.setattr("authtuna.helpers.mail.email_manager.send_password_reset_email", lambda *a, **k: None)
    monkeypatch.setattr("authtuna.helpers.mail.email_manager.send_password_change_email", lambda *a, **k: None)
    # Signup
    await fastapi_client.post(
        "/auth/signup",
        json={"username": "testuser3", "email": "testuser3@example.com", "password": "pw123456"},
    )
    # Forgot password (POST)
    resp = await fastapi_client.post(
        "/auth/forgot-password",
        json={"email": "testuser3@example.com"},
    )
    assert resp.status_code in (status.HTTP_202_ACCEPTED, status.HTTP_501_NOT_IMPLEMENTED)
    # Reset password (POST, invalid token)
    resp = await fastapi_client.post(
        "/auth/reset-password",
        json={"token": "badtoken", "new_password": "newpw123"},
    )
    assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_501_NOT_IMPLEMENTED)

@pytest.mark.asyncio
async def test_verify_email_and_reset_page(fastapi_client: AsyncClient):
    # These endpoints render HTML, just check for 200 or error
    resp = await fastapi_client.get("/auth/verify?token=badtoken")
    assert resp.status_code == status.HTTP_200_OK
    resp = await fastapi_client.get("/auth/reset-password?token=badtoken")
    assert resp.status_code == status.HTTP_200_OK
