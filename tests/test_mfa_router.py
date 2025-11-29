import pytest
from unittest.mock import AsyncMock, Mock, patch
from fastapi import status
from httpx import AsyncClient
import pyotp

from authtuna.core.database import User
import authtuna.routers.mfa as mfa_router

@pytest.mark.asyncio
async def test_mfa_setup_flow(fastapi_client, auth_tuna_async, authenticated_user):
    # 1. Login/Session
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # 2. Initiate Setup
    response = await fastapi_client.post("/mfa/setup", cookies=cookies)
    assert response.status_code == 200
    data = response.json()
    assert "provisioning_uri" in data
    uri = data["provisioning_uri"]
    
    # Extract secret from URI
    # otpauth://totp/AuthTuna:...?secret=...&issuer=AuthTuna
    import urllib.parse
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    secret = query["secret"][0]

    # 3. Verify Setup
    totp = pyotp.TOTP(secret)
    code = totp.now()
    
    response = await fastapi_client.post("/mfa/verify", json={"code": code}, cookies=cookies)
    assert response.status_code == 200
    data = response.json()
    assert "recovery_codes" in data
    assert len(data["recovery_codes"]) > 0

    # 4. Verify MFA Enabled in DB
    user = await auth_tuna_async.users.get_by_id(authenticated_user.id)
    assert user.mfa_enabled is True

    # 5. Disable MFA
    response = await fastapi_client.post("/mfa/disable", cookies=cookies)
    assert response.status_code == 200
    
    # 6. Verify MFA Disabled
    user = await auth_tuna_async.users.get_by_id(authenticated_user.id)
    assert user.mfa_enabled is False

@pytest.mark.asyncio
async def test_mfa_pages(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # Setup Page
    response = await fastapi_client.get("/mfa/setup", cookies=cookies)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

    # Challenge Page (public)
    response = await fastapi_client.get("/mfa/challenge")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

@pytest.mark.asyncio
async def test_get_qr_code(fastapi_client):
    response = await fastapi_client.get("/mfa/qr-code?uri=otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"

@pytest.mark.asyncio
async def test_validate_mfa_login(fastapi_client, auth_tuna_async, authenticated_user):
    # Enable MFA for user
    secret = pyotp.random_base32()
    async with auth_tuna_async.db_manager.get_db() as db:
        from authtuna.core.database import MFAMethod
        db.add(MFAMethod(user_id=authenticated_user.id, method_type="totp", secret=secret, is_verified=True))
        user = await auth_tuna_async.users.get_by_id(authenticated_user.id, db=db)
        user.mfa_enabled = True
        await db.commit()

    # Create MFA token (simulating login flow)
    mfa_token = await auth_tuna_async.tokens.create(authenticated_user.id, "mfa_validation", expiry_seconds=300)

    # Generate code
    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Validate
    response = await fastapi_client.post("/mfa/validate-login", json={
        "mfa_token": mfa_token.id,
        "code": code
    })
    
    assert response.status_code == 200
    assert "Login successful" in response.json()["message"]
    assert "session_token" in response.cookies

@pytest.mark.asyncio
async def test_mfa_errors(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # Verify with invalid code
    response = await fastapi_client.post("/mfa/verify", json={"code": "000000"}, cookies=cookies)
    assert response.status_code == 400

    # Disable when not enabled
    response = await fastapi_client.post("/mfa/disable", cookies=cookies)
    assert response.status_code == 409
