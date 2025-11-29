import pytest
from unittest.mock import patch, AsyncMock
from authtuna.core.config import settings
from authtuna.core.database import Token
from sqlalchemy import select

@pytest.mark.asyncio
async def test_passwordless_flow(fastapi_client, auth_tuna_async, authenticated_user):
    # Ensure EMAIL_ENABLED is True
    with patch.object(settings, 'EMAIL_ENABLED', True):
        # Mock email manager to avoid actual sending (and errors)
        with patch('authtuna.routers.passwordless.email_manager.send_passwordless_login_email', new=AsyncMock()) as mock_send:
            # 1. Request Magic Link
            response = await fastapi_client.post("/auth/passwordless/request", json={"email": authenticated_user.email})
            assert response.status_code == 202
            
            # Verify email mock was called
            assert mock_send.called

            # 2. Retrieve Token from DB
            async with auth_tuna_async.db_manager.get_db() as db:
                stmt = select(Token).where(
                    Token.user_id == authenticated_user.id,
                    Token.purpose == "passwordless_login"
                )
                token_obj = (await db.execute(stmt)).scalar_one_or_none()
                assert token_obj is not None
                token_id = token_obj.id

            # 3. Login with Token
            response = await fastapi_client.get(f"/auth/passwordless/login?token={token_id}")
            assert response.status_code == 200
            assert "Login successful" in response.json()["message"]
            assert settings.SESSION_TOKEN_NAME in response.cookies

@pytest.mark.asyncio
async def test_passwordless_disabled(fastapi_client):
    with patch.object(settings, 'EMAIL_ENABLED', False):
        response = await fastapi_client.post("/auth/passwordless/request", json={"email": "test@example.com"})
        assert response.status_code == 501

@pytest.mark.asyncio
async def test_passwordless_invalid_token(fastapi_client):
    response = await fastapi_client.get("/auth/passwordless/login?token=invalid_token")
    assert response.status_code == 400
