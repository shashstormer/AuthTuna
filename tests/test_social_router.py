import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import status
from authtuna.core.database import User, SocialAccount

@pytest.mark.asyncio
async def test_social_login_redirect(fastapi_client):
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_provider = AsyncMock()
        mock_provider.authorize_redirect.return_value = {"status": "redirect"} # Mock response
        mock_get_provider.return_value = mock_provider

        response = await fastapi_client.get("/auth/google/login")
        assert response.status_code == 200 # Mock returns dict, FastAPI returns JSON
        mock_provider.authorize_redirect.assert_called_once()

@pytest.mark.asyncio
async def test_social_login_provider_not_found(fastapi_client):
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_get_provider.return_value = None
        response = await fastapi_client.get("/auth/unknown/login")
        assert response.status_code == 404

@pytest.mark.asyncio
async def test_social_callback_google_success_new_user(fastapi_client, auth_tuna_async):
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_provider = AsyncMock()
        mock_get_provider.return_value = mock_provider
        
        # Mock token
        mock_provider.authorize_access_token.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_at": 1234567890,
            "token_type": "bearer"
        }
        
        # Mock user info
        mock_provider.userinfo.return_value = {
            "sub": "12345",
            "name": "Social User",
            "email": "social@example.com"
        }

        response = await fastapi_client.get("/auth/google/callback")
        
        # Should redirect to dashboard (or return_url)
        # But RedirectResponse in FastAPI test client follows redirects?
        # Or returns 307/303?
        # If it follows, we check final URL.
        # But here we just check status code.
        assert response.status_code == 307 or response.status_code == 200 # 307 Temporary Redirect
        
        # Verify user created
        user = await auth_tuna_async.users.get_by_email("social@example.com")
        assert user is not None
        assert user.username == "Social User" or user.username.startswith("Social")

@pytest.mark.asyncio
async def test_social_callback_github_success_existing_user(fastapi_client, auth_tuna_async, authenticated_user):
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_provider = AsyncMock()
        mock_get_provider.return_value = mock_provider
        
        # Mock token
        mock_provider.authorize_access_token.return_value = {
            "access_token": "gh_access_token",
            "token_type": "bearer"
        }
        
        # Mock GitHub API responses
        mock_resp_user = MagicMock()
        mock_resp_user.json.return_value = {"id": 67890, "name": "GitHub User", "email": None}
        mock_resp_user.raise_for_status = MagicMock()
        
        mock_resp_emails = MagicMock()
        mock_resp_emails.json.return_value = [{"email": authenticated_user.email, "primary": True}]
        mock_resp_emails.raise_for_status = MagicMock()
        
        # Configure get side_effect
        async def side_effect(url, token=None):
            if url == 'user':
                return mock_resp_user
            if url == 'user/emails':
                return mock_resp_emails
            return MagicMock()
            
        mock_provider.get.side_effect = side_effect

        response = await fastapi_client.get("/auth/github/callback")
        
        assert response.status_code == 307 or response.status_code == 200
        
        # Verify social account linked
        from sqlalchemy import select
        from authtuna.core.database import SocialAccount
        async with auth_tuna_async.db_manager.get_db() as db:
            stmt = select(SocialAccount).where(SocialAccount.user_id == authenticated_user.id)
            result = await db.execute(stmt)
            account = result.scalar_one_or_none()
            assert account is not None
            assert account.provider == "github"
            assert account.provider_user_id == "67890"

@pytest.mark.asyncio
async def test_social_callback_mfa_enabled(fastapi_client, auth_tuna_async):
    # Create user with MFA
    user = await auth_tuna_async.users.create("mfauser@example.com", "mfauser", "password", "127.0.0.1")
    
    # Enable MFA directly in DB
    async with auth_tuna_async.db_manager.get_db() as db:
        user_db = await auth_tuna_async.users.get_by_id(user.id, db=db)
        user_db.mfa_enabled = True
        await db.commit()
        
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_provider = AsyncMock()
        mock_get_provider.return_value = mock_provider
        
        mock_provider.authorize_access_token.return_value = {"access_token": "token"}
        mock_provider.userinfo.return_value = {"sub": "111", "email": "mfauser@example.com"}

        response = await fastapi_client.get("/auth/google/callback")
        
        # Should redirect to MFA challenge
        assert response.status_code == 307
        assert "/mfa/challenge" in response.headers["location"]

@pytest.mark.asyncio
async def test_social_callback_oauth_error(fastapi_client):
    from authlib.integrations.starlette_client import OAuthError
    with patch("authtuna.routers.social.get_social_provider") as mock_get_provider:
        mock_provider = AsyncMock()
        mock_get_provider.return_value = mock_provider
        
        mock_provider.authorize_access_token.side_effect = OAuthError("error", "description")
        
        response = await fastapi_client.get("/auth/google/callback")
        assert response.status_code == 400
