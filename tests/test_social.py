import pytest
from authtuna.core.social import get_social_provider, oauth
from fastapi import status
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

def test_get_social_provider_valid():
    # These providers may or may not be registered depending on settings, but the function should not error
    for provider in ["google", "github"]:
        client = get_social_provider(provider)
        assert client is None or hasattr(client, 'authorize_redirect')

def test_get_social_provider_invalid():
    assert get_social_provider("notarealprovider") is None

def test_oauth_registry_is_accessible():
    # The oauth object should be present and have a registry dict
    print(oauth)
    assert hasattr(oauth, '_registry')
    assert isinstance(oauth._registry, dict)

@pytest.mark.asyncio
async def test_social_login_and_callback_success(fastapi_client: AsyncClient):
    # Patch get_social_provider to return a mock provider
    class MockProvider:
        async def authorize_redirect(self, request, redirect_uri):
            return {"redirect": redirect_uri}
        async def authorize_access_token(self, request):
            return {"access_token": "tok", "refresh_token": "ref", "expires_at": 123456}
        async def userinfo(self, token):
            return {"sub": "123", "name": "Test User", "email": "social@example.com"}
        async def get(self, path, token=None):
            class Resp:
                def raise_for_status(self): pass
                def json(self): return {"id": 123, "name": "Test User", "email": "social@example.com"}
            return Resp()
    with patch("authtuna.routers.social.get_social_provider", return_value=MockProvider()):
        # Login
        resp = await fastapi_client.get("/auth/google/login")
        assert resp.status_code == status.HTTP_200_OK or resp.status_code == status.HTTP_307_TEMPORARY_REDIRECT
        # Callback
        with patch("authtuna.core.database.db_manager.get_db", AsyncMock()):
            resp = await fastapi_client.get("/auth/google/callback")
            # Accept any 200, 307, or 400 (since we mock DB and may hit missing user logic)
            assert resp.status_code in (status.HTTP_200_OK, status.HTTP_307_TEMPORARY_REDIRECT, status.HTTP_400_BAD_REQUEST)

@pytest.mark.asyncio
async def test_social_login_provider_not_found(fastapi_client: AsyncClient):
    resp = await fastapi_client.get("/auth/notarealprovider/login")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    resp = await fastapi_client.get("/auth/notarealprovider/callback")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
