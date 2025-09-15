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
async def test_social_login_provider_not_found(fastapi_client: AsyncClient):
    resp = await fastapi_client.get("/auth/notarealprovider/login")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    resp = await fastapi_client.get("/auth/notarealprovider/callback")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
