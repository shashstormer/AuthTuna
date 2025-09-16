import pytest
from unittest.mock import patch, AsyncMock, Mock, PropertyMock
from fastapi import status
from httpx import AsyncClient
from authlib.integrations.starlette_client import OAuthError


@pytest.mark.asyncio
async def test_social_login_redirect_google(fastapi_client: AsyncClient):
    async def fake_authorize_redirect(request, redirect_uri):
        class FakeResp:
            status_code = status.HTTP_302_FOUND
        return FakeResp()

    fake_provider = Mock()
    fake_provider.authorize_redirect = AsyncMock(side_effect=fake_authorize_redirect)

    with patch('authtuna.routers.social.get_social_provider', return_value=fake_provider):
        resp = await fastapi_client.get('/auth/google/login')
        assert resp.status_code in (status.HTTP_302_FOUND, status.HTTP_200_OK)


@pytest.mark.asyncio
async def test_social_callback_new_user_google_success(fastapi_client: AsyncClient):
    # Mock provider that returns token and userinfo without touching request.session
    fake_provider = Mock()
    fake_provider.authorize_access_token = AsyncMock(return_value={'access_token': 'tok', 'token_type': 'bearer'})
    fake_provider.userinfo = AsyncMock(return_value={'sub': 'google_user_1', 'email': 'newg@example.com', 'name': 'New G'})

    with patch('authtuna.routers.social.get_social_provider', return_value=fake_provider):
        # Also avoid sending emails in test
        with patch('authtuna.routers.social.email_manager') as mock_email_mgr:
            mock_email_mgr.send_new_social_account_connected_email = AsyncMock()
            mock_email_mgr.send_welcome_email = AsyncMock()
            resp = await fastapi_client.get('/auth/google/callback')
            assert resp.status_code in (status.HTTP_302_FOUND, status.HTTP_307_TEMPORARY_REDIRECT)


@pytest.mark.asyncio
async def test_social_callback_oauth_error(fastapi_client: AsyncClient):
    fake_provider = Mock()
    fake_provider.authorize_access_token = AsyncMock(side_effect=OAuthError(description='bad'))

    with patch('authtuna.routers.social.get_social_provider', return_value=fake_provider):
        resp = await fastapi_client.get('/auth/google/callback')
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_social_login_unknown_provider(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/auth/unknownprovider/login')
    assert resp.status_code == 404
    assert "not found" in resp.text.lower()


@pytest.mark.asyncio
async def test_social_callback_unknown_provider(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/auth/unknownprovider/callback')
    assert resp.status_code == 404
    assert "not found" in resp.text.lower()


@pytest.mark.asyncio
async def test_social_callback_unsupported_provider(fastapi_client: AsyncClient):
    fake_provider = Mock()
    fake_provider.authorize_access_token = AsyncMock(return_value={'access_token': 'tok', 'token_type': 'bearer'})
    with patch('authtuna.routers.social.get_social_provider', return_value=fake_provider):
        resp = await fastapi_client.get('/auth/unknown/callback')
        assert resp.status_code == 400 or resp.status_code == 404

@pytest.mark.asyncio
async def test_social_callback_new_user_username_sanitization(fastapi_client: AsyncClient):
    fake_provider = Mock()
    fake_provider.authorize_access_token = AsyncMock(return_value={'access_token': 'tok', 'token_type': 'bearer'})
    fake_provider.userinfo = AsyncMock(return_value={'sub': 'google_user_2', 'email': 'new2@example.com', 'name': None})
    with patch('authtuna.routers.social.get_social_provider', return_value=fake_provider):
        with patch('authtuna.routers.social.email_manager') as mock_email_mgr:
            mock_email_mgr.send_new_social_account_connected_email = AsyncMock()
            mock_email_mgr.send_welcome_email = AsyncMock()
            resp = await fastapi_client.get('/auth/google/callback')
            assert resp.status_code in (status.HTTP_302_FOUND, status.HTTP_307_TEMPORARY_REDIRECT)
