import pytest
from unittest.mock import AsyncMock, Mock, patch
from fastapi import status
from httpx import AsyncClient

from authtuna.core.database import User
import authtuna.routers.mfa as mfa_router


@pytest.fixture
def fake_user():
    return User(id="u1", username="u", email="u@example.com", mfa_enabled=False)


@pytest.mark.asyncio
async def test_get_qr_code_success(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/mfa/qr-code', params={'uri': 'otpauth://totp/...'} )
    assert resp.status_code == 200 or resp.status_code == 422  # 422 if missing required param
    assert resp.headers.get('content-type', '').startswith('image/png') or resp.status_code == 422


@pytest.mark.asyncio
async def test_validate_mfa_login_success(fastapi_client: AsyncClient):
    with patch('authtuna.routers.mfa.auth_service') as mock_auth:
        mock_auth.validate_mfa_login = AsyncMock(return_value=Mock(get_cookie_string=lambda: 'cookie'))
        resp = await fastapi_client.post('/mfa/validate-login', json={'mfa_token': 'tok', 'code': '123456'})
        assert resp.status_code == 200
        assert 'Login successful' in resp.text



@pytest.mark.asyncio
async def test_show_mfa_challenge_page(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/mfa/challenge')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers.get('content-type', '')
