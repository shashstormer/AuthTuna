import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from fastapi import status
import authtuna.routers.auth as auth_router


@pytest.mark.asyncio
async def test_signup_email_disabled_creates_session(fastapi_client: AsyncClient):
    # email disabled path => no verification token, create session and welcome email
    with patch('authtuna.routers.auth.auth_service') as mock_auth, \
         patch('authtuna.routers.auth.create_session_and_set_cookie', new=AsyncMock()):
        mock_user = type('U', (), {'id': 'u', 'email': 'e@example.com', 'username': 'u'})()
        mock_auth.signup = AsyncMock(return_value=(mock_user, None))
        with patch('authtuna.routers.auth.email_manager') as mock_email_mgr:
            mock_email_mgr.send_welcome_email = AsyncMock()
            resp = await fastapi_client.post('/auth/signup', json={
                'username': 'u', 'email': 'e@example.com', 'password': 'pw123456'
            })
            assert resp.status_code in (status.HTTP_200_OK, status.HTTP_201_CREATED, status.HTTP_202_ACCEPTED)


@pytest.mark.asyncio
async def test_login_mfa_required_path(fastapi_client: AsyncClient):
    from authtuna.core.database import Token
    import time
    mfa_token = Token(id='mfaid', purpose='mfa_validation', user_id='uid', ctime=time.time(), etime=time.time()+3600, used=False)
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.login = AsyncMock(return_value=(object(), mfa_token))
        resp = await fastapi_client.post('/auth/login', json={
            'username_or_email': 'u', 'password': 'pw'
        })
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data.get('mfa_required') is True
        assert data.get('mfa_token') == 'mfaid'


@pytest.mark.asyncio
async def test_forgot_password_email_disabled(fastapi_client: AsyncClient):
    # EMAIL_ENABLED is False in tests; endpoint should return 501
    resp = await fastapi_client.post('/auth/forgot-password', json={'email': 'e@example.com'})
    assert resp.status_code == status.HTTP_501_NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_reset_password_email_disabled(fastapi_client: AsyncClient):
    resp = await fastapi_client.post('/auth/reset-password', json={'token': 't', 'new_password': 'pw'})
    assert resp.status_code == status.HTTP_501_NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_verify_email_success_template(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.verify_email = AsyncMock(return_value=None)
        resp = await fastapi_client.get('/auth/verify', params={'token': 'ok'})
        assert resp.status_code == status.HTTP_200_OK
        assert 'text/html' in resp.headers.get('content-type', '')


@pytest.mark.asyncio
async def test_verify_email_error_template(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import InvalidTokenError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.verify_email = AsyncMock(side_effect=InvalidTokenError('bad'))
        resp = await fastapi_client.get('/auth/verify', params={'token': 'bad'})
        assert resp.status_code == status.HTTP_200_OK
        assert 'text/html' in resp.headers.get('content-type', '')


@pytest.mark.asyncio
async def test_reset_password_page_invalid_token(fastapi_client: AsyncClient):
    # No token in DB -> error page
    resp = await fastapi_client.get('/auth/reset-password', params={'token': 'missing'})
    assert resp.status_code == status.HTTP_200_OK
    assert 'text/html' in resp.headers.get('content-type', '')


@pytest.mark.asyncio
async def test_user_info_dependency_override(app, fastapi_client: AsyncClient):
    from authtuna.integrations.fastapi_integration import get_current_user
    fake_user = type('U', (), {
        'id': 'id', 'username': 'name', 'email': 'email', 'is_active': True, 'email_verified': False, 'mfa_enabled': False
    })()
    app.dependency_overrides[get_current_user] = lambda: fake_user
    resp = await fastapi_client.get('/auth/user-info')
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data['user_id'] == 'id'
    assert data['username'] == 'name'
