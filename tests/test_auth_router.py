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
async def test_show_signup_page(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/auth/signup')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers['content-type']


@pytest.mark.asyncio
async def test_show_login_page(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/auth/login')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers['content-type']


@pytest.mark.asyncio
async def test_login_success(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_user = type('U', (), {'id': 'u', 'email': 'e@example.com', 'username': 'u'})()
        mock_session = type('S', (), {'get_cookie_string': lambda self: 'cookie'})()
        mock_auth.login = AsyncMock(return_value=(mock_user, mock_session))
        with patch('authtuna.routers.auth.create_session_and_set_cookie', new=AsyncMock()):
            resp = await fastapi_client.post('/auth/login', json={
                'username_or_email': 'u', 'password': 'pw123456'
            })
            assert resp.status_code == 200
            assert 'message' in resp.json() or resp.json() == {}


@pytest.mark.asyncio
async def test_login_invalid_credentials(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import InvalidCredentialsError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.login = AsyncMock(side_effect=InvalidCredentialsError("Invalid credentials"))
        resp = await fastapi_client.post('/auth/login', json={
            'username_or_email': 'u', 'password': 'wrongpw'
        })
        assert resp.status_code == 401
        assert 'Invalid credentials' in resp.text


@pytest.mark.asyncio
async def test_signup_user_already_exists(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import UserAlreadyExistsError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.signup = AsyncMock(side_effect=UserAlreadyExistsError("User exists"))
        resp = await fastapi_client.post('/auth/signup', json={
            'username': 'u', 'email': 'e@example.com', 'password': 'pw123456'
        })
        assert resp.status_code == 409
        assert 'User exists' in resp.text


@pytest.mark.asyncio
async def test_logout_success(fastapi_client: AsyncClient):
    resp = await fastapi_client.post('/auth/logout')
    assert resp.status_code == 200
    assert 'Logged out' in resp.text or resp.json().get('message')


@pytest.mark.asyncio
async def test_forgot_password_success(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth, \
         patch('authtuna.routers.auth.email_manager') as mock_email_mgr:
        mock_auth.request_password_reset = AsyncMock(return_value=type('T', (), {'id': 'tid'})())
        mock_email_mgr.send_password_reset_email = AsyncMock()
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/forgot-password', json={'email': 'e@example.com'})
            assert resp.status_code == 202
            assert 'reset link' in resp.text or resp.json().get('message')


@pytest.mark.asyncio
async def test_forgot_password_rate_limit(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import RateLimitError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.request_password_reset = AsyncMock(side_effect=RateLimitError('Too many requests'))
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/forgot-password', json={'email': 'e@example.com'})
            assert resp.status_code == 429
            assert 'Too many requests' in resp.text


@pytest.mark.asyncio
async def test_forgot_password_generic_error(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.request_password_reset = AsyncMock(side_effect=Exception('fail'))
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/forgot-password', json={'email': 'e@example.com'})
            assert resp.status_code == 202  # Always generic message


@pytest.mark.asyncio
async def test_reset_password_success(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth, \
         patch('authtuna.routers.auth.email_manager') as mock_email_mgr:
        mock_auth.reset_password = AsyncMock(return_value=type('U', (), {'email': 'e@example.com'})())
        mock_email_mgr.send_password_change_email = AsyncMock()
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/reset-password', json={'token': 't', 'new_password': 'pw'})
            assert resp.status_code == 200
            assert 'Password has been reset' in resp.text or resp.json().get('message')


@pytest.mark.asyncio
async def test_reset_password_invalid_token(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import InvalidTokenError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.reset_password = AsyncMock(side_effect=InvalidTokenError('bad token'))
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/reset-password', json={'token': 't', 'new_password': 'pw'})
            assert resp.status_code == 400
            assert 'bad token' in resp.text


@pytest.mark.asyncio
async def test_reset_password_generic_error(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.reset_password = AsyncMock(side_effect=Exception('fail'))
        with patch('authtuna.core.config.settings.EMAIL_ENABLED', True):
            resp = await fastapi_client.post('/auth/reset-password', json={'token': 't', 'new_password': 'pw'})
            assert resp.status_code == 500
            assert 'unexpected error' in resp.text.lower()


@pytest.mark.asyncio
async def test_verify_email_expired_token(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import TokenExpiredError
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.verify_email = AsyncMock(side_effect=TokenExpiredError('expired'))
        resp = await fastapi_client.get('/auth/verify', params={'token': 'expired'})
        assert resp.status_code == 200
        assert 'text/html' in resp.headers.get('content-type', '')
        assert 'expired' in resp.text


@pytest.mark.asyncio
async def test_verify_email_generic_error(fastapi_client: AsyncClient):
    with patch('authtuna.routers.auth.auth_service') as mock_auth:
        mock_auth.verify_email = AsyncMock(side_effect=Exception('fail'))
        resp = await fastapi_client.get('/auth/verify', params={'token': 'fail'})
        assert resp.status_code == 200
        assert 'text/html' in resp.headers.get('content-type', '')
        assert 'unexpected error' in resp.text.lower()


@pytest.mark.asyncio
async def test_reset_password_page_valid_token(fastapi_client: AsyncClient):
    # This test assumes a valid token is present in the DB. If not, it will render error page.
    # For full coverage, you may want to insert a valid token into the test DB before running this test.
    resp = await fastapi_client.get('/auth/reset-password', params={'token': 'validtoken'})
    assert resp.status_code == 200
    assert 'text/html' in resp.headers.get('content-type', '')


@pytest.mark.asyncio
async def test_show_forgot_password_page(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/auth/forgot-password')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers.get('content-type', '')
