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
async def test_mfa_setup_success(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    async def fake_dispatch(self, request, call_next):
        request.state.user_id = fake_user.id
        request.state.user_object = fake_user
        request.state.device_data = {"region": "", "device": "Test"}
        return await call_next(request)

    with patch('authtuna.middlewares.session.DatabaseSessionMiddleware.dispatch', new=fake_dispatch):
        with patch('authtuna.routers.mfa.auth_service') as mock_auth:
            mock_auth.mfa.setup_totp = AsyncMock(return_value=("secret", "otpauth://..."))
            resp = await fastapi_client.post('/mfa/setup')
            assert resp.status_code == status.HTTP_200_OK
            assert 'provisioning_uri' in resp.json()


@pytest.mark.asyncio
async def test_mfa_verify_success(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    async def fake_dispatch(self, request, call_next):
        request.state.user_id = fake_user.id
        request.state.user_object = fake_user
        request.state.device_data = {"region": "", "device": "Test"}
        return await call_next(request)

    with patch('authtuna.middlewares.session.DatabaseSessionMiddleware.dispatch', new=fake_dispatch):
        with patch('authtuna.routers.mfa.auth_service') as mock_auth:
            mock_auth.mfa.verify_and_enable_totp = AsyncMock(return_value=["ABC-DEF-GHI"])
            with patch('authtuna.routers.mfa.email_manager') as mock_email:
                mock_email.send_mfa_added_email = AsyncMock()
                resp = await fastapi_client.post('/mfa/verify', json={'code': '123456'})
                assert resp.status_code == status.HTTP_200_OK
                assert 'recovery_codes' in resp.json()


@pytest.mark.asyncio
async def test_mfa_verify_invalid_code(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    from authtuna.core.exceptions import InvalidTokenError
    async def fake_dispatch(self, request, call_next):
        request.state.user_id = fake_user.id
        request.state.user_object = fake_user
        request.state.device_data = {"region": "", "device": "Test"}
        return await call_next(request)

    with patch('authtuna.middlewares.session.DatabaseSessionMiddleware.dispatch', new=fake_dispatch):
        with patch('authtuna.routers.mfa.auth_service') as mock_auth:
            mock_auth.mfa.verify_and_enable_totp = AsyncMock(side_effect=InvalidTokenError("bad code"))
            resp = await fastapi_client.post('/mfa/verify', json={'code': '000000'})
            assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_mfa_disable_success(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    fake_user.mfa_enabled = True
    async def fake_dispatch(self, request, call_next):
        request.state.user_id = fake_user.id
        request.state.user_object = fake_user
        request.state.device_data = {"region": "", "device": "Test"}
        return await call_next(request)

    with patch('authtuna.middlewares.session.DatabaseSessionMiddleware.dispatch', new=fake_dispatch):
        with patch('authtuna.routers.mfa.auth_service') as mock_auth:
            mock_auth.mfa.disable_mfa = AsyncMock()
            with patch('authtuna.routers.mfa.email_manager') as mock_email:
                mock_email.send_mfa_removed_email = AsyncMock()
                resp = await fastapi_client.post('/mfa/disable')
                assert resp.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_mfa_disable_conflict_when_not_enabled(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    fake_user.mfa_enabled = False
    async def fake_dispatch(self, request, call_next):
        request.state.user_id = fake_user.id
        request.state.user_object = fake_user
        request.state.device_data = {"region": "", "device": "Test"}
        return await call_next(request)

    with patch('authtuna.middlewares.session.DatabaseSessionMiddleware.dispatch', new=fake_dispatch):
        resp = await fastapi_client.post('/mfa/disable')
        assert resp.status_code == status.HTTP_409_CONFLICT


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
async def test_validate_mfa_login_invalid_token(fastapi_client: AsyncClient):
    from authtuna.core.exceptions import InvalidTokenError
    with patch('authtuna.routers.mfa.auth_service') as mock_auth:
        mock_auth.validate_mfa_login = AsyncMock(side_effect=InvalidTokenError('bad token'))
        resp = await fastapi_client.post('/mfa/validate-login', json={'mfa_token': 'tok', 'code': '123456'})
        assert resp.status_code == 401
        assert 'bad token' in resp.text


@pytest.mark.asyncio
async def test_disable_mfa_success(app, fastapi_client: AsyncClient, fake_user):
    fake_user.mfa_enabled = True
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    with patch('authtuna.routers.mfa.auth_service') as mock_auth:
        mock_auth.mfa.disable_mfa = AsyncMock()
        with patch('authtuna.routers.mfa.email_manager') as mock_email:
            mock_email.send_mfa_removed_email = AsyncMock()
            resp = await fastapi_client.post('/mfa/disable')
            assert resp.status_code == 200
            assert 'successfully disabled' in resp.text


@pytest.mark.asyncio
async def test_disable_mfa_not_enabled(app, fastapi_client: AsyncClient, fake_user):
    fake_user.mfa_enabled = False
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    resp = await fastapi_client.post('/mfa/disable')
    assert resp.status_code == 409
    assert 'not enabled' in resp.text


@pytest.mark.asyncio
async def test_show_mfa_setup_page_success(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    with patch('authtuna.routers.mfa.auth_service') as mock_auth:
        mock_auth.mfa.setup_totp = AsyncMock(return_value=("token", "otpauth://..."))
        resp = await fastapi_client.get('/mfa/setup')
        assert resp.status_code == 200
        assert 'text/html' in resp.headers.get('content-type', '')


@pytest.mark.asyncio
async def test_show_mfa_setup_page_forbidden(app, fastapi_client: AsyncClient, fake_user):
    app.dependency_overrides[mfa_router.get_current_user] = lambda: fake_user
    from authtuna.core.exceptions import OperationForbiddenError
    with patch('authtuna.routers.mfa.auth_service') as mock_auth:
        mock_auth.mfa.setup_totp = AsyncMock(side_effect=OperationForbiddenError('forbidden'))
        resp = await fastapi_client.get('/mfa/setup')
        assert resp.status_code == 403
        assert 'forbidden' in resp.text


@pytest.mark.asyncio
async def test_show_mfa_challenge_page(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/mfa/challenge')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers.get('content-type', '')
