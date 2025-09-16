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
async def test_mfa_qr_code_endpoint(fastapi_client: AsyncClient):
    resp = await fastapi_client.get('/mfa/qr-code', params={'uri': 'otpauth://totp/...'} )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.headers.get('content-type') == 'image/png'
