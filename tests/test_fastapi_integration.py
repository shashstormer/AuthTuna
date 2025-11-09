import pytest
from fastapi import Request, status
from fastapi.exceptions import HTTPException
from authtuna.integrations.fastapi_integration import get_current_user, get_user_ip, PermissionChecker
from unittest.mock import AsyncMock, MagicMock, patch

import types
import asyncio

@pytest.mark.asyncio
async def test_get_current_user_authenticated():
    user_obj = MagicMock(id='u1')
    request = MagicMock()
    request.state = types.SimpleNamespace(user_id='u1', token_method="COOKIE")
    with patch('authtuna.integrations.fastapi_integration.auth_service.users.get_by_id', new=AsyncMock(return_value=user_obj)):
        user = await get_current_user(request)
        test_getting_cached = await get_current_user(request)
        assert user.id == 'u1'
        assert user is user_obj
        assert request.state.user_object is user_obj
        assert test_getting_cached is user_obj

@pytest.mark.asyncio
async def test_get_current_user_unauthenticated():
    request = MagicMock()
    request.state = types.SimpleNamespace()
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_get_current_user_not_found():
    request = MagicMock()
    request.state = types.SimpleNamespace(user_id='u2')
    with patch('authtuna.integrations.fastapi_integration.auth_service.users.get_by_id', new=AsyncMock(return_value=None)):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(request)
        print(exc.value.detail)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_get_current_user_error():
    request = MagicMock()
    request.state = types.SimpleNamespace(user_id='u3')
    with patch('authtuna.integrations.fastapi_integration.auth_service.users.get_by_id', new=AsyncMock(side_effect=Exception('fail'))):
        with pytest.raises(HTTPException) as exc:
            await get_current_user(request)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_user_ip():
    request = MagicMock()
    request.state = types.SimpleNamespace(user_ip_address='1.2.3.4')
    assert get_user_ip(request) == '1.2.3.4'

@pytest.mark.asyncio
async def test_permission_checker_and_mode():
    user = MagicMock(id='u1')
    request = MagicMock()
    request.state = types.SimpleNamespace(user_id='u1', token_method="COOKIE")
    # AND mode, missing permission
    checker = PermissionChecker('perm1', 'perm2', mode='AND')
    with patch('authtuna.integrations.fastapi_integration.auth_service.roles.has_permission', new=AsyncMock(return_value=False)):
        with pytest.raises(HTTPException) as exc:
            await checker(request, user)
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    # OR mode, at least one permission
    checker = PermissionChecker('perm1', 'perm2', mode='OR')
    with patch('authtuna.integrations.fastapi_integration.auth_service.roles.has_permission', new=AsyncMock(side_effect=[False, True])):
        result = await checker(request, user)
        assert result is user
    # Scope from path param missing
    checker = PermissionChecker('perm', mode='AND', scope_from_path='org_id')
    request.path_params = {}
    with pytest.raises(HTTPException) as exc:
        await checker(request, user)
    assert exc.value.status_code == 500

