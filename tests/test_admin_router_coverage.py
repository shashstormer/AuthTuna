import pytest
from unittest.mock import AsyncMock, patch
from fastapi import status
from authtuna.core.exceptions import UserNotFoundError, RoleNotFoundError, PermissionNotFoundError, OperationForbiddenError

@pytest.fixture
async def setup_admin_user(auth_tuna_async, authenticated_user):
    # Create Admin Role with all permissions
    role, _ = await auth_tuna_async.roles.get_or_create("SuperAdmin")
    permissions = [
        "admin:access:panel",
        "admin:manage:users",
        "admin:manage:roles",
        "admin:manage:permissions"
    ]
    for perm_name in permissions:
        await auth_tuna_async.permissions.get_or_create(perm_name)
        await auth_tuna_async.roles.add_permission_to_role("SuperAdmin", perm_name)
    
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "SuperAdmin", assigner_id="system", scope="global")

@pytest.mark.asyncio
async def test_get_assignable_roles_user_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.get_assignable_roles_for_user", side_effect=UserNotFoundError("User not found")):
        response = await fastapi_client.get("/admin/users/nonexistent_user/assignable-roles")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_user_details_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    async def get_by_id_side_effect(user_id, *args, **kwargs):
        if user_id == authenticated_user.id:
            return authenticated_user
        return None

    with patch("authtuna.routers.admin.auth_service.users.get_by_id", side_effect=get_by_id_side_effect):
        response = await fastapi_client.get("/admin/users/nonexistent_user/details-data")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_role_details_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.get_by_name", return_value=None):
        response = await fastapi_client.get("/admin/roles/NonexistentRole/details-data")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Role not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_suspend_user_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.users.suspend_user", side_effect=UserNotFoundError("User not found")):
        response = await fastapi_client.post("/admin/users/nonexistent_user/suspend", json={"reason": "test"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_unsuspend_user_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.users.unsuspend_user", side_effect=UserNotFoundError("User not found")):
        response = await fastapi_client.post("/admin/users/nonexistent_user/unsuspend", json={"reason": "test"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_create_role_conflict(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.create", side_effect=ValueError("Role already exists")):
        response = await fastapi_client.post("/admin/roles", json={"name": "ExistingRole"})
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "Role already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_create_permission_conflict(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.permissions.get_or_create", side_effect=ValueError("Permission error")):
        response = await fastapi_client.post("/admin/permissions", json={"name": "perm:test"})
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "Permission error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_add_permission_to_role_not_found(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.add_permission_to_role", side_effect=RoleNotFoundError("Role not found")):
        response = await fastapi_client.post("/admin/roles/NonexistentRole/permissions", json={"permission_name": "perm:test"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Role not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_assign_role_to_user_errors(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Not Found
    with patch("authtuna.routers.admin.auth_service.roles.assign_to_user", side_effect=UserNotFoundError("User not found")):
        response = await fastapi_client.post("/admin/users/roles/assign", json={"user_id": "uid", "role_name": "role"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    # Forbidden
    with patch("authtuna.routers.admin.auth_service.roles.assign_to_user", side_effect=OperationForbiddenError("Forbidden")):
        response = await fastapi_client.post("/admin/users/roles/assign", json={"user_id": "uid", "role_name": "role"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_revoke_role_from_user_errors(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Not Found (RoleNotFoundError)
    with patch("authtuna.routers.admin.auth_service.roles.revoke_user_role_by_scope", side_effect=RoleNotFoundError("Role not found")):
        response = await fastapi_client.post("/admin/users/roles/revoke", json={"user_id": "uid", "role_name": "role"})
        assert response.status_code == status.HTTP_404_NOT_FOUND

    # Not Found (Success False)
    with patch("authtuna.routers.admin.auth_service.roles.revoke_user_role_by_scope", return_value=False):
        response = await fastapi_client.post("/admin/users/roles/revoke", json={"user_id": "uid", "role_name": "role"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "Role assignment not found" in response.json()["detail"]
    
    # Forbidden
    with patch("authtuna.routers.admin.auth_service.roles.revoke_user_role_by_scope", side_effect=OperationForbiddenError("Forbidden")):
        response = await fastapi_client.post("/admin/users/roles/revoke", json={"user_id": "uid", "role_name": "role"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_delete_role_errors(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Not Found
    with patch("authtuna.routers.admin.auth_service.roles.delete_role", side_effect=RoleNotFoundError("Role not found")):
        response = await fastapi_client.delete("/admin/roles/NonexistentRole")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    # Forbidden
    with patch("authtuna.routers.admin.auth_service.roles.delete_role", side_effect=OperationForbiddenError("Forbidden")):
        response = await fastapi_client.delete("/admin/roles/ProtectedRole")
        assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_grant_role_assignment_permission_error(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.grant_relationship", side_effect=RoleNotFoundError("Role not found")):
        response = await fastapi_client.post("/admin/roles/grants/assign-role", json={"assigner_role_name": "r1", "assignable_role_name": "r2"})
        assert response.status_code == status.HTTP_404_NOT_FOUND

@pytest.mark.asyncio
async def test_grant_permission_granting_permission_error(fastapi_client, auth_tuna_async, authenticated_user, setup_admin_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.admin.auth_service.roles.grant_relationship", side_effect=PermissionNotFoundError("Perm not found")):
        response = await fastapi_client.post("/admin/roles/grants/grant-permission", json={"granter_role_name": "r1", "grantable_permission_name": "p1"})
        assert response.status_code == status.HTTP_404_NOT_FOUND
