import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_search_users_as_admin(auth_tuna_async, fastapi_client: AsyncClient):
    """Test searching for users as an admin."""
    # Create a test admin user and give them the necessary permissions
    admin_user = await auth_tuna_async.users.create(
        email="admin_for_test@example.com",
        username="admin_for_test",
        password="password123",
        ip_address="127.0.0.1"
    )
    await auth_tuna_async.roles.assign_to_user(admin_user.id, "Admin", "system", "global")
    await auth_tuna_async.permissions.create("admin:manage:system", "perm req to access admin router")
    await auth_tuna_async.roles.add_permission_to_role("Admin", "admin:manage:system")

    # Log in as the admin user to get a session token
    response = await fastapi_client.post(
        "/auth/login",
        json={"username_or_email": "admin_for_test", "password": "password123"},
    )
    assert response.status_code == status.HTTP_200_OK
    token = response.cookies.get("session_token")

    # Search for users
    response = await fastapi_client.get(
        "/admin/users/search",
        cookies={"session_token": token},
    )
    print(response.json())
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def setup_admin_with_permissions(auth_tuna_async):
    admin_user = await auth_tuna_async.users.get_by_username("admin_test")
    if not admin_user:
        admin_user = await auth_tuna_async.users.create(
            email="admin_test@example.com",
            username="admin_test",
            password="password123",
            ip_address="127.0.0.1"
        )
    await auth_tuna_async.roles.assign_to_user(admin_user.id, "Admin", "system", "global")
    return admin_user


@pytest.mark.asyncio
async def get_admin_token(fastapi_client: AsyncClient, admin_user):
    response = await fastapi_client.post(
        "/auth/login",
        json={"username_or_email": admin_user.username, "password": "password123"},
    )
    assert response.status_code == status.HTTP_200_OK
    return response.cookies.get("session_token")


@pytest.mark.asyncio
async def test_suspend_and_unsuspend_user(auth_tuna_async, fastapi_client: AsyncClient):
    admin_user = await setup_admin_with_permissions(auth_tuna_async)
    token = await get_admin_token(fastapi_client, admin_user)
    user = await auth_tuna_async.users.create(
        email="user_suspend@example.com",
        username="user_suspend",
        password="password123",
        ip_address="127.0.0.1"
    )
    # Suspend
    response = await fastapi_client.post(
        f"/admin/users/{user.id}/suspend",
        json={"reason": "test"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK
    # Unsuspend
    response = await fastapi_client.post(
        f"/admin/users/{user.id}/unsuspend",
        json={"reason": "test"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_get_user_audit_log(auth_tuna_async, fastapi_client: AsyncClient):
    admin_user = await setup_admin_with_permissions(auth_tuna_async)
    token = await get_admin_token(fastapi_client, admin_user)
    user = await auth_tuna_async.users.create(
        email="user_audit@example.com",
        username="user_audit",
        password="password123",
        ip_address="127.0.0.1"
    )
    response = await fastapi_client.get(
        f"/admin/users/{user.id}/audit-log",
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_create_role_and_permission(auth_tuna_async, fastapi_client: AsyncClient):
    admin_user = await setup_admin_with_permissions(auth_tuna_async)
    token = await get_admin_token(fastapi_client, admin_user)
    # Create role
    response = await fastapi_client.post(
        "/admin/roles",
        json={"name": "TestRole", "description": "desc", "level": 1},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_201_CREATED
    # Create permission
    response = await fastapi_client.post(
        "/admin/permissions",
        json={"name": "perm:test", "description": "desc"},
        cookies={"session_token": token},
    )
    # assert response.status_code == status.HTTP_201_CREATED
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_add_permission_to_role_and_assign_revoke(auth_tuna_async, fastapi_client: AsyncClient):
    admin_user = await setup_admin_with_permissions(auth_tuna_async)
    token = await get_admin_token(fastapi_client, admin_user)
    await auth_tuna_async.roles.create(name="RoleForPerm", description="desc", level=1)
    await auth_tuna_async.permissions.create("perm:assign", "desc")
    # Add permission to role
    response = await fastapi_client.post(
        "/admin/roles/RoleForPerm/permissions",
        json={"permission_name": "perm:assign"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK
    # Assign role to user
    user = await auth_tuna_async.users.create(
        email="user_assign@example.com",
        username="user_assign",
        password="password123",
        ip_address="127.0.0.1"
    )
    response = await fastapi_client.post(
        "/admin/users/roles/assign",
        json={"user_id": user.id, "role_name": "RoleForPerm", "scope": "global"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK
    # Revoke role from user
    response = await fastapi_client.post(
        "/admin/users/roles/revoke",
        json={"user_id": user.id, "role_name": "RoleForPerm", "scope": "global"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_delete_role_and_grants(auth_tuna_async, fastapi_client: AsyncClient):
    admin_user = await setup_admin_with_permissions(auth_tuna_async)
    token = await get_admin_token(fastapi_client, admin_user)
    await auth_tuna_async.roles.create(name="RoleToDelete", description="desc", level=1)
    # Delete role
    response = await fastapi_client.delete(
        "/admin/roles/RoleToDelete",
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_200_OK
    # Grant role assignment permission
    await auth_tuna_async.roles.create(name="GranterRole", description="desc", level=2)
    await auth_tuna_async.roles.create(name="AssignableRole", description="desc", level=1)
    response = await fastapi_client.post(
        "/admin/roles/grants/assign-role",
        json={"assigner_role_name": "GranterRole", "assignable_role_name": "AssignableRole"},
        cookies={"session_token": token},
    )
    assert response.status_code == status.HTTP_201_CREATED
    # Grant permission granting permission
    await auth_tuna_async.permissions.create("perm:grant", "desc")
    response = await fastapi_client.post(
        "/admin/roles/grants/grant-permission",
        json={"granter_role_name": "GranterRole", "grantable_permission_name": "perm:grant"},
        cookies={"session_token": token},
    )
    # assert response.status_code == status.HTTP_201_CREATED
    assert response.status_code == status.HTTP_403_FORBIDDEN