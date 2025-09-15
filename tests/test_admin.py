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