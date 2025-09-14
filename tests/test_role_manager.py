import pytest

@pytest.mark.asyncio
async def test_create_role(auth_tuna_async):
    """Test creating a new role."""
    role = await auth_tuna_async.roles.create(name="Test-Admin", description="Administrator role")
    assert role.name == "Test-Admin"
    assert role.description == "Administrator role"

@pytest.mark.asyncio
async def test_assign_role_to_user(auth_tuna_async):
    """Test assigning a role to a user."""
    user = await auth_tuna_async.users.create(
        email="test3@example.com",
        username="testuser3",
        password="password123",
        ip_address="127.0.0.1"
    )
    role = await auth_tuna_async.roles.create(name="Test-Editor", description="Editor role", level=1)
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    user_with_roles = await auth_tuna_async.users.get_by_id(user.id)
    assert "Test-Editor" in [r.name for r in user_with_roles.roles]