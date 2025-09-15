import pytest
from authtuna.core.exceptions import RoleNotFoundError, UserNotFoundError

@pytest.mark.asyncio
async def test_create_role(auth_tuna_async):
    """Test creating a new role."""
    role = await auth_tuna_async.roles.create(name="Test-Admin", description="Administrator role", level=1)
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

@pytest.mark.asyncio
async def test_get_role_by_name_and_id(auth_tuna_async):
    """Test retrieving a role by name and ID."""
    role = await auth_tuna_async.roles.create(name="Test-Viewer", description="Viewer role", level=1)
    by_name = await auth_tuna_async.roles.get_by_name("Test-Viewer")
    by_id = await auth_tuna_async.roles.get_by_id(role.id)
    assert by_name.id == role.id
    assert by_id.name == "Test-Viewer"

@pytest.mark.asyncio
async def test_delete_role(auth_tuna_async):
    """Test deleting a role."""
    role = await auth_tuna_async.roles.create(name="Test-Deletable", description="To delete", level=1)
    await auth_tuna_async.roles.delete_role(role.name, "default-admin")

    result = await auth_tuna_async.roles.get_by_id(role.id)
    assert result is None

@pytest.mark.asyncio
async def test_assign_same_role_twice(auth_tuna_async):
    """Test assigning the same role to a user twice."""
    user = await auth_tuna_async.users.create(
        email="test7@example.com",
        username="testuser7",
        password="password123",
        ip_address="127.0.0.1"
    )
    role = await auth_tuna_async.roles.create(name="Test-Duplicate", description="Dup role", level=1)
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    # Should not raise or duplicate
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    user_with_roles = await auth_tuna_async.users.get_by_id(user.id)
    assert [r.name for r in user_with_roles.roles].count("Test-Duplicate") == 1

@pytest.mark.asyncio
async def test_remove_role_from_user(auth_tuna_async):
    """Test removing a role from a user."""
    user = await auth_tuna_async.users.create(
        email="test5@example.com",
        username="testuser5",
        password="password123",
        ip_address="127.0.0.1"
    )
    role = await auth_tuna_async.roles.create(name="Test-Remove", description="Removable role", level=1)
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    await auth_tuna_async.roles.remove_from_user(user.id, role.name, "default-admin")
    user_with_roles = await auth_tuna_async.users.get_by_id(user.id)
    assert "Test-Remove" not in [r.name for r in user_with_roles.roles]

@pytest.mark.asyncio
async def test_list_user_roles(auth_tuna_async):
    """Test listing all roles for a user."""
    user = await auth_tuna_async.users.create(
        email="test6@example.com",
        username="testuser6",
        password="password123",
        ip_address="127.0.0.1"
    )
    await auth_tuna_async.roles.create(name="Test-Role1", description="Role1", level=1)
    await auth_tuna_async.roles.create(name="Test-Role2", description="Role2", level=1)
    await auth_tuna_async.roles.assign_to_user(user.id, "Test-Role1", "system")
    await auth_tuna_async.roles.assign_to_user(user.id, "Test-Role2", "system")
    roles = await auth_tuna_async.roles.get_user_roles_with_scope(user.id)
    role_names = [r["role_name"] for r in roles]
    assert "Test-Role1" in role_names and "Test-Role2" in role_names

@pytest.mark.asyncio
async def test_assign_role_to_nonexistent_user(auth_tuna_async):
    """Test assigning a role to a nonexistent user."""
    role = await auth_tuna_async.roles.create(name="Test-NonUser", description="Role", level=1)
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.assign_to_user("nonexistent-id", role.name, "system")

