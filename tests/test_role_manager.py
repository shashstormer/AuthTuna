import pytest
from authtuna.core.exceptions import UserNotFoundError, OperationForbiddenError, RoleNotFoundError

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
        email="test23@example.com",
        username="testuser23",
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
        email="test10@example.com",
        username="testuser10",
        password="password123",
        ip_address="127.0.0.1"
    )
    role = await auth_tuna_async.roles.create(name="Test-Duplicate", description="Dup role", level=1)
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    user_with_roles = await auth_tuna_async.users.get_by_id(user.id)
    assert [r.name for r in user_with_roles.roles].count("Test-Duplicate") == 1

@pytest.mark.asyncio
async def test_remove_role_from_user(auth_tuna_async):
    """Test removing a role from a user."""
    user = await auth_tuna_async.users.create(
        email="test11@example.com",
        username="testuser11",
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
        email="test12@example.com",
        username="testuser12",
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

@pytest.mark.asyncio
async def test_get_or_create_role(auth_tuna_async):
    role, created = await auth_tuna_async.roles.get_or_create("Test-GetOrCreate", defaults={"description": "desc", "level": 1})
    assert created is True
    role2, created2 = await auth_tuna_async.roles.get_or_create("Test-GetOrCreate")
    assert created2 is False
    assert role.id == role2.id

@pytest.mark.asyncio
async def test_add_permission_to_role(auth_tuna_async):
    role = await auth_tuna_async.roles.create(name="Test-AddPerm", description="desc", level=1)
    perm = await auth_tuna_async.permissions.create(name="perm:add", description="desc")
    await auth_tuna_async.roles.add_permission_to_role(role.name, perm.name)
    # Should not raise if added again
    await auth_tuna_async.roles.add_permission_to_role(role.name, perm.name)

@pytest.mark.asyncio
async def test_grant_relationship(auth_tuna_async):
    role1 = await auth_tuna_async.roles.create(name="Test-Grant1", description="desc", level=2)
    role2 = await auth_tuna_async.roles.create(name="Test-Grant2", description="desc", level=1)
    await auth_tuna_async.roles.grant_relationship(role1.name, role2.name, auth_tuna_async.roles, "can_assign_roles")
    # Should not raise if granted again
    await auth_tuna_async.roles.grant_relationship(role1.name, role2.name, auth_tuna_async.roles, "can_assign_roles")

@pytest.mark.asyncio
async def test_has_permission(auth_tuna_async):
    role = await auth_tuna_async.roles.create(name="Test-HasPerm", description="desc", level=1)
    perm = await auth_tuna_async.permissions.create(name="perm:has", description="desc")
    await auth_tuna_async.roles.add_permission_to_role(role.name, perm.name)
    user = await auth_tuna_async.users.create(email="test13@example.com", username="testuser13", password="pw", ip_address="1.1.1.1")
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, "system")
    assert await auth_tuna_async.roles.has_permission(user.id, perm.name)
    assert not await auth_tuna_async.roles.has_permission(user.id, "notaperm")

@pytest.mark.asyncio
async def test_revoke_user_role_by_scope(auth_tuna_async):
    role = await auth_tuna_async.roles.create(name="Test-Revoke", description="desc", level=2)
    user = await auth_tuna_async.users.create(email="test14@example.com", username="testuser14", password="pw", ip_address="1.1.1.1")
    admin = await auth_tuna_async.users.create(email="admin1@example.com", username="adminuser1", password="pw", ip_address="1.1.1.1")
    await auth_tuna_async.roles.assign_to_user(admin.id, role.name, "system", scope="global")
    await auth_tuna_async.roles.assign_to_user(admin.id, "Admin", "system", scope="global")
    await auth_tuna_async.roles.assign_to_user(user.id, role.name, admin.id)
    assert await auth_tuna_async.roles.revoke_user_role_by_scope(user.id, role.name, "none", admin.id)
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.revoke_user_role_by_scope(user.id, role.name, "none", user.id)

@pytest.mark.asyncio
async def test_delete_role_errors(auth_tuna_async):
    role = await auth_tuna_async.roles.create(name="Test-DeleteErr", description="desc", level=1)
    admin = await auth_tuna_async.users.create(email="admin2@example.com", username="adminuser2", password="pw", ip_address="1.1.1.1")
    # Should fail if user lacks permission
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.delete_role(role.name, admin.id)
    # Should fail for system role
    sysrole = await auth_tuna_async.roles.create(name="Test-System", description="desc", system=True, level=1)
    # Grant admin permission to delete roles
    perm, new = await auth_tuna_async.permissions.get_or_create(name="admin:manage:roles", defaults={"description": "desc"})
    assert new is False
    await auth_tuna_async.roles.add_permission_to_role(sysrole.name, perm.name)
    await auth_tuna_async.roles.assign_to_user(admin.id, sysrole.name, "system")
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.delete_role(sysrole.name, admin.id)

@pytest.mark.asyncio
async def test_remove_from_user_errors(auth_tuna_async):
    user = await auth_tuna_async.users.create(email="test15@example.com", username="testuser15", password="pw", ip_address="1.1.1.1")
    admin = await auth_tuna_async.users.create(email="admin3@example.com", username="adminuser3", password="pw", ip_address="1.1.1.1")
    role = await auth_tuna_async.roles.create(name="Test-RemoveErr", description="desc", level=1)
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.remove_from_user(user.id, role.name, "notfound")
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.remove_from_user(user.id, "notarole", admin.id)
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.remove_from_user(user.id, role.name, "default-admin")
