import pytest
from authtuna.core.exceptions import (
    UserAlreadyExistsError, UserNotFoundError, RoleNotFoundError, 
    PermissionNotFoundError, OperationForbiddenError, SessionNotFoundError
)
import uuid

@pytest.fixture
def unique_email():
    return f"test_{uuid.uuid4().hex}@example.com"

@pytest.fixture
def unique_username():
    return f"user_{uuid.uuid4().hex}"

@pytest.mark.asyncio
async def test_user_manager_errors(auth_tuna_async, unique_email, unique_username):
    # Create User
    user = await auth_tuna_async.users.create(unique_email, unique_username, "password")
    
    # Create Duplicate
    with pytest.raises(UserAlreadyExistsError):
        await auth_tuna_async.users.create(unique_email, "other_user", "password")
    
    with pytest.raises(UserAlreadyExistsError):
        await auth_tuna_async.users.create("other@example.com", unique_username, "password")

    # Update Non-existent
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.update("nonexistent", {"username": "new"})

    # Delete Non-existent
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.delete("nonexistent")

    # Set Password Non-existent
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.set_password("nonexistent", "newpass", "127.0.0.1")

    # Suspend/Unsuspend Non-existent
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.suspend_user("nonexistent", "admin_id")
    
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.unsuspend_user("nonexistent", "admin_id")

@pytest.mark.asyncio
async def test_role_manager_assign_errors(auth_tuna_async, authenticated_user):
    # Assigner not found
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="nonexistent")

    # Role not found
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "NonexistentRole", assigner_id=authenticated_user.id)

    # Target user not found
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.assign_to_user("nonexistent", "User", assigner_id="system")

    # Forbidden (Assigner lacks permission)
    # Create a dummy user without permissions
    dummy_user = await auth_tuna_async.users.create(f"dummy_{uuid.uuid4().hex}@example.com", f"dummy_{uuid.uuid4().hex}", "password")
    role, _ = await auth_tuna_async.roles.get_or_create("TestRole")
    
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "TestRole", assigner_id=dummy_user.id)

@pytest.mark.asyncio
async def test_role_manager_remove_errors(auth_tuna_async, authenticated_user):
    # Remover not found
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.remove_from_user(authenticated_user.id, "User", remover_id="nonexistent")

    # Role not found
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.remove_from_user(authenticated_user.id, "NonexistentRole", remover_id="system")

    # Target user not found
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.roles.remove_from_user("nonexistent", "User", remover_id="system")
    
    # Role not found for user (when trying to remove a role the user doesn't have)
    role, _ = await auth_tuna_async.roles.get_or_create("UnassignedRole")
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.remove_from_user(authenticated_user.id, "UnassignedRole", remover_id="system")

    # Forbidden
    dummy_user = await auth_tuna_async.users.create(f"dummy2_{uuid.uuid4().hex}@example.com", f"dummy2_{uuid.uuid4().hex}", "password")
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system")
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.remove_from_user(authenticated_user.id, "User", remover_id=dummy_user.id)

@pytest.mark.asyncio
async def test_role_manager_create_errors(auth_tuna_async):
    await auth_tuna_async.roles.create("UniqueRole")
    with pytest.raises(ValueError):
        await auth_tuna_async.roles.create("UniqueRole")

@pytest.mark.asyncio
async def test_role_manager_add_permission_errors(auth_tuna_async):
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.add_permission_to_role("NonexistentRole", "perm:test")
    
    role, _ = await auth_tuna_async.roles.get_or_create("TestRole2")
    with pytest.raises(PermissionNotFoundError):
        await auth_tuna_async.roles.add_permission_to_role("TestRole2", "perm:nonexistent")

@pytest.mark.asyncio
async def test_role_manager_grant_relationship_errors(auth_tuna_async):
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.grant_relationship("NonexistentRole", "User", auth_tuna_async.roles)
    
    role, _ = await auth_tuna_async.roles.get_or_create("TestRole3")
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.grant_relationship("TestRole3", "NonexistentRole", auth_tuna_async.roles)

@pytest.mark.asyncio
async def test_role_manager_delete_errors(auth_tuna_async, authenticated_user):
    # Forbidden (no permission)
    dummy_user = await auth_tuna_async.users.create(f"dummy3_{uuid.uuid4().hex}@example.com", f"dummy3_{uuid.uuid4().hex}", "password")
    role, _ = await auth_tuna_async.roles.get_or_create("RoleToDelete")
    
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.delete_role("RoleToDelete", deleter_id=dummy_user.id)

    # Grant permission to authenticated_user
    perm, _ = await auth_tuna_async.permissions.get_or_create("admin:manage:roles")
    admin_role, _ = await auth_tuna_async.roles.get_or_create("AdminRole")
    await auth_tuna_async.roles.add_permission_to_role("AdminRole", "admin:manage:roles")
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "AdminRole", assigner_id="system", scope="global")
    with pytest.raises(RoleNotFoundError):
        await auth_tuna_async.roles.delete_role("NonexistentRole", deleter_id=authenticated_user.id)
    system_role, _ = await auth_tuna_async.roles.get_or_create("SystemRole", defaults={"system": True})
    try:
        await auth_tuna_async.roles.create("SystemRoleUnique", system=True)
    except ValueError:
        pass # Already exists
    
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.roles.delete_role("SystemRoleUnique", deleter_id=authenticated_user.id)

@pytest.mark.asyncio
async def test_permission_manager_create_errors(auth_tuna_async):
    with pytest.raises(ValueError):
        await auth_tuna_async.permissions.create("invalid name") # Space not allowed usually?
    
    await auth_tuna_async.permissions.get_or_create("perm:valid")
    with pytest.raises(ValueError):
        await auth_tuna_async.permissions.create("perm:valid")

@pytest.mark.asyncio
async def test_session_manager_terminate_errors(auth_tuna_async):
    with pytest.raises(SessionNotFoundError):
        await auth_tuna_async.sessions.terminate("nonexistent_session", "127.0.0.1", errors="raise")
