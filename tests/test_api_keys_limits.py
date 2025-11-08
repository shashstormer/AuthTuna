import pytest

from authtuna.core.exceptions import OperationForbiddenError
from authtuna.core.config import init_settings


@pytest.mark.asyncio
async def test_master_key_limit(auth_tuna_async, authenticated_user):
    user = authenticated_user
    # Ensure we use default MAX_MASTER_KEYS_PER_USER from settings (5)
    max_master = auth_tuna_async.api._db_manager  # just to reference object; we'll get limit from settings
    # Create up to the limit
    from authtuna.core.config import get_settings
    limit = get_settings().MAX_MASTER_KEYS_PER_USER
    created = []
    for i in range(limit):
        key = await auth_tuna_async.api.create_key(user.id, f"master-{i}", key_type="master", scopes=None, valid_seconds=3600)
        created.append(key)
    # Next creation should raise
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.api.create_key(user.id, "master-overflow", key_type="master", scopes=None, valid_seconds=3600)


@pytest.mark.asyncio
async def test_total_api_key_limit_with_reinit(auth_tuna_async, authenticated_user):
    # Reinitialize settings to a small total key limit for this test
    init_settings(MAX_API_KEYS_PER_USER=3)
    from authtuna.core.config import get_settings
    assert get_settings().MAX_API_KEYS_PER_USER == 3

    user = authenticated_user
    # create 3 keys (mix types)
    await auth_tuna_async.api.create_key(user.id, "k1", key_type="public", scopes=None, valid_seconds=3600)
    await auth_tuna_async.api.create_key(user.id, "k2", key_type="secret", scopes=[], valid_seconds=3600)
    await auth_tuna_async.api.create_key(user.id, "k3", key_type="test", scopes=[], valid_seconds=3600)

    # Next creation should raise
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.api.create_key(user.id, "k4", key_type="secret", scopes=[], valid_seconds=3600)


@pytest.mark.asyncio
async def test_secret_scope_limit(auth_tuna_async, authenticated_user):
    # Set scope limit to 1
    init_settings(MAX_SCOPES_PER_SECRET_KEY=1)
    from authtuna.core.config import get_settings
    assert get_settings().MAX_SCOPES_PER_SECRET_KEY == 1

    user = authenticated_user
    # Ensure the user has the role required for the scopes
    # Create a role and assign to user if needed
    await auth_tuna_async.roles.create("RoleA")
    await auth_tuna_async.roles.grant_relationship("System", "RoleA", auth_tuna_async.roles, "can_assign_roles")
    await auth_tuna_async.roles.assign_to_user(user.id, "RoleA", assigner_id="system", scope="global")

    # Creating a secret key with 1 scope should succeed
    key = await auth_tuna_async.api.create_key(user.id, "secret-1", key_type="secret", scopes=["RoleA"], valid_seconds=3600)
    assert key is not None

    # Creating a secret key with 2 scopes should fail
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.api.create_key(user.id, "secret-2", key_type="secret", scopes=["RoleA", "RoleA:sub"], valid_seconds=3600)

