import pytest
from sqlalchemy import select
from authtuna.core.database import User, Role, user_roles_association
from authtuna.core.hooks import Events
import time

@pytest.mark.asyncio
async def test_hooks_user_role_assignment(auth_tuna_async, dbsession):
    """Verify that creating a user triggers the default hook to assign 'User' role."""
    
    # 1. Standard Signup
    email = f"hook_test_{int(time.time())}@example.com"
    username = f"hook_user_{int(time.time())}"
    user, token = await auth_tuna_async.signup(username, email, "password123", "127.0.0.1")
    
    # Verify role assignment
    # Need to check DB
    stmt = select(Role).join(user_roles_association).where(
        user_roles_association.c.user_id == user.id,
        Role.name == "User"
    )
    role = (await dbsession.execute(stmt)).unique().scalar_one_or_none()
    assert role is not None, "Standard signup did not assign 'User' role via hook"

@pytest.mark.asyncio
async def test_social_registration_hooks(auth_tuna_async, dbsession):
    """Verify that social registration triggers hooks and assigns role."""
    email = f"social_hook_{int(time.time())}@example.com"
    provider_id = f"pid_{int(time.time())}"
    
    user, social_account = await auth_tuna_async.register_social_user(
        email=email,
        provider="github",
        provider_user_id=provider_id,
        token_data={"access_token": "token", "token_type": "bearer", "expires_at": time.time() + 3600},
        ip_address="127.0.0.1"
    )
    
    # Verify role assignment
    stmt = select(Role).join(user_roles_association).where(
        user_roles_association.c.user_id == user.id,
        Role.name == "User"
    )
    role = (await dbsession.execute(stmt)).unique().scalar_one_or_none()
    assert role is not None, "Social registration did not assign 'User' role via hook"
