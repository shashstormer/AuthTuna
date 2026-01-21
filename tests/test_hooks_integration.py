import time
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select, update

from authtuna.core.database import User, Role, user_roles_association


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
    """Verify that social registration triggers hooks, assigns role, and sends emails."""
    email = f"social_hook_{int(time.time())}@example.com"
    provider_id = f"pid_{int(time.time())}"
    with patch("authtuna.manager.asynchronous.email_manager") as mock_email_manager:
        mock_email_manager.send_welcome_email = AsyncMock()
        mock_email_manager.send_new_social_account_connected_email = AsyncMock()

        user, social_account = await auth_tuna_async.register_social_user(
            email=email,
            provider="github",
            provider_user_id=provider_id,
            token_data={"access_token": "token", "token_type": "bearer", "expires_at": time.time() + 3600},
            ip_address="127.0.0.1"
        )
        
        stmt = select(Role).join(user_roles_association).where(
            user_roles_association.c.user_id == user.id,
            Role.name == "User"
        )
        role = (await dbsession.execute(stmt)).unique().scalar_one_or_none()
        assert role is not None, "Social registration did not assign 'User' role via hook"
        
        mock_email_manager.send_welcome_email.assert_called_once()
        mock_email_manager.send_new_social_account_connected_email.assert_not_called()
        mock_email_manager.send_welcome_email.reset_mock()
        mock_email_manager.send_new_social_account_connected_email.reset_mock()
        old_time = time.time() - 3600
        await dbsession.execute(
            update(User).where(User.id == user.id).values(created_at=old_time)
        )
        await dbsession.commit()
        
        user2, social2 = await auth_tuna_async.register_social_user(
            email=email,
            provider="github",
            provider_user_id=provider_id,
            token_data={"access_token": "token2", "token_type": "bearer", "expires_at": time.time() + 3600},
            ip_address="127.0.0.1",
            username_candidate="existing_user"
        )
        
        mock_email_manager.send_welcome_email.assert_not_called()
        mock_email_manager.send_new_social_account_connected_email.assert_called_once()
