import pytest
from authtuna.core.exceptions import UserAlreadyExistsError, UserNotFoundError, InvalidCredentialsError

@pytest.mark.asyncio
async def test_create_user(auth_tuna_async):
    """Test creating a new user."""
    user = await auth_tuna_async.users.create(
        email="test@example.com",
        username="testuser",
        password="password123",
        ip_address="127.0.0.1"
    )
    assert user.email == "test@example.com"
    assert user.username == "testuser"

@pytest.mark.asyncio
async def test_create_duplicate_user(auth_tuna_async):
    """Test that creating a user with a duplicate email or username raises an error."""
    await auth_tuna_async.users.create(
        email="test2@example.com",
        username="testuser2",
        password="password123",
        ip_address="127.0.0.1"
    )
    with pytest.raises(UserAlreadyExistsError):
        await auth_tuna_async.users.create(
            email="test2@example.com",
            username="anotheruser",
            password="password123",
            ip_address="127.0.0.1"
        )
