import pytest
from authtuna.core.exceptions import UserAlreadyExistsError, UserNotFoundError, InvalidCredentialsError

@pytest.mark.asyncio
async def test_create_user(auth_tuna_async):
    """Test creating a new user."""
    user = await auth_tuna_async.users.create(
        email="test25@example.com",
        username="testuser25",
        password="password123",
        ip_address="127.0.0.1"
    )
    assert user.email == "test25@example.com"
    assert user.username == "testuser25"

@pytest.mark.asyncio
async def test_create_duplicate_user(auth_tuna_async):
    """Test that creating a user with a duplicate email or username raises an error."""
    await auth_tuna_async.users.create(
        email="test24@example.com",
        username="testuser24",
        password="password123",
        ip_address="127.0.0.1"
    )
    with pytest.raises(UserAlreadyExistsError):
        await auth_tuna_async.users.create(
            email="test24@example.com",
            username="anotheruser",
            password="password123",
            ip_address="127.0.0.1"
        )

@pytest.mark.asyncio
async def test_get_by_id_and_not_found(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test20@example.com",
        username="testuser20",
        password="password123",
        ip_address="127.0.0.1"
    )
    found = await auth_tuna_async.users.get_by_id(user.id)
    assert found is not None
    not_found = await auth_tuna_async.users.get_by_id("nonexistent")
    assert not_found is None

@pytest.mark.asyncio
async def test_get_by_email_and_username(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test21@example.com",
        username="testuser21",
        password="password123",
        ip_address="127.0.0.1"
    )
    by_email = await auth_tuna_async.users.get_by_email("test21@example.com")
    by_username = await auth_tuna_async.users.get_by_username("testuser21")
    assert by_email.id == user.id
    assert by_username.id == user.id

@pytest.mark.asyncio
async def test_list_users(auth_tuna_async):
    users = await auth_tuna_async.users.list()
    assert isinstance(users, list)

@pytest.mark.asyncio
async def test_update_user_and_not_found(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test22@example.com",
        username="testuser22",
        password="password123",
        ip_address="127.0.0.1"
    )
    updated = await auth_tuna_async.users.update(user.id, {"username": "updateduser"})
    assert updated.username == "updateduser"
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.update("nonexistent", {"username": "fail"})

@pytest.mark.asyncio
async def test_delete_user_and_not_found(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test16@example.com",
        username="testuser16",
        password="password123",
        ip_address="127.0.0.1"
    )
    await auth_tuna_async.users.delete(user.id)
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.delete("nonexistent")

@pytest.mark.asyncio
async def test_set_password_and_not_found(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test17@example.com",
        username="testuser17",
        password="password123",
        ip_address="127.0.0.1"
    )
    await auth_tuna_async.users.set_password(user.id, "newpassword", "127.0.0.1")
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.set_password("nonexistent", "pw", "127.0.0.1")

@pytest.mark.asyncio
async def test_suspend_and_unsuspend_user(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test18@example.com",
        username="testuser18",
        password="password123",
        ip_address="127.0.0.1"
    )
    suspended = await auth_tuna_async.users.suspend_user(user.id, "admin")
    assert suspended.is_active is False
    unsuspended = await auth_tuna_async.users.unsuspend_user(user.id, "admin")
    assert unsuspended.is_active is True
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.suspend_user("nonexistent", "admin")
    with pytest.raises(UserNotFoundError):
        await auth_tuna_async.users.unsuspend_user("nonexistent", "admin")

@pytest.mark.asyncio
async def test_search_and_basic_search_users(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test19@example.com",
        username="testuser19",
        password="password123",
        ip_address="127.0.0.1"
    )
    results = await auth_tuna_async.users.search_users(identity="testuser19")
    assert any(u.id == user.id for u in results)
    basic = await auth_tuna_async.users.basic_search_users(identity="testuser19")
    assert any(u["user_id"] == user.id for u in basic)
