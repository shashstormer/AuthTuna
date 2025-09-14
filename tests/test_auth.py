import pytest
from authtuna.core.exceptions import InvalidCredentialsError

@pytest.mark.asyncio
async def test_signup_and_login(auth_tuna_async):
    """Test user signup and subsequent login."""
    # Signup a new user
    user, _ = await auth_tuna_async.signup(
        username="test_auth_user",
        email="test_auth@example.com",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    assert user is not None
    assert user.email == "test_auth@example.com"

    # Login with correct credentials
    loggedInUser, session = await auth_tuna_async.login(
        username_or_email="test_auth_user",
        password="ValidPassword123",
        ip_address="127.0.0.1",
        region="Test Region",
        device="Test Device"
    )
    assert loggedInUser is not None
    assert session is not None
    assert loggedInUser.id == user.id

    # Attempt login with incorrect password
    with pytest.raises(InvalidCredentialsError):
        await auth_tuna_async.login(
            username_or_email="test_auth_user",
            password="WrongPassword",
            ip_address="127.0.0.1",
            region="Test Region",
            device="Test Device"
        )