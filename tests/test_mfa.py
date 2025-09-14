import pytest
import pyotp

@pytest.mark.asyncio
async def test_setup_and_verify_totp(auth_tuna_async):
    """Test setting up and verifying TOTP for a user."""
    user = await auth_tuna_async.users.create(
        email="test4@example.com",
        username="testuser4",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    recovery_codes = await auth_tuna_async.mfa.verify_and_enable_totp(user, code)
    assert len(recovery_codes) == 10
    updated_user = await auth_tuna_async.users.get_by_id(user.id)
    assert updated_user.mfa_enabled is True