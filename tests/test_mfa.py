import pytest
import pyotp
from authtuna.core.exceptions import OperationForbiddenError, InvalidTokenError

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

@pytest.mark.asyncio
async def test_setup_totp_when_already_enabled(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test5@example.com",
        username="testuser5",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    await auth_tuna_async.mfa.verify_and_enable_totp(user, code)
    user = await auth_tuna_async.users.get_by_id(user.id)
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")

@pytest.mark.asyncio
async def test_verify_totp_with_invalid_code(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test6@example.com",
        username="testuser6",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    with pytest.raises(InvalidTokenError):
        await auth_tuna_async.mfa.verify_and_enable_totp(user, "000000")

@pytest.mark.asyncio
async def test_verify_totp_when_already_enabled(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test7@example.com",
        username="testuser7",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    await auth_tuna_async.mfa.verify_and_enable_totp(user, code)
    user = await auth_tuna_async.users.get_by_id(user.id)
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.mfa.verify_and_enable_totp(user, code)

@pytest.mark.asyncio
async def test_recovery_code_verification(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test8@example.com",
        username="testuser8",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    recovery_codes = await auth_tuna_async.mfa.verify_and_enable_totp(user, code)
    # Valid code
    async with auth_tuna_async.db_manager.get_db() as db:
        assert await auth_tuna_async.mfa.verify_recovery_code(user, recovery_codes[0], db) is True
        # Reuse same code (should now be used)
        assert await auth_tuna_async.mfa.verify_recovery_code(user, recovery_codes[0], db) is False
        # Invalid code
        assert await auth_tuna_async.mfa.verify_recovery_code(user, "INVALID-CODE", db) is False

@pytest.mark.asyncio
async def test_disable_mfa(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="test9@example.com",
        username="testuser9",
        password="password123",
        ip_address="127.0.0.1"
    )
    secret, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    await auth_tuna_async.mfa.verify_and_enable_totp(user, code)
    await auth_tuna_async.mfa.disable_mfa(user)
    user = await auth_tuna_async.users.get_by_id(user.id)
    assert user.mfa_enabled is False
    # Should be able to set up TOTP again
    secret2, _ = await auth_tuna_async.mfa.setup_totp(user, issuer_name="TestApp")
    assert secret2
