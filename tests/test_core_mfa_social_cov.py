import pytest
from unittest.mock import patch, AsyncMock, Mock
from sqlalchemy import select

from authtuna.core.mfa import MFAManager
from authtuna.core.social import get_social_provider, oauth
from authtuna.core.database import User, MFAMethod, MFARecoveryCode
from authtuna.core.exceptions import OperationForbiddenError, InvalidTokenError


@pytest.mark.asyncio
async def test_core_mfa_setup_when_already_enabled(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email='coremfa@example.com', username='coremfa', password='ValidPassword123', ip_address='127.0.0.1'
    )
    user.mfa_enabled = True
    mfa = MFAManager(auth_tuna_async.db_manager)
    with pytest.raises(OperationForbiddenError):
        await mfa.setup_totp(user, 'App')


@pytest.mark.asyncio
async def test_core_mfa_verify_without_setup(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email='novsetup@example.com', username='novsetup', password='ValidPassword123', ip_address='127.0.0.1'
    )
    mfa = MFAManager(auth_tuna_async.db_manager)
    with pytest.raises(InvalidTokenError):
        await mfa.verify_and_enable_totp(user, '000000')


@pytest.mark.asyncio
async def test_core_mfa_verify_with_wrong_code(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email='wrongcode@example.com', username='wcode', password='ValidPassword123', ip_address='127.0.0.1'
    )
    mfa = MFAManager(auth_tuna_async.db_manager)
    secret, _ = await mfa.setup_totp(user, 'App')
    # Wrong code
    with pytest.raises(InvalidTokenError):
        await mfa.verify_and_enable_totp(user, '000000')


@pytest.mark.asyncio
async def test_core_mfa_reuse_verification(auth_tuna_async):
    import pyotp
    user = await auth_tuna_async.users.create(
        email='reuse@example.com', username='reuse', password='ValidPassword123', ip_address='127.0.0.1'
    )
    mfa = MFAManager(auth_tuna_async.db_manager)
    secret, _ = await mfa.setup_totp(user, 'App')
    code = pyotp.TOTP(secret).now()
    await mfa.verify_and_enable_totp(user, code)
    with pytest.raises(OperationForbiddenError):
        await mfa.verify_and_enable_totp(user, code)


@pytest.mark.asyncio
async def test_core_mfa_verify_recovery_code_paths(auth_tuna_async):
    # Ensure both branches (with provided db and without) are exercised
    user = await auth_tuna_async.users.create(
        email='recc@example.com', username='recc', password='ValidPassword123', ip_address='127.0.0.1'
    )
    mfa = MFAManager(auth_tuna_async.db_manager)
    secret, _ = await mfa.setup_totp(user, 'App')
    import pyotp
    code = pyotp.TOTP(secret).now()
    codes = await mfa.verify_and_enable_totp(user, code)

    # With provided db
    async with auth_tuna_async.db_manager.get_db() as db:
        ok = await mfa.verify_recovery_code(user, codes[0], db)
        assert ok is True

    # Without provided db (uses context manager)
    ok2 = await mfa.verify_recovery_code(user, 'INVALID-CODE', None)
    assert ok2 is False


def test_core_social_get_provider_valid_and_invalid():
    # oauth registry exists; providers may or may not be registered depending on env
    google = get_social_provider('google')
    github = get_social_provider('github')
    assert google is None or hasattr(google, 'authorize_redirect')
    assert github is None or hasattr(github, 'authorize_redirect')
    # Unsupported provider
    assert get_social_provider('notreal') is None


def test_core_social_oauth_registry_accessible():
    assert hasattr(oauth, '_registry')
    assert isinstance(oauth._registry, dict)
