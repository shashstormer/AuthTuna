import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from authtuna.manager.asynchronous import UserManager, AuthTunaAsync
from authtuna.core.exceptions import UserAlreadyExistsError, UserNotFoundError, InvalidCredentialsError, OperationForbiddenError, InvalidTokenError
from authtuna.core.database import User
from authtuna.core.config import settings

@pytest.fixture
def user_manager():
    """Provides a UserManager instance with a correctly mocked DB manager."""
    db_manager = MagicMock()

    session_mock = AsyncMock()

    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = session_mock

    db_manager.get_db.return_value = context_manager
    db_manager.log_audit_event = AsyncMock()

    return UserManager(db_manager), session_mock

@pytest.mark.asyncio
async def test_user_manager_create_success(user_manager):
    """
    Tests successful user creation.
    """
    manager, session_mock = user_manager

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = None
    session_mock.execute = AsyncMock(return_value=mock_result)

    with patch('authtuna.manager.asynchronous.is_email_valid', new=AsyncMock()), \
         patch('authtuna.core.database.User.set_password', new=AsyncMock()):

        user = await manager.create("test@example.com", "testuser", "password")

        assert user.email == "test@example.com"
        assert user.username == "testuser"
        session_mock.add.assert_called_once()
        manager._db_manager.log_audit_event.assert_called_once()
        session_mock.commit.assert_called_once()

@pytest.mark.asyncio
async def test_user_manager_create_user_exists(user_manager):
    """
    Tests that creating a user who already exists raises UserAlreadyExistsError.
    """
    manager, session_mock = user_manager

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = MagicMock()
    session_mock.execute = AsyncMock(return_value=mock_result)

    with patch('authtuna.manager.asynchronous.is_email_valid', new=AsyncMock()):
        with pytest.raises(UserAlreadyExistsError):
            await manager.create("test@example.com", "testuser", "password")

@pytest.mark.asyncio
async def test_user_manager_delete_success(user_manager):
    """
    Tests successful user deletion.
    """
    manager, session_mock = user_manager
    mock_user = MagicMock()
    mock_user.id = "test_user_id"
    mock_user.email = "test@example.com"

    table_mock = MagicMock()

    id_col = MagicMock()
    id_col.name = 'id'
    email_col = MagicMock()
    email_col.name = 'email'

    table_mock.columns = [id_col, email_col]
    mock_user.__table__ = table_mock

    session_mock.get.return_value = mock_user

    await manager.delete("test_user_id")

    session_mock.add.assert_called_once()
    session_mock.delete.assert_called_once_with(mock_user)
    manager._db_manager.log_audit_event.assert_called_once()
    session_mock.commit.assert_called_once()

@pytest.mark.asyncio
async def test_user_manager_delete_not_found(user_manager):
    """
    Tests that deleting a non-existent user raises UserNotFoundError.
    """
    manager, session_mock = user_manager
    session_mock.get.return_value = None

    with pytest.raises(UserNotFoundError):
        await manager.delete("test_user_id")

@pytest.mark.asyncio
async def test_signup_success():
    """
    Tests successful user signup.
    """
    db_manager = AsyncMock()
    auth_tuna = AuthTunaAsync(db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.id = "new_user_id"

    with patch.object(auth_tuna.users, 'create', new=AsyncMock(return_value=mock_user)) as mock_create, \
         patch.object(auth_tuna.roles, 'assign_to_user', new=AsyncMock()) as mock_assign, \
         patch.object(auth_tuna.tokens, 'create', new=AsyncMock()) as mock_token_create:

        user, token = await auth_tuna.signup("testuser", "test@example.com", "password", "127.0.0.1")

        mock_create.assert_called_once()
        mock_assign.assert_called_once_with("new_user_id", "User", assigner_id="system", scope="global")
        if settings.EMAIL_ENABLED:
            mock_token_create.assert_called_once()
        else:
            mock_token_create.assert_not_called()
        assert user == mock_user

@pytest.mark.asyncio
async def test_login_success(user_manager):
    """
    Tests successful user login.
    """
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.is_active = True
    mock_user.mfa_enabled = False

    async def check_password_true(*args, **kwargs):
        return True

    mock_user.check_password = check_password_true

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_user
    session_mock.execute = AsyncMock(return_value=mock_result)
    # Mock scalar to return 0 for rate limit checks
    session_mock.scalar = AsyncMock(return_value=0)

    with patch('authtuna.manager.asynchronous.select'), \
         patch.object(auth_tuna.sessions, 'create', new=AsyncMock(return_value=MagicMock())) as mock_session_create:

        user, session = await auth_tuna.login("testuser", "password", "127.0.0.1", "test-region", "test-device")
        assert user == mock_user
        mock_session_create.assert_called_once()

@pytest.mark.asyncio
async def test_login_invalid_credentials(user_manager):
    """
    Tests login with invalid credentials.
    """
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = None
    session_mock.execute = AsyncMock(return_value=mock_result)
    # Mock scalar to return 0 for rate limit checks
    session_mock.scalar = AsyncMock(return_value=0)

    with patch('authtuna.manager.asynchronous.select'):
        with pytest.raises(InvalidCredentialsError):
            await auth_tuna.login("testuser", "password", "127.0.0.1", "test-region", "test-device")

@pytest.mark.asyncio
async def test_user_manager_suspend_and_unsuspend_user(user_manager):
    """
    Tests suspending and unsuspending a user.
    """
    manager, session_mock = user_manager
    mock_user = MagicMock(spec=User)
    mock_user.is_active = True
    session_mock.get.return_value = mock_user

    suspended_user = await manager.suspend_user("test_user_id", "admin_id")
    assert not suspended_user.is_active
    manager._db_manager.log_audit_event.assert_called_with("test_user_id", "USER_SUSPENDED", "system", {"by": "admin_id", "reason": "No reason provided."}, db=session_mock)

    unsuspended_user = await manager.unsuspend_user("test_user_id", "admin_id")
    assert unsuspended_user.is_active
    manager._db_manager.log_audit_event.assert_called_with("test_user_id", "USER_UNSUSPENDED", "system", {"by": "admin_id", "reason": "No reason provided."}, db=session_mock)

@pytest.mark.asyncio
async def test_login_suspended_user(user_manager):
    """
    Tests that a suspended user cannot log in.
    """
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.is_active = False # User is suspended

    async def check_password_true(*args, **kwargs):
        return True

    mock_user.check_password = check_password_true

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_user
    session_mock.execute = AsyncMock(return_value=mock_result)
    # Mock scalar to return 0 for rate limit checks
    session_mock.scalar = AsyncMock(return_value=0)

    with patch('authtuna.manager.asynchronous.select'):
        with pytest.raises(OperationForbiddenError):
            await auth_tuna.login("testuser", "password", "127.0.0.1", "test-region", "test-device")

@pytest.mark.asyncio
async def test_change_password_success(user_manager):
    """
    Tests successful password change.
    """
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.id = "user1"

    async def check_password(password, *args, **kwargs):
        return password == "old_password"

    mock_user.check_password = check_password
    mock_user.set_password = AsyncMock()

    session_mock.get.return_value = mock_user

    with patch.object(auth_tuna.sessions, 'terminate_all_for_user', new=AsyncMock()) as mock_terminate:
        await auth_tuna.change_password(mock_user, "old_password", "new_password", "127.0.0.1", "session1")

        mock_user.set_password.assert_called_once_with("new_password", "127.0.0.1", db_manager_custom=auth_tuna.db_manager, db=session_mock)
        mock_terminate.assert_called_once_with("user1", "127.0.0.1", except_session_id="session1", db=session_mock)

@pytest.mark.asyncio
async def test_change_password_invalid_current_password(user_manager):
    """
    Tests that changing password fails with an invalid current password.
    """
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)

    async def check_password(password, *args, **kwargs):
        return password == "old_password"

    mock_user.check_password = check_password
    session_mock.get.return_value = mock_user

    with pytest.raises(InvalidCredentialsError):
        await auth_tuna.change_password(mock_user, "wrong_password", "new_password", "127.0.0.1", "session1")

@pytest.mark.asyncio
async def test_reset_password_success(user_manager):
    manager, _ = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.set_password = AsyncMock()

    with patch.object(auth_tuna.tokens, 'validate', new=AsyncMock(return_value=mock_user)) as mock_validate:
        user = await auth_tuna.reset_password("valid_token", "new_password", "127.0.0.1")

        mock_validate.assert_called_once()
        mock_user.set_password.assert_called_once()
        assert user == mock_user

@pytest.mark.asyncio
async def test_verify_email_success(user_manager):
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mock_user.email_verified = False

    # Mock scalar to return 0 for rate limit checks
    session_mock.scalar = AsyncMock(return_value=0)

    with patch.object(auth_tuna.tokens, 'validate', new=AsyncMock(return_value=mock_user)) as mock_validate:
        user = await auth_tuna.verify_email("valid_token", "127.0.0.1")

        mock_validate.assert_called_once()
        assert user.email_verified is True

@pytest.mark.asyncio
async def test_request_password_reset_success(user_manager):
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_result = MagicMock()
    mock_result.scalar.return_value = 0
    session_mock.execute = AsyncMock(return_value=mock_result)

    with patch.object(auth_tuna.users, 'get_by_email', new=AsyncMock(return_value=MagicMock())) as mock_get_by_email, \
         patch.object(auth_tuna.tokens, 'create', new=AsyncMock()) as mock_create:

        await auth_tuna.request_password_reset("test@example.com")

        mock_get_by_email.assert_called_once()
        mock_create.assert_called_once()

@pytest.mark.asyncio
async def test_validate_mfa_login_invalid_code(user_manager):
    manager, session_mock = user_manager
    auth_tuna = AuthTunaAsync(manager._db_manager)

    mock_user = MagicMock(spec=User)
    mfa_method = MagicMock(method_type='totp', secret='secret')
    mock_user_with_mfa = MagicMock(spec=User)
    mock_user_with_mfa.mfa_methods = [mfa_method]

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_user_with_mfa
    session_mock.execute = AsyncMock(return_value=mock_result)

    with patch.object(auth_tuna.tokens, 'validate', new=AsyncMock(return_value=mock_user)), \
         patch('pyotp.TOTP.verify', return_value=False), \
         patch.object(auth_tuna.mfa, 'verify_recovery_code', new=AsyncMock(return_value=False)):

        with pytest.raises(InvalidTokenError):
            await auth_tuna.validate_mfa_login("mfa_token", "wrong_code", "127.0.0.1", {})
