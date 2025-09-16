import pytest
import time
from unittest.mock import patch, Mock, AsyncMock
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from authtuna.core.database import (
    Base, CaseInsensitiveText, JsonType, User, Role, Permission, 
    Session, Token, MFAMethod, MFARecoveryCode, SocialAccount, AuditEvent,
    DatabaseManager
)
from authtuna.manager.asynchronous import (
    UserManager, RoleManager, PermissionManager,
    SessionManager, TokenManager, AuditManager
)
from authtuna.core.exceptions import (
    UserAlreadyExistsError, UserNotFoundError, InvalidCredentialsError,
    RoleNotFoundError, PermissionNotFoundError, SessionNotFoundError,
    InvalidTokenError, TokenExpiredError, OperationForbiddenError
)
from authtuna.core.encryption import encryption_utils


@pytest.mark.asyncio
async def test_database_manager_initialization():
    """Test DatabaseManager initialization."""
    db_manager = DatabaseManager()
    assert db_manager is not None
    assert hasattr(db_manager, 'get_db')


@pytest.mark.asyncio
async def test_user_model_methods():
    """Test User model methods."""
    user = User(
        id="test_user_123",
        username="testuser",
        email="test@example.com",
        is_active=True,
        email_verified=True,
        mfa_enabled=False
    )
    
    # Test is_email_verified
    assert user.is_email_verified() is True
    user.email_verified = False
    assert user.is_email_verified() is False
    
    # Test has_role (no roles assigned)
    assert user.has_role("admin") is False
    
    # Test has_permission (no permissions)
    assert user.has_permission("read") is False
    
    # Test repr
    user_repr = repr(user)
    assert "testuser" in user_repr


@pytest.mark.asyncio
async def test_user_with_roles_and_permissions():
    """Test User model with roles and permissions."""
    # Create roles and permissions
    admin_role = Role(id=1, name="admin", description="Administrator")
    read_permission = Permission(id=1, name="read", description="Read access")
    write_permission = Permission(id=2, name="write", description="Write access")
    
    # Assign permission to role
    admin_role.permissions = [read_permission, write_permission]
    
    # Create user with role
    user = User(
        id="admin_user_123",
        username="adminuser",
        email="admin@example.com",
        is_active=True,
        email_verified=True,
        mfa_enabled=False
    )
    user.roles = [admin_role]
    
    # Test has_role
    assert user.has_role("admin") is True
    assert user.has_role("user") is False
    
    # Test has_permission
    assert user.has_permission("read") is True
    assert user.has_permission("write") is True
    assert user.has_permission("delete") is False


@pytest.mark.asyncio
async def test_role_model():
    """Test Role model."""
    role = Role(id=1, name="editor", description="Content Editor")
    
    # Test repr
    role_repr = repr(role)
    assert "editor" in role_repr


@pytest.mark.asyncio
async def test_permission_model():
    """Test Permission model."""
    permission = Permission(id=1, name="delete", description="Delete access")
    
    # Test repr
    perm_repr = repr(permission)
    assert "delete" in perm_repr


@pytest.mark.asyncio
async def test_session_model():
    """Test Session model."""
    current_time = time.time()
    session = Session(
        session_id="session_123",
        user_id="user_123",
        region="US",
        device="Chrome",
        active=True,
        ctime=current_time,
        mtime=current_time,
        etime=current_time + 3600,  # 1 hour from now
        e_abs_time=current_time + 86400,  # 1 day from now
        create_ip="192.168.1.1",
        last_ip="192.168.1.1",
        random_string="random123",
        previous_random_strings=[]
    )
    
    # Test is_expired (not expired)
    assert session.is_expired() is False
    
    # Test is_expired (expired)
    session.etime = current_time - 1  # Expired
    assert session.is_expired() is True
    
    # Test get_cookie_string contains expected claims when decoded
    cookie_string = session.get_cookie_string()
    decoded = encryption_utils.decode_jwt_token(cookie_string)
    assert decoded["session"] == session.session_id
    assert decoded["random_string"] == session.random_string
    assert decoded["user_id"] == session.user_id


@pytest.mark.asyncio
async def test_token_model():
    """Test Token model."""
    current_time = time.time()
    token = Token(
        id="token_123",
        purpose="email_verification",
        user_id="user_123",
        ctime=current_time,
        etime=current_time + 3600,  # 1 hour from now
        used=False
    )
    
    # Test is_valid (valid)
    assert token.is_valid() is True
    
    # Test is_valid (expired)
    token.etime = current_time - 1
    assert token.is_valid() is False
    
    # Test is_valid (used)
    token.etime = current_time + 3600
    token.used = True
    assert token.is_valid() is False


@pytest.mark.asyncio
async def test_mfa_method_model():
    """Test MFAMethod model."""
    mfa_method = MFAMethod(
        id="mfa_123",
        user_id="user_123",
        method_type="totp",
        secret="secret123",
        is_verified=True
    )
    
    assert mfa_method.method_type == "totp"
    assert mfa_method.is_verified is True


@pytest.mark.asyncio
async def test_mfa_recovery_code_model():
    """Test MFARecoveryCode model."""
    recovery_code = MFARecoveryCode(
        id="recovery_123",
        user_id="user_123",
        hashed_code="hashed_code_123",
        is_used=False
    )
    
    assert recovery_code.is_used is False
    assert recovery_code.hashed_code == "hashed_code_123"


@pytest.mark.asyncio
async def test_social_account_model():
    """Test SocialAccount model."""
    social_account = SocialAccount(
        id="social_123",
        user_id="user_123",
        provider="google",
        provider_user_id="google_123",
        access_token="token123",
        extra_data={"email": "user@gmail.com", "name": "User Name", "avatar_url": "https://example.com/avatar.jpg"}
    )
    
    assert social_account.provider == "google"
    assert social_account.provider_user_id == "google_123"
    assert social_account.access_token == "token123"


@pytest.mark.asyncio
async def test_audit_event_model():
    """Test AuditEvent model."""
    current_time = time.time()
    audit_event = AuditEvent(
        id="audit_123",
        user_id="user_123",
        event_type="login",
        ip_address="192.168.1.1",
        details={"success": True},
        timestamp=current_time
    )
    
    assert audit_event.event_type == "login"
    assert audit_event.details == {"success": True}


@pytest.mark.asyncio
async def test_user_manager_create_success(auth_tuna_async):
    """Test UserManager create method success."""
    user_manager = auth_tuna_async.users
    
    user = await user_manager.create(
        email="newuser@example.com",
        username="newuser",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    
    assert user is not None
    assert user.email == "newuser@example.com"
    assert user.username == "newuser"
    assert user.is_active is True


@pytest.mark.asyncio
async def test_user_manager_create_duplicate_email(auth_tuna_async):
    """Test UserManager create method with duplicate email."""
    user_manager = auth_tuna_async.users
    
    # Create first user
    await user_manager.create(
        email="duplicate@example.com",
        username="user1",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    
    # Try to create second user with same email
    with pytest.raises(UserAlreadyExistsError):
        await user_manager.create(
            email="duplicate@example.com",
            username="user2",
            password="ValidPassword123",
            ip_address="127.0.0.1"
        )


@pytest.mark.asyncio
async def test_user_manager_create_duplicate_username(auth_tuna_async):
    """Test UserManager create method with duplicate username."""
    user_manager = auth_tuna_async.users
    
    # Create first user
    await user_manager.create(
        email="user1@example.com",
        username="duplicateuser",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    
    # Try to create second user with same username
    with pytest.raises(UserAlreadyExistsError):
        await user_manager.create(
            email="user2@example.com",
            username="duplicateuser",
            password="ValidPassword123",
            ip_address="127.0.0.1"
        )


@pytest.mark.asyncio
async def test_user_manager_get_by_id_not_found(auth_tuna_async):
    """Test UserManager get_by_id with non-existent user."""
    user_manager = auth_tuna_async.users
    
    user = await user_manager.get_by_id("nonexistent_user_id")
    assert user is None


@pytest.mark.asyncio
async def test_user_manager_get_by_email_not_found(auth_tuna_async):
    """Test UserManager get_by_email with non-existent email."""
    user_manager = auth_tuna_async.users
    
    user = await user_manager.get_by_email("nonexistent@example.com")
    assert user is None


@pytest.mark.asyncio
async def test_user_manager_get_by_username_not_found(auth_tuna_async):
    """Test UserManager get_by_username with non-existent username."""
    user_manager = auth_tuna_async.users
    
    user = await user_manager.get_by_username("nonexistentuser")
    assert user is None


@pytest.mark.asyncio
async def test_user_manager_update_not_found(auth_tuna_async):
    """Test UserManager update with non-existent user."""
    user_manager = auth_tuna_async.users
    
    with pytest.raises(UserNotFoundError):
        await user_manager.update("nonexistent_user_id", {"username": "newname"})


@pytest.mark.asyncio
async def test_user_manager_delete_not_found(auth_tuna_async):
    """Test UserManager delete with non-existent user."""
    user_manager = auth_tuna_async.users
    
    with pytest.raises(UserNotFoundError):
        await user_manager.delete("nonexistent_user_id")


@pytest.mark.asyncio
async def test_user_manager_set_password_not_found(auth_tuna_async):
    """Test UserManager set_password with non-existent user."""
    user_manager = auth_tuna_async.users
    
    with pytest.raises(UserNotFoundError):
        await user_manager.set_password("nonexistent_user_id", "newpassword", "127.0.0.1")


@pytest.mark.asyncio
async def test_login_invalid_credentials(auth_tuna_async):
    """Test login with invalid credentials via service layer."""
    # Create a user
    await auth_tuna_async.users.create(
        email="auth@example.com",
        username="authuser",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    # Wrong password should raise
    with pytest.raises(InvalidCredentialsError):
        await auth_tuna_async.login("authuser", "wrongpassword", "127.0.0.1", "Region", "Device")


@pytest.mark.asyncio
async def test_login_user_not_found(auth_tuna_async):
    with pytest.raises(InvalidCredentialsError):
        await auth_tuna_async.login("nonexistentuser", "password", "127.0.0.1", "Region", "Device")


@pytest.mark.asyncio
async def test_login_inactive_user(auth_tuna_async):
    user = await auth_tuna_async.users.create(
        email="inactive@example.com",
        username="inactiveuser",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    user.is_active = False
    async with auth_tuna_async.db_manager.get_db() as db:
        db.add(user)
        await db.commit()
    with pytest.raises(OperationForbiddenError):
        await auth_tuna_async.login("inactiveuser", "ValidPassword123", "127.0.0.1", "Region", "Device")


@pytest.mark.asyncio
async def test_role_manager_get_by_name_not_found(auth_tuna_async):
    """Test RoleManager get_by_name with non-existent role."""
    role_manager = auth_tuna_async.roles
    
    role = await role_manager.get_by_name("nonexistent_role")
    assert role is None


@pytest.mark.asyncio
async def test_role_manager_get_by_id_not_found(auth_tuna_async):
    """Test RoleManager get_by_id with non-existent role."""
    role_manager = auth_tuna_async.roles
    
    role = await role_manager.get_by_id(99999)
    assert role is None


@pytest.mark.asyncio
async def test_permission_manager_get_by_name_not_found(auth_tuna_async):
    """Test PermissionManager get_by_name with non-existent permission."""
    permission_manager = auth_tuna_async.permissions
    
    permission = await permission_manager.get_by_name("nonexistent_permission")
    assert permission is None


@pytest.mark.asyncio
async def test_json_type_serialization():
    """Test JsonType serialization and deserialization."""
    engine = create_engine('sqlite:///:memory:')
    
    class TestModel(Base):
        __tablename__ = 'test_json_model'
        id = Column(Integer, primary_key=True)
        data = Column(JsonType)
    
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    # Test with dictionary
    test_data = {"key": "value", "nested": {"inner": "data"}}
    db.add(TestModel(data=test_data))
    db.commit()
    
    result = db.query(TestModel).first()
    assert result.data == test_data
    
    # Test with list
    test_list = [1, 2, 3, {"nested": "list"}]
    db.add(TestModel(data=test_list))
    db.commit()
    
    result = db.query(TestModel).filter(TestModel.data == test_list).first()
    assert result is not None
    assert result.data == test_list
    
    db.close()


@pytest.mark.asyncio
async def test_case_insensitive_text():
    """Test CaseInsensitiveText type."""
    engine = create_engine('sqlite:///:memory:')
    
    class TestModel(Base):
        __tablename__ = 'test_case_model'
        id = Column(Integer, primary_key=True)
        name = Column(CaseInsensitiveText(50))
    
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    # Test case insensitive storage and retrieval
    db.add(TestModel(name="TestName"))
    db.commit()
    
    # Retrieve and assert value stored and compare case-insensitively at Python level
    result = db.query(TestModel).first()
    assert result is not None
    assert result.name == "TestName"
    assert result.name.lower() == "testname"
    assert result.name.upper() == "TESTNAME"
    
    db.close()
