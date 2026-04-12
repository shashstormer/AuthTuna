import pytest
import time
from sqlalchemy import select
from authtuna.core.config import settings
from authtuna.core.database import User, EncryptionKey, AuditEvent, db_manager
from authtuna.core.encryption import encryption_utils

@pytest.fixture
async def gdpr_enabled(monkeypatch):
    monkeypatch.setattr(settings, "PII_ENCRYPTION_ENABLED", True)
    # PII_HMAC_KEY must be a SecretStr if using newer pydantic, but here it might be just str in env
    from pydantic import SecretStr
    monkeypatch.setattr(settings, "PII_HMAC_KEY", SecretStr("test-hmac-key"))
    monkeypatch.setattr(settings, "ENCRYPT_AUDIT_IP", True)
    yield

@pytest.mark.asyncio
async def test_user_creation_with_encryption(gdpr_enabled, auth_tuna_async, dbsession):
    email = "gdpr_test@example.com"
    username = "gdpr_user"
    user = await auth_tuna_async.users.create(email=email, username=username, password="password123")
    
    # Verify User fields
    assert user.email != email  # Should be a hash
    assert len(user.email) == 64  # SHA256 hex digest
    assert user.email_encrypted is not None
    assert user.email_key_id is not None
    
    # Verify encryption key exists
    from authtuna.core.database import EncryptionKey
    stmt = select(EncryptionKey).where(EncryptionKey.id == user.email_key_id)
    key_obj = (await dbsession.execute(stmt)).scalar_one()
    assert key_obj is not None
    assert key_obj.deleted_at is None
    
    # Verify get_email()
    decrypted_email = user.get_email()
    assert decrypted_email == email
    
    # Verify lookup by email
    found_user = await auth_tuna_async.users.get_by_email(email)
    assert found_user is not None
    assert found_user.id == user.id

@pytest.mark.asyncio
async def test_crypto_shredding(gdpr_enabled, auth_tuna_async, dbsession):
    email = "shred_test@example.com"
    user = await auth_tuna_async.users.create(email=email, username="shred_user")
    
    user_id = user.id
    # Verify key exists
    assert user.encryption_key is not None
    
    # Erase user
    success = await auth_tuna_async.users.erase_user(user_id)
    assert success is True
    
    # Clear session and refetch
    dbsession.expire_all()
    stmt = select(User).where(User.id == user_id)
    user = (await dbsession.execute(stmt)).scalar_one()
    
    assert user.email_encrypted is None
    assert "erased_" in user.email
    assert user.encryption_key.deleted_at is not None
    assert "SHREDDED_" in user.encryption_key.key_ciphertext
    
    # Verify get_email() returns anonymized email
    assert user.get_email() == f"erased_{user.id}@erased.invalid"

@pytest.mark.asyncio
async def test_audit_log_ip_encryption(gdpr_enabled, auth_tuna_async, dbsession):
    email = "audit_test@example.com"
    ip = "192.168.1.100"
    user = await auth_tuna_async.users.create(email=email, username="audit_user", ip_address=ip)
    
    # Find the USER_CREATED audit event
    stmt = select(AuditEvent).where(AuditEvent.user_id == user.id, AuditEvent.event_type == "USER_CREATED")
    event = (await dbsession.execute(stmt)).scalar_one()
    
    # Plain IP should be masked
    assert event.ip_address == "192.168.X.X"
    assert event.ip_address_encrypted is not None
    
    # Decrypt and verify
    raw_key = encryption_utils.unwrap_user_key(user.encryption_key.key_ciphertext)
    decrypted_ip = encryption_utils.decrypt_pii(event.ip_address_encrypted, raw_key)
    assert decrypted_ip == ip

@pytest.mark.asyncio
async def test_search_users_with_encryption(gdpr_enabled, auth_tuna_async):
    email = "search_test@example.com"
    await auth_tuna_async.users.create(email=email, username="search_user")
    
    # Search by exact email
    results = await auth_tuna_async.users.search_users(identity=email)
    assert len(results) == 1
    assert results[0].username == "search_user"
    
    # Search by part of email (should fail as it's hashed)
    results = await auth_tuna_async.users.search_users(identity="search_test")
    assert len(results) == 0
    
    # Search by username (should still work)
    results = await auth_tuna_async.users.search_users(identity="search_user")
    assert len(results) == 1
