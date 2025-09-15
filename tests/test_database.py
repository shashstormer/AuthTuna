import pytest
from authtuna.core.database import CaseInsensitiveText, JsonType, User, Role, Permission, Session, Token, Base
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
import time
import types


def test_json_type_sqlite():
    engine = create_engine('sqlite:///:memory:')
    class TestModel(Base):
        __tablename__ = 'test_json'
        id = Column(Integer, primary_key=True)
        data = Column(JsonType)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    db.add(TestModel(data={"foo": "bar"}))
    db.commit()
    result = db.query(TestModel).first()
    assert result.data == {"foo": "bar"}

# --- ORM Model Methods (sync logic only, async logic is tested in other files) ---
def test_user_repr_and_flags():
    user = User(id="1", username="testuser", email="test@example.com", is_active=True, email_verified=True, mfa_enabled=False)
    assert user.is_email_verified() is True
    assert user.has_role("admin") is False
    assert user.has_permission("perm") is False
    assert "testuser" in repr(user)

def test_role_and_permission_repr():
    role = Role(id=1, name="admin", description="desc")
    perm = Permission(id=1, name="perm", description="desc")
    assert "admin" in repr(role)
    assert "perm" in repr(perm)

def test_session_expiry_and_repr():
    session = Session(session_id="abc", user_id="1", region="r", device="d", active=True, ctime=time.time(), mtime=time.time(), etime=time.time()+100, e_abs_time=time.time()+100, create_ip="ip", last_ip="ip", random_string="rand", previous_random_strings=[])
    assert session.is_expired() is False
    assert isinstance(session.get_cookie_string(), str)

def test_token_validity_and_repr():
    token = Token(id="tok", purpose="test", user_id="1", ctime=time.time(), etime=time.time()+100, used=False)
    assert token.is_valid() is True
    assert "tok" == token.id

import pytest

@pytest.mark.asyncio
async def test_permission_manager_crud(auth_tuna_async):
    perm, created = await auth_tuna_async.permissions.get_or_create("perm:test", defaults={"description": "desc"})
    assert created is True
    perm2, created2 = await auth_tuna_async.permissions.get_or_create("perm:test")
    assert created2 is False
    assert perm.id == perm2.id
    found = await auth_tuna_async.permissions.get_by_name("perm:test")
    assert found.id == perm.id
    with pytest.raises(ValueError):
        await auth_tuna_async.permissions.create("perm:test")

@pytest.mark.asyncio
async def test_session_manager_crud(auth_tuna_async):
    user = await auth_tuna_async.users.create(email="sess@example.com", username="sessuser", password="pw", ip_address="1.1.1.1")
    session = await auth_tuna_async.sessions.create(user.id, "1.1.1.1", "region", "device")
    found = await auth_tuna_async.sessions.get_by_id(session.session_id)
    assert found.session_id == session.session_id
    all_sessions = await auth_tuna_async.sessions.get_all_for_user(user.id, session.session_id)
    assert any(s.session_id == session.session_id for s in all_sessions)
    await auth_tuna_async.sessions.terminate(session.session_id, "1.1.1.1")
    # Terminate non-existent session (should return False)
    assert not await auth_tuna_async.sessions.terminate("notfound", "1.1.1.1")
    # Terminate all for user (should not error)
    await auth_tuna_async.sessions.terminate_all_for_user(user.id, "1.1.1.1")

@pytest.mark.asyncio
async def test_token_manager_create(auth_tuna_async):
    user = await auth_tuna_async.users.create(email="tok@example.com", username="tokuser", password="pw", ip_address="1.1.1.1")
    token = await auth_tuna_async.tokens.create(user.id, "test-purpose", expiry_seconds=60)
    assert token.purpose == "test-purpose"
    assert token.is_valid()
