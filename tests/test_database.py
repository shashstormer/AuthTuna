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

