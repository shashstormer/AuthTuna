import json
import time
from sqlalchemy import create_engine, Column, event, Table, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.types import TypeDecorator, TEXT, String, Text, Boolean, Integer, Float
from sqlalchemy.engine import Engine
from authtuna.core.encryption import encryption_utils
from sqlalchemy.dialects.postgresql import CITEXT, JSONB
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authtuna.core.config import settings
from contextlib import contextmanager

Base = declarative_base()
engine = create_engine(settings.DEFAULT_DATABASE_URI,
                       connect_args={'check_same_thread': False} if 'sqlite' in settings.DEFAULT_DATABASE_URI else {})

if engine.dialect.name == 'sqlite':
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Enforces foreign key constraints and case-insensitive LIKE for SQLite."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA case_sensitive_like=OFF")
        cursor.close()


class CaseInsensitiveText(TypeDecorator):
    """
    A case-insensitive Text type that uses CITEXT on PostgreSQL and
    a case-insensitive collation on SQLite, falling back to regular Text.
    """
    impl = TEXT
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(CITEXT())
        elif dialect.name == 'sqlite':
            return dialect.type_descriptor(String)
        else:
            return dialect.type_descriptor(String)


class JsonType(TypeDecorator):
    """
    Stores a Python dict as JSON. Uses the native JSONB type on PostgreSQL
    for efficiency, and a regular TEXT field on other databases.
    """
    impl = TEXT

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(Text)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value
        else:
            return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == 'postgresql':
            return value
        else:
            if isinstance(value, str):
                return json.loads(value)
            return value


user_roles_association = Table(
    'user_roles', Base.metadata,
    Column('user_id', String(64), ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('given_by_id', String(64), ForeignKey('users.id'), nullable=False),
    Column('given_at', Float, nullable=False, default=time.time),
)

role_permissions_association = Table(
    'role_permissions', Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('added_by_id', String(64), ForeignKey('users.id'), nullable=True),
    Column('added_at', Float, nullable=False, default=time.time),
)


class User(Base):
    """
    Represents a user in the database.
    Maps to the 'users' table.
    """
    __tablename__ = 'users'

    id = Column(String(64), primary_key=True, index=True)
    username = Column(CaseInsensitiveText(80, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                      unique=True, nullable=False, index=True)
    email = Column(CaseInsensitiveText(120, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                   unique=True, nullable=False, index=True)

    password_hash = Column(String(256), nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    requires_password_reset = Column(Boolean, default=False, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)

    created_at = Column(Float, nullable=False, default=time.time)
    last_login = Column(Float, nullable=False, default=time.time)

    # Relationships
    roles = relationship(
        "Role",
        secondary=user_roles_association,
        back_populates="users",
        lazy="joined",
        primaryjoin=lambda: User.id == user_roles_association.c.user_id,
        secondaryjoin=lambda: Role.id == user_roles_association.c.role_id,
    )

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan", foreign_keys="Token.user_id")
    social_accounts = relationship("SocialAccount", back_populates="user", cascade="all, delete-orphan")
    mfa_methods = relationship("MFAMethod", back_populates="user", cascade="all, delete-orphan")
    mfa_recovery_codes = relationship("MFARecoveryCode", back_populates="user", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password, ip: str, db_manager_custom=None):
        """Sets the user's password hash."""
        db_manager_to_use = db_manager_custom or db_manager
        old_hash = self.password_hash
        self.password_hash = encryption_utils.hash_password(password)
        db_manager_to_use.log_audit_event(
            self.id, "PASSWORD_CHANGED", ip,
            {"had_old_password": bool(old_hash)}
        )

    def check_password(self, password, ip: str, db_manager_custom=None):
        """Checks if the given password matches the user's password hash."""
        db_manager_to_use = db_manager_custom or db_manager
        if self.requires_password_reset:
            db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "password_reset_required"})
            return False
        if not self.email_verified:
            db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "email_not_verified"})
            return None
        if self.password_hash:
            if encryption_utils.verify_password(password, self.password_hash):
                db_manager_to_use.log_audit_event(self.id, "LOGIN_SUCCESS", ip)
                return True
            else:
                db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "incorrect_password"})
                return False
        db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "no_password_set"})
        return False

    def is_email_verified(self):
        return self.email_verified

    def has_role(self, role_name):
        """Checks if the user has a role with the given name."""
        return any(role.name == role_name for role in self.roles)

    def has_permission(self, permission_name):
        """Checks if a user has a permission through any of their roles."""
        for role in self.roles:
            if any(permission.name == permission_name for permission in role.permissions):
                return True
        return False

    def __repr__(self):
        return f"<User {self.username}>"


class Role(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
    system = Column(Boolean, default=False, nullable=False)

    users = relationship(
        "User",
        secondary=user_roles_association,
        back_populates="roles",
        primaryjoin=lambda: Role.id == user_roles_association.c.role_id,
        secondaryjoin=lambda: User.id == user_roles_association.c.user_id,
    )
    permissions = relationship("Permission", secondary=role_permissions_association, back_populates="roles",
                               lazy="joined")

    def __repr__(self):
        return f"<Role {self.name}>"


class Permission(Base):
    __tablename__ = 'permissions'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
    system = Column(Boolean, default=False, nullable=False)

    roles = relationship("Role", secondary=role_permissions_association, back_populates="permissions")

    def __repr__(self):
        return f"<Permission {self.name}>"


class Session(Base):
    """
    Represents an active user session.
    """
    __tablename__ = 'sessions'

    session_id = Column(String(32), primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    region = Column(String(255))
    device = Column(String(255))
    active = Column(Boolean, default=True, nullable=False)
    ctime = Column(Float, nullable=False, default=time.time)
    mtime = Column(Float, nullable=False, default=time.time, onupdate=time.time)
    etime = Column(Float, nullable=False, default=lambda: time.time() + settings.SESSION_LIFETIME_SECONDS,
                   onupdate=lambda: time.time() + settings.SESSION_LIFETIME_SECONDS)
    e_abs_time = Column(Float, nullable=False, default=lambda: time.time() + settings.SESSION_ABSOLUTE_LIFETIME_SECONDS)
    create_ip = Column(String(45))
    last_ip = Column(String(45))
    user = relationship('User', back_populates='sessions')
    random_string = Column(String(255), nullable=False, default=encryption_utils.gen_random_string,
                           onupdate=encryption_utils.gen_random_string)  # VV-IMP: This minimizes session hijack risks.

    def __repr__(self):
        return f'<Session {self.session_id} for User {self.user_id}>'

    def is_expired(self):
        return time.time() > self.etime or time.time() > self.e_abs_time

    def is_valid(self, region: str = "", device: str = "", random_string: str = ""):
        if self.active and not self.is_expired():
            if self.region == region:
                pass
            else:
                db_manager.log_audit_event(
                    self.user_id, "SESSION_INVALIDATED", self.last_ip,
                    {"reason": "region_mismatch"}
                )
                self.terminate(self.last_ip)
                return False
            if self.device == device:
                pass
            else:
                db_manager.log_audit_event(self.user_id, "SESSION_INVALIDATED", self.last_ip,
                                           {"reason": "device_mismatch"})
                self.terminate(self.last_ip)
                return False
            if self.random_string == random_string:
                return True
            else:
                db_manager.log_audit_event(
                    self.user_id, "SESSION_INVALIDATED", self.last_ip,
                    {"reason": "random_string_mismatch"}
                )
                self.terminate(self.last_ip)
        return False

    def update_last_ip(self, ip: str, db_manager_custom=None):
        db_manager_to_use = db_manager_custom or db_manager
        old_ip = self.last_ip
        self.last_ip = ip
        self.mtime = time.time()
        if old_ip != ip:
            db_manager_to_use.log_audit_event(
                self.user_id, "SESSION_IP_UPDATED", ip,
                {"old_ip": old_ip, "new_ip": ip}
            )

    def get_random_string(self):
        return self.random_string

    def get_user_id(self):
        return self.user_id

    def update_random_string(self):
        self.random_string = encryption_utils.gen_random_string()
        self.mtime = time.time()
        return self.random_string

    def terminate(self, ip: str, db_manager_custom=None):
        db_manager_to_use = db_manager_custom or db_manager
        self.active = False
        db_manager_to_use.log_audit_event(
            self.user_id, "SESSION_TERMINATED", ip,
            {"session_id": self.session_id}
        )

    def get_cookie_string(self):
        cookie_data = {
            'session': self.session_id,
            'e_abs_time': self.e_abs_time,
            'random_string': self.random_string,
            'user_id': self.user_id,
            'database_checked': time.time(),
        }
        return encryption_utils.create_jwt_token(cookie_data)


class Token(Base):
    __tablename__ = 'tokens'

    id = Column(String(64), primary_key=True)
    purpose = Column(String(50), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)

    ctime = Column(Float, nullable=False, default=time.time)
    etime = Column(Float, nullable=False, default=lambda: time.time() + settings.TOKENS_EXPIRY_SECONDS)
    used = Column(Boolean, default=False, nullable=False)

    new_gen_id = Column(String(64), ForeignKey('tokens.id'), nullable=True)

    user = relationship("User", back_populates="tokens", foreign_keys=[user_id])
    new_generation = relationship("Token", remote_side=[id], backref="previous_generation", uselist=False)

    def is_valid(self):
        return self.used is False and self.etime > time.time()

    def mark_used(self, ip: str, db_manager_custom=None):
        db_manager_to_use = db_manager_custom or db_manager
        self.used = True
        db_manager_to_use.log_audit_event(
            self.user_id, "TOKEN_USED", ip,
            {"token_id": self.id, "purpose": self.purpose}
        )

    def __repr__(self):
        return f"<Token {self.id} for {self.purpose}>"


class SocialAccount(Base, OAuth2ClientMixin):
    """
    Represents a link between a user and an external OAuth provider.
    Now integrates with Authlib for a seamless OAuth client experience.
    """
    __tablename__ = 'social_accounts'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    extra_data = Column(JsonType, nullable=True)
    created_at = Column(Float, nullable=False, default=time.time)
    last_used_at = Column(Float, nullable=False, default=time.time)

    # Authlib Mixin required columns
    provider = Column(String(50), nullable=False, index=True)
    provider_user_id = Column(String(255), nullable=False, index=True)
    token_type = Column(String(40), nullable=False, default="bearer")
    access_token = Column(String(1200), nullable=False)
    refresh_token = Column(String(1200))
    expires_at = Column(Integer, nullable=False)

    user = relationship('User', back_populates='social_accounts')

    def __repr__(self):
        return f'<SocialAccount {self.provider}:{self.provider_user_id} for User {self.user_id}>'


class MFAMethod(Base):
    """
    Stores a configured MFA method for a user (e.g., TOTP authenticator app).
    """
    __tablename__ = 'mfa_methods'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)

    method_type = Column(String(20), nullable=False)
    secret = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False, nullable=False)

    user = relationship('User', back_populates='mfa_methods')

    def __repr__(self):
        return f'<MFAMethod {self.method_type} for User {self.user_id}>'


class MFARecoveryCode(Base):
    """
    Stores a single-use MFA recovery code.
    """
    __tablename__ = 'mfa_recovery_codes'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)

    hashed_code = Column(String(256), nullable=False, unique=True)
    is_used = Column(Boolean, default=False, nullable=False)
    actived_at = Column(Float, nullable=True)
    active = Column(Boolean, default=False, nullable=False)
    user = relationship('User', back_populates='mfa_recovery_codes')

    def __repr__(self):
        return f'<MFARecoveryCode for User {self.user_id}>'


class DeletedUser(Base):
    """
    Stores information about users marked for deletion to manage a staged cleanup process.
    """
    __tablename__ = 'deleted_users'

    user_id = Column(String(64), primary_key=True)
    email = Column(String(255), nullable=False)

    data = Column(JsonType, nullable=True)

    initiated_at = Column(Float, nullable=False, default=time.time)

    cleanup_counter = Column(Integer, default=0, nullable=False)

    def __repr__(self):
        return f'<DeletedUser {self.user_id} - Cleanup step {self.cleanup_counter}>'


class AuditEvent(Base):
    """
    Represents a single audit trail event for security and tracking purposes.
    """
    __tablename__ = 'audit_events'

    id = Column(Integer, primary_key=True)

    user_id = Column(String(64), ForeignKey('users.id'), nullable=True, index=True)

    event_type = Column(String(100), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, default=time.time)
    ip_address = Column(String(45), nullable=True)

    details = Column(JsonType, nullable=True)

    user = relationship('User', back_populates='audit_events')

    def __repr__(self):
        return f'<AuditEvent {self.event_type} at {self.timestamp}>'


class DatabaseManager:
    """
    Manages database connections and sessions using SQLAlchemy.
    """
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def __init__(self):
        """Initializes the database and creates tables if they don't exist."""
        super().__init__()
        Base.metadata.create_all(bind=engine)

    @contextmanager
    def get_context_manager_db(self):
        return self.get_db()

    def get_db(self):
        """Provides a database session as a context manager."""
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()


    def log_audit_event(self, user_id: str, event_type: str, ip_address: str = None, details: dict = None):
        """Logs an audit event in the database."""
        try:
            with self.get_db() as db:
                audit_event = AuditEvent(
                    user_id=user_id,
                    event_type=event_type,
                    ip_address=ip_address,
                    details=details or {}
                )
                db.add(audit_event)
                db.commit()
                return audit_event
        except TypeError:
            with self.get_context_manager_db() as db:
                audit_event = AuditEvent(
                    user_id=user_id,
                    event_type=event_type,
                    ip_address=ip_address,
                    details=details or {}
                )
                db.add(audit_event)
                db.commit()
                return audit_event



db_manager = DatabaseManager()
