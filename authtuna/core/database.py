"""
Database models and async database manager for AuthTuna.

This module defines all SQLAlchemy ORM models (User, Role, Permission, Session, Token, etc.) and provides the async database engine and session manager. Only SQLite (aiosqlite) and PostgreSQL (asyncpg) are supported. All operations are async and designed for high-security, high-performance web applications.
"""

import json
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
import asyncio
from sqlalchemy import Column, event, Table, ForeignKey, text, AsyncAdaptedQueuePool, VARCHAR, LargeBinary, ForeignKeyConstraint, select
from sqlalchemy.dialects.postgresql import CITEXT, JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.types import TypeDecorator, TEXT, String, Text, Boolean, Integer, Float
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authtuna.core.config import settings
from authtuna.core.encryption import encryption_utils

# --- Base Model ---
# Declarative base for all SQLAlchemy models.
Base = declarative_base()

# --- Async Engine Setup ---
# The database URL is modified for async drivers if needed.
# Only SQLite (aiosqlite) and PostgreSQL (asyncpg) are supported.
db_uri = settings.DEFAULT_DATABASE_URI
if 'sqlite' in db_uri and 'aiosqlite' not in db_uri:
    db_uri = db_uri.replace('sqlite:///', 'sqlite+aiosqlite:///')

# Asynchronous engine for database connections.
engine = create_async_engine(
    db_uri,
    connect_args={'check_same_thread': False} if 'sqlite' in db_uri else {},
    poolclass=AsyncAdaptedQueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_recycle=settings.DATABASE_POOL_RECYCLE,
    pool_pre_ping=settings.DATABASE_POOL_PRE_PING,
)

# --- SQLite PRAGMA Configuration ---
# This event listener works for both sync and async engines.
if engine.dialect.name == 'sqlite':
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Enforces foreign key constraints and case-insensitive LIKE for SQLite."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA case_sensitive_like=OFF")
        cursor.close()


# --- Custom Column Types ---

class CaseInsensitiveText(TypeDecorator):
    """
    Case-insensitive text column type.
    Uses CITEXT on PostgreSQL and NOCASE collation on SQLite.
    """
    impl = TEXT
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(CITEXT())
        else:
            # For SQLite, the collation is set on the Column itself.
            # For other DBs, it falls back to a standard string.
            return dialect.type_descriptor(String)


class JsonType(TypeDecorator):
    """
    Stores a Python dict as JSON. Uses native JSONB on PostgreSQL, TEXT on SQLite.
    """
    impl = TEXT
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(Text)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        # PostgreSQL with JSONB handles dicts natively.
        if dialect.name == 'postgresql':
            return value
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        # PostgreSQL with JSONB returns a dict.
        if dialect.name == 'postgresql':
            return value
        # Other DBs store it as a string.
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {}
        return value


# --- Association Tables ---

user_roles_association = Table(
    'user_roles', Base.metadata,
    Column('user_id', String(64), ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('scope', String(255), primary_key=True, default='none', nullable=False),
    Column('given_by_id', VARCHAR(64),
           nullable=False),
    Column('given_at', Float, nullable=False, default=time.time),
)

role_permissions_association = Table(
    'role_permissions', Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('added_by_id', String(64), ForeignKey('users.id'), nullable=True),
    Column('added_at', Float, nullable=False, default=time.time),
)


role_assign_permissions = Table(
    'role_assign_permissions', Base.metadata,
    Column('assigner_role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('assignable_role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)


role_grant_permissions = Table(
    'role_grant_permissions', Base.metadata,
    Column('granter_role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('grantable_permission_id', Integer, ForeignKey('permissions.id'), primary_key=True)
)


organization_members = Table(
    'organization_members', Base.metadata,
    Column('user_id', String(64), ForeignKey('users.id'), primary_key=True),
    Column('organization_id', String(64), ForeignKey('organization.id'), primary_key=True),
    Column('joined_at', Float, default=time.time, nullable=False)
)


team_members = Table(
    'team_members', Base.metadata,
    Column('user_id', String(64), ForeignKey('users.id'), primary_key=True),
    Column('team_id', String(64), ForeignKey('team.id'), primary_key=True),
    Column('joined_at', Float, default=time.time, nullable=False)
)

class UserRoleAssociation(Base):
    """
    Association object mapping Users to Roles, including the 'scope'
    and audit data (who gave the role and when).
    """
    __table__ = user_roles_association
    user = relationship("User", back_populates="role_associations", viewonly=True)
    role = relationship("Role", back_populates="user_associations", viewonly=True)

class ApiKeyScope(Base):
    """
    Normalized mapping between an ApiKey and a specific entry in user_roles.
    This enforces that any scope granted to an ApiKey must already exist in the
    user's assigned roles (prevents creating arbitrary roles/scopes via JSON).
    The composite ForeignKeyConstraint references the user_roles table's
    composite primary key (user_id, role_id, scope).
    """
    __tablename__ = 'api_key_scopes'

    api_key_id = Column(String(64), ForeignKey('api_keys.id', ondelete='CASCADE'), primary_key=True)
    user_id = Column(String(64), nullable=False, primary_key=True)
    role_id = Column(Integer, nullable=False, primary_key=True)
    scope = Column(String(255), nullable=False, primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ['user_id', 'role_id', 'scope'],
            ['user_roles.user_id', 'user_roles.role_id', 'user_roles.scope'],
            ondelete='CASCADE'
        ),
    )

# --- ORM Models ---

class User(Base):
    """
    Represents a user in the database.
    All password and login methods are async and log audit events.
    """
    __tablename__ = 'users'

    id = Column(String(64), primary_key=True, index=True)
    username = Column(CaseInsensitiveText(80, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                      unique=True, nullable=False, index=True)
    email = Column(CaseInsensitiveText(120, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                   unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    password_hash = Column(String(256), nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    requires_password_reset = Column(Boolean, default=False, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)

    created_at = Column(Float, nullable=False, default=time.time)
    last_login = Column(Float, nullable=False, default=time.time)
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")

    roles = relationship(
        "Role", secondary=user_roles_association, back_populates="users", lazy="joined",
        primaryjoin=lambda: User.id == user_roles_association.c.user_id,
        secondaryjoin=lambda: Role.id == user_roles_association.c.role_id,
        cascade="all, delete",
    )
    role_associations = relationship(
        "UserRoleAssociation",
        back_populates="user",
        lazy="joined",
        cascade="all, delete-orphan",
        viewonly=True
    )

    passkey_credentials = relationship("PasskeyCredential", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan", foreign_keys="Token.user_id")
    social_accounts = relationship("SocialAccount", back_populates="user", cascade="all, delete-orphan")
    mfa_methods = relationship("MFAMethod", back_populates="user", cascade="all, delete-orphan")
    mfa_recovery_codes = relationship("MFARecoveryCode", back_populates="user", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="user", cascade="all, delete-orphan")
    organizations_owned = relationship("Organization", back_populates="owner", foreign_keys="Organization.owner_id", cascade="all, delete-orphan")
    organizations = relationship("Organization", secondary=organization_members, back_populates="members", cascade="all, delete")
    teams = relationship("Team", secondary=team_members, back_populates="members", cascade="all, delete")

    async def set_password(self, password: str, ip: str, db_manager_custom=None, db: AsyncSession = None):
        """
        Asynchronously sets the user's password hash and logs the event.
        """
        db_manager_to_use = db_manager_custom or db_manager
        old_hash = self.password_hash
        self.password_hash = encryption_utils.hash_password(password)
        await db_manager_to_use.log_audit_event(
            self.id, "PASSWORD_CHANGED", ip,
            {"had_old_password": bool(old_hash)}, db=db,
        )

    async def check_password(self, password: str, ip: str, db_manager_custom=None, db: AsyncSession = None) -> Optional[bool]:
        """
        Asynchronously checks the password and logs login attempts.
        Returns True if valid, False otherwise.
        """
        db_manager_to_use = db_manager_custom or db_manager
        if self.requires_password_reset:
            await db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "password_reset_required"}, db=db)
            return False
        if settings.EMAIL_ENABLED and not self.email_verified:
            await db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "email_not_verified"}, db=db)
            return None
        if self.password_hash:
            if encryption_utils.verify_password(password, self.password_hash):
                await db_manager_to_use.log_audit_event(self.id, "LOGIN_SUCCESS", ip, db=db)
                return True
            else:
                await db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "incorrect_password"}, db=db)
                return False
        await db_manager_to_use.log_audit_event(self.id, "LOGIN_FAILED", ip, {"reason": "no_password_set"}, db=db)
        return False

    def is_email_verified(self):
        return self.email_verified

    def has_role(self, role_name: str):
        return any(role.name == role_name for role in self.roles)

    def has_permission(self, permission_name: str):
        for role in self.roles:
            if any(permission.name == permission_name for permission in role.permissions):
                return True
        return False

    def get_role_scope(self, role_id: int):
        """
        Returns the scope of a given role assigned to the user. If no role is found, returns None.
        :param role_id:
        :return:
        """
        scopes = []
        for assoc in self.role_associations:
            if assoc.role_id == role_id:
                scopes.append(assoc.scope)
        return scopes

    def __repr__(self):
        return f"<User {self.username}>"


class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
    system = Column(Boolean, default=False, nullable=False)
    level = Column(Integer, nullable=True)

    users = relationship(
        "User", secondary=user_roles_association, back_populates="roles",
        primaryjoin=lambda: Role.id == user_roles_association.c.role_id,
        secondaryjoin=lambda: User.id == user_roles_association.c.user_id,
    )
    permissions = relationship("Permission", secondary=role_permissions_association, back_populates="roles", lazy="joined")

    can_assign_roles = relationship(
        "Role",
        secondary=role_assign_permissions,
        primaryjoin=id == role_assign_permissions.c.assigner_role_id,
        secondaryjoin=id == role_assign_permissions.c.assignable_role_id,
        backref="assignable_by_roles",
        lazy="joined"
    )

    can_grant_permissions = relationship(
        "Permission",
        secondary=role_grant_permissions,
        primaryjoin=id == role_grant_permissions.c.granter_role_id,
        secondaryjoin=lambda: Permission.id == role_grant_permissions.c.grantable_permission_id,
        backref="grantable_by_roles",
        lazy="joined"
    )

    user_associations = relationship(
        "UserRoleAssociation",
        back_populates="role",
        lazy="selectin",
        cascade="all, delete-orphan",
        viewonly=True,
    )

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
    All methods are async and support advanced session hijack detection.
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
    random_string = Column(String(255), nullable=False, default=encryption_utils.gen_random_string)
    previous_random_strings = Column(JsonType, nullable=False, default=list)

    def is_expired(self):
        return time.time() > self.etime or time.time() > self.e_abs_time

    async def is_valid(self, region: str = "", device: str = "", random_string: str = "", ip: str = "", db: AsyncSession = None) -> bool:
        """
        Checks if the session is valid, not expired, and matches device/region/random_string.
        Invalidates and logs if any check fails.
        """
        if self.active and not self.is_expired():
            if settings.LOCK_SESSION_REGION and (self.region != region)  and (self.create_ip != ip):
                await db_manager.log_audit_event(self.user_id, "SESSION_INVALIDATED", self.last_ip, {"reason": "region_mismatch"}, db=db)
                await self.terminate(self.last_ip, db=db)
                return False
            if self.device != device:
                await db_manager.log_audit_event(self.user_id, "SESSION_INVALIDATED", self.last_ip, {"reason": "device_mismatch"}, db=db)
                await self.terminate(self.last_ip, db=db)
                return False
            if settings.DISABLE_RANDOM_STRING:
                is_token_valid = True
            else:
                is_token_valid = (self.random_string == random_string or
                              any(entry['value'] == random_string for entry in self.previous_random_strings))

            if is_token_valid:
                return True
            else:
                await db_manager.log_audit_event(self.user_id, "SESSION_INVALIDATED", self.last_ip,
                                                 {"reason": "random_string_mismatch"}, db=db)
                await self.terminate(self.last_ip, db=db)
                return False
        return False

    async def update_last_ip(self, ip: str, db_manager_custom=None, db: AsyncSession = None):
        """
        Updates the last IP address for the session and logs the change.
        """
        db_manager_to_use = db_manager_custom or db_manager
        old_ip = self.last_ip
        self.last_ip = ip
        self.mtime = time.time()
        if old_ip != ip:
            await db_manager_to_use.log_audit_event(self.user_id, "SESSION_IP_UPDATED", ip, {"old_ip": old_ip, "new_ip": ip}, db=db)

    def get_cookie_string(self) -> str:
        """Return a signed JWT string representing the current session state.
        Encodes session_id, user_id, absolute expiry and the current random_string,
        and includes a database_checked timestamp to control DB verification cadence.
        """
        cookie_data = {
            'session': self.session_id, 'e_abs_time': self.e_abs_time,
            'random_string': self.random_string, 'user_id': self.user_id,
            'database_checked': time.time(),
        }
        return encryption_utils.create_jwt_token(cookie_data)

    async def update_random_string(self):
        """
        Rotates the per-request random_string to mitigate replay attacks.
        """
        now = time.time()

        new_history = [{'value': self.random_string, 'timestamp': now}]
        if settings.DISABLE_RANDOM_STRING:
            grace_period = 0
        else:
            grace_period = settings.SESSION_DB_VERIFICATION_INTERVAL + settings.RANDOM_STRING_GRACE # MINIMIZES FALSE INVALIDATIONS
        for entry in self.previous_random_strings:
            if now - entry.get('timestamp', 0) < grace_period:
                new_history.append(entry)
        self.previous_random_strings = new_history
        self.random_string = encryption_utils.gen_random_string()
        self.mtime = now
        return self.random_string

    async def terminate(self, ip: str, db_manager_custom=None, db: AsyncSession = None):
        """
        Marks session inactive and writes an audit event.
        """
        db_manager_to_use = db_manager_custom or db_manager
        self.active = False
        await db_manager_to_use.log_audit_event(self.user_id, "SESSION_TERMINATED", ip, {"session_id": self.session_id}, db=db)


class Token(Base):
    __tablename__ = 'tokens'
    id = Column(String(64), primary_key=True)
    purpose = Column(String(200), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    ctime = Column(Float, nullable=False, default=time.time)
    etime = Column(Float, nullable=False, default=lambda: time.time() + settings.TOKENS_EXPIRY_SECONDS)
    used = Column(Boolean, default=False, nullable=False)
    new_gen_id = Column(String(64), ForeignKey('tokens.id'), nullable=True)
    user = relationship("User", back_populates="tokens", foreign_keys=[user_id])
    new_generation = relationship("Token", remote_side=[id], backref="previous_generation", uselist=False)

    def is_valid(self):
        return not self.used and self.etime > time.time()

    async def mark_used(self, ip: str, db_manager_custom=None, db: AsyncSession = None):
        db_manager_to_use = db_manager_custom or db_manager
        self.used = True
        await db_manager_to_use.log_audit_event(self.user_id, "TOKEN_USED", ip, {"token_id": self.id, "purpose": self.purpose}, db=db)


class SocialAccount(Base, OAuth2ClientMixin):
    __tablename__ = 'social_accounts'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    extra_data = Column(JsonType, nullable=True)
    created_at = Column(Float, nullable=False, default=time.time)
    last_used_at = Column(Float, nullable=False, default=time.time)
    provider = Column(String(50), nullable=False, index=True)
    provider_user_id = Column(String(255), nullable=False, index=True)
    token_type = Column(String(40), nullable=False, default="bearer")
    access_token = Column(String(1200), nullable=False)
    refresh_token = Column(String(1200))
    expires_at = Column(Integer, nullable=True)
    user = relationship('User', back_populates='social_accounts')


class MFAMethod(Base):
    __tablename__ = 'mfa_methods'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    method_type = Column(String(20), nullable=False)
    secret = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    user = relationship('User', back_populates='mfa_methods')


class MFARecoveryCode(Base):
    __tablename__ = 'mfa_recovery_codes'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    hashed_code = Column(String(256), nullable=False, unique=True)
    is_used = Column(Boolean, default=False, nullable=False)
    actived_at = Column(Float, nullable=True)
    active = Column(Boolean, default=False, nullable=False)
    user = relationship('User', back_populates='mfa_recovery_codes')


class PasskeyCredential(Base):
    __tablename__ = 'passkey_credentials'

    id = Column(LargeBinary(1023), primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id', ondelete="CASCADE"), nullable=False, index=True)
    nickname = Column(String(100), nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    aaguid = Column(LargeBinary(16), nullable=True)
    is_discoverable = Column(Boolean, default=False, nullable=False)
    is_backup_eligible = Column(Boolean, default=False, nullable=False)
    is_backed_up = Column(Boolean, default=False, nullable=False)
    transports = Column(JsonType, nullable=True, default=list)
    created_at = Column(Float, nullable=False, default=time.time)
    last_used_at = Column(Float, nullable=False, default=time.time, onupdate=time.time)
    user = relationship("User", back_populates="passkey_credentials")


class DeletedUser(Base):
    __tablename__ = 'deleted_users'
    user_id = Column(String(64), primary_key=True)
    email = Column(String(255), nullable=False)
    data = Column(JsonType, nullable=True)
    initiated_at = Column(Float, nullable=False, default=time.time)
    cleanup_counter = Column(Integer, default=0, nullable=False)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, default=time.time)
    ip_address = Column(String(45), nullable=True)
    details = Column(JsonType, nullable=True)
    user = relationship('User', back_populates='audit_events')


class Organization(Base):
    __tablename__ = 'organization'

    id = Column(String(64), primary_key=True, default=lambda: f"org_{encryption_utils.gen_random_string(28)}")
    name = Column(String(100), nullable=False, unique=True)
    owner_id = Column(String(64), ForeignKey('users.id'), nullable=False)
    created_at = Column(Float, nullable=False, default=time.time)

    owner = relationship("User", back_populates="organizations_owned", foreign_keys=[owner_id])
    teams = relationship("Team", back_populates="organization", cascade="all, delete-orphan")
    members = relationship("User", secondary=organization_members, back_populates="organizations")

    def __repr__(self):
        return f"<Organization {self.name} (ID: {self.id})>"


class Team(Base):
    __tablename__ = 'team'

    id = Column(String(64), primary_key=True, default=lambda: f"team_{encryption_utils.gen_random_string(27)}")
    name = Column(String(100), nullable=False)
    organization_id = Column(String(64), ForeignKey('organization.id'), nullable=False)
    created_at = Column(Float, nullable=False, default=time.time)

    organization = relationship("Organization", back_populates="teams")
    members = relationship("User", secondary=team_members, back_populates="teams")

    def __repr__(self):
        return f"<Team {self.name} (ID: {self.id})>"


class DatabaseManager:
    """
    Manages async database connections and sessions for AuthTuna.
    Only supports SQLite (aiosqlite) and PostgreSQL (asyncpg).
    Handles auto-creation of tables and audit event logging.
    """
    AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    def __init__(self):
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def initialize_database(self):
        """
        Initializes the database and creates tables if they don't exist.
        For PostgreSQL, ensures the citext extension is available.
        """
        if engine.dialect.name == 'postgresql':
            try:
                async with engine.connect() as conn:
                    await conn.run_sync(
                        lambda sync_conn: sync_conn.execute(text('CREATE EXTENSION IF NOT EXISTS citext;'))
                    )
                    await conn.commit()
            except Exception as e:
                logging.debug(f"Could not create PostgreSQL extension citext (it may already exist): {e}")

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        from authtuna.core.defaults import provision_defaults
        async with self.AsyncSessionLocal() as session:
            await provision_defaults(session)

    @asynccontextmanager
    async def get_context_manager_db(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Provides an async database session as a context manager.
        Ensures tables are created if AUTO_CREATE_DATABASE is enabled.
        """
        if settings.AUTO_CREATE_DATABASE:
            if not self._initialized:
                async with self._init_lock:
                    if not self._initialized and getattr(settings, 'AUTO_CREATE_DATABASE', False):
                        await self.initialize_database()
        async with self.AsyncSessionLocal() as session:
            yield session

    def get_db(self):
        """
        Returns an async context manager for a database session.
        Usage: async with db_manager.get_db() as db:
        """
        # Returns the async context manager itself to be used with `async with`
        return self.get_context_manager_db()

    async def log_audit_event(self, user_id: str, event_type: str, ip_address: str = None, details: dict = None, db: AsyncSession = None):
        """
        Asynchronously logs an audit event in the database.
        If db is provided, adds to that session; otherwise, creates a new session.
        """
        audit_event = AuditEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            details=details or {}
        )
        if db:
            # If a session object is passed, add the event to that session.
            # The caller is responsible for committing the transaction.
            db.add(audit_event)
            return audit_event

        try:
            async with self.get_db() as session:
                session.add(audit_event)
                await session.commit()
                return audit_event
        except TypeError:
            async with self.get_context_manager_db() as session:
                session.add(audit_event)
                await session.commit()
                return audit_event


class ApiKey(Base):
    """
    Represents a user-generated API key.
    The 'id' column stores the *public, non-secret* part of the key (e.g., 'sk_live_123abc...').
    The 'hashed_key' stores the bcrypt hash of the *full, secret* key.
    """
    __tablename__ = 'api_keys'

    id = Column(String(64), primary_key=True, index=True)
    hashed_key = Column(String(256), nullable=False, unique=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)
    key_type = Column(String(20), nullable=False, default="secret") # secret, public_key, master_key, test_key
    name = Column(String(100), nullable=True)
    created_at = Column(Float, nullable=False, default=time.time)
    last_used_at = Column(Float, nullable=True)
    expires_at = Column(Float, nullable=True)
    api_key_scopes = relationship('ApiKeyScope', backref='api_key', cascade='all, delete-orphan')
    user = relationship('User', back_populates='api_keys')

    def __repr__(self):
        return f"<ApiKey {self.id} (User: {self.user_id})>"

    @property
    def scopes(self):
        """Return a lightweight list of scope entries linked to this ApiKey.

        Each entry is a dict: {'role_id': <int>, 'scope': <str>}.
        This does not perform any DB I/O and reads from the in-memory relationship
        collection (so ensure the relationship is loaded).
        """
        return [{'role_id': s.role_id, 'scope': s.scope} for s in self.api_key_scopes]

    def has_scope(self, scope: str) -> bool:
        """Check whether this ApiKey includes the exact scope string (no DB access)."""
        return any(s.scope == scope for s in self.api_key_scopes)

    def granted_role_ids(self) -> set:
        """Return set of role_id integers granted to this key (no DB access)."""
        return {s.role_id for s in self.api_key_scopes}

    async def load_scope_role_names(self, db: AsyncSession):
        """Load the role names for the scopes on this ApiKey in a single query.

        Returns a list of dicts: [{'role_name': <str>, 'scope': <str>}]. This is
        useful for authorization checks where role names are required without
        issuing N queries.
        """
        if self.key_type == "MASTER":
            stmt = select(Role, user_roles_association.c.scope).join(
                user_roles_association, Role.id == user_roles_association.c.role_id
            ).where(user_roles_association.c.user_id == self.user_id)
            result = await db.execute(stmt)
            rows = result.unique().all()
            return [{'role_name': row[0].name, 'scope': row[1]} for row in rows]

        role_ids = {s.role_id for s in self.api_key_scopes}
        if not role_ids:
            return []
        stmt = select(Role).where(Role.id.in_(role_ids))
        result = await db.execute(stmt)
        roles = {r.id: r.name for r in result.scalars().all()}
        return [{'role_name': roles.get(s.role_id), 'scope': s.scope} for s in self.api_key_scopes]

    async def grants_role_name(self, role_name: str, db: AsyncSession) -> bool:
        """Efficiently check if this ApiKey grants the given role name by batch-loading role names once."""
        rows = await self.load_scope_role_names(db)
        return any(r['role_name'] == role_name for r in rows)

# class RefreshFramework(Base):
#     """
#     I am thinking to implement refresh framework for creating refresh tokens + access tokens but still dont feel its worth it rn so leaving it blank for now.
#     """
#     __tablename__ = 'refresh_framework'
#     id = Column(Integer, primary_key=True)
#     pass

db_manager = DatabaseManager()
