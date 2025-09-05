import json
import time
from sqlalchemy import create_engine, Column, event, Table, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.types import TypeDecorator, TEXT, String, Text, Boolean, Integer, Float
from sqlalchemy.engine import Engine
from authtuna.core.encryption import encryption_utils
from sqlalchemy.dialects.postgresql import CITEXT, JSONB

from authtuna.core.config import settings

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





user_roles_association = Table('user_roles', Base.metadata,
                               Column('user_id', String(64), ForeignKey('users.id'), primary_key=True),
                               Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
                               
                               Column('given_by_id', String(64), ForeignKey('users.id'), nullable=False),
                               
                               Column('given_at', Float, nullable=False, default=time.time)
                               )


role_permissions_association = Table('role_permissions', Base.metadata,
                                     Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
                                     Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
                                     
                                     Column('added_by_id', String(64), ForeignKey('users.id'), nullable=True),
                                     Column('added_at', Float, nullable=False, default=time.time)
                                     )




class User(Base):
    """
    Represents a user in the database.
    Maps to the 'users' table.
    """
    __tablename__ = 'users'

    id = Column(String(64), primary_key=True, index=True)
    username = Column(CaseInsensitiveText(80, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                      unique=True, nullable=False)
    email = Column(CaseInsensitiveText(120, collation='NOCASE' if engine.dialect.name == 'sqlite' else None),
                   unique=True, nullable=False, index=True)
    
    password_hash = Column(String(256), nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    requires_password_reset = Column(Boolean, default=False,
                                     nullable=False)  
    mfa_enabled = Column(Boolean, default=False, nullable=False)  
    
    created_at = Column(Float, nullable=False, default=time.time)
    last_login = Column(Float, nullable=False, default=time.time)

    
    roles = relationship('Role', secondary=user_roles_association, back_populates='users', lazy='joined')
    
    sessions = relationship('Session', back_populates='user', cascade="all, delete-orphan")
    tokens = relationship('Token', back_populates='user', cascade="all, delete-orphan", foreign_keys='Token.user_id')
    social_accounts = relationship('SocialAccount', back_populates='user', cascade="all, delete-orphan")
    mfa_methods = relationship('MFAMethod', back_populates='user', cascade="all, delete-orphan")
    mfa_recovery_codes = relationship('MFARecoveryCode', back_populates='user', cascade="all, delete-orphan")
    audit_events = relationship('AuditEvent', back_populates='user', cascade="all, delete-orphan")

    def set_password(self, password):
        """Sets the user's password hash."""
        self.password_hash = encryption_utils.hash_password(password)


    def check_password(self, password):
        """Checks if the given password matches the user's password hash."""
        if not self.email_verified:
            return None
        if self.password_hash:
            return encryption_utils.verify_password(password, self.password_hash)
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
        return f'<User {self.username}>'


class Role(Base):
    """
    Represents a role that can be assigned to users.
    """
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
    system = Column(Boolean, default=False, nullable=False)  

    users = relationship('User', secondary=user_roles_association, back_populates='roles')
    permissions = relationship('Permission', secondary=role_permissions_association, back_populates='roles',
                               lazy='joined')

    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(Base):
    """
    Represents a specific permission.
    """
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)  
    description = Column(String(255))
    system = Column(Boolean, default=False, nullable=False)  

    roles = relationship('Role', secondary=role_permissions_association, back_populates='permissions')

    def __repr__(self):
        return f'<Permission {self.name}>'


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
    etime = Column(Float, nullable=False, default=lambda: time.time()+settings.SESSION_LIFETIME_SECONDS, onupdate=lambda: time.time()+settings.SESSION_LIFETIME_SECONDS)
    e_abs_time = Column(Float, nullable=False, default=lambda: time.time() + settings.SESSION_ABSOLUTE_LIFETIME_SECONDS)
    create_ip = Column(String(45))  
    last_ip = Column(String(45))  
    user = relationship('User', back_populates='sessions')
    random_string = Column(String(255), nullable=False, default=encryption_utils.gen_random_string, onupdate=encryption_utils.gen_random_string)  # VV-IMP: This minimizes session hijack risks.
    def __repr__(self):
        return f'<Session {self.session_id} for User {self.user_id}>'

    def is_expired(self):
        return time.time() > self.etime or time.time() > self.e_abs_time

    def is_valid(self, region: str = "", device: str = "", random_string: str = ""):
        return self.active and not self.is_expired() and self.region == region and  self.device == device and self.random_string == random_string

    def update_last_ip(self, ip: str):
        self.last_ip = ip
        self.mtime = time.time()

    def get_random_string(self):
        return self.random_string

    def get_user_id(self):
        return self.user_id

    def update_random_string(self):
        self.random_string = encryption_utils.gen_random_string()
        self.mtime = time.time()
        return self.random_string

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
    """
    Represents a single-use token for actions like password reset or email verification.
    """
    __tablename__ = 'tokens'

    id = Column(String(64), primary_key=True)  
    purpose = Column(String(50), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)

    ctime = Column(Float, nullable=False, default=time.time)
    etime = Column(Float, nullable=False)  

    used = Column(Boolean, default=False, nullable=False)

    
    new_gen_id = Column(String(64), ForeignKey('tokens.id'), nullable=True)

    user = relationship('User', back_populates='tokens', foreign_keys=[user_id])
    
    new_generation = relationship('Token', remote_side=[id], backref='previous_generation', uselist=False)

    def __repr__(self):
        return f'<Token {self.id} for {self.purpose}>'


class SocialAccount(Base):
    """
    Represents a link between a user and an external OAuth provider.
    """
    __tablename__ = 'social_accounts'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False, index=True)

    provider = Column(String(50), nullable=False, index=True)  
    provider_user_id = Column(String(255), nullable=False, index=True)  

    extra_data = Column(JsonType, nullable=True)  

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
    active = Column(Boolean, default = False, nullable = False)
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

    def get_db(self):
        """Provides a database session as a context manager."""
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()



db_manager = DatabaseManager()
