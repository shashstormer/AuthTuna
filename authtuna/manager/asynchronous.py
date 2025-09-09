import time
from typing import Optional, Tuple, List, Dict, Any

from authtuna.core.config import settings
from authtuna.core.database import (
    DatabaseManager, User, Role, Permission, DeletedUser,
    Session as DBSession, Token, user_roles_association, role_permissions_association
)
from authtuna.core.encryption import encryption_utils
from authtuna.core.exceptions import (
    UserAlreadyExistsError, InvalidCredentialsError, EmailNotVerifiedError,
    InvalidTokenError, TokenExpiredError, RateLimitError, UserNotFoundError,
    SessionNotFoundError, RoleNotFoundError, PermissionNotFoundError, OperationForbiddenError
)
from sqlalchemy import or_, select
from sqlalchemy.orm import joinedload, Session
from starlette.concurrency import run_in_threadpool


class UserManager:
    """Manages all CRUD and business logic operations related to Users."""

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_id(self, user_id: str, with_relations: bool = True) -> Optional[User]:
        with self._db_manager.get_context_manager_db() as db:
            query = db.query(User)
            if with_relations:
                query = query.options(joinedload(User.roles))
            return await run_in_threadpool(query.filter(User.id == user_id).first)

    async def get_by_email(self, email: str) -> Optional[User]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(User).filter(User.email == email).first)

    async def get_by_username(self, username: str) -> Optional[User]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(User).filter(User.username == username).first)

    async def list(self, skip: int = 0, limit: int = 100) -> List[User]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(User).offset(skip).limit(limit).all)

    async def create(self, email: str, username: str, password: Optional[str] = None, ip_address: str = 'system',
                     **kwargs) -> User:
        """
        FIXED: Creates a user, sets password, and logs audit event in a single atomic transaction.
        """
        with self._db_manager.get_context_manager_db() as db:
            if await run_in_threadpool(
                    db.query(User).filter((User.email == email) | (User.username == username)).first):
                raise UserAlreadyExistsError("A user with this email or username already exists.")

            new_user = User(
                id=encryption_utils.gen_random_string(32), email=email, username=username, **kwargs
            )
            db.add(new_user)

            if password:
                # Pass the session 'db' to ensure it's the same transaction
                new_user.set_password(password, ip_address, self._db_manager, db)

            # Log the event *inside* the transaction block
            self._db_manager.log_audit_event(
                new_user.id, "USER_CREATED", ip_address,
                {"by": "system" if ip_address == 'system' else 'user_signup'}, db=db
            )

            # Only one commit at the end for atomicity
            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, new_user)
            return new_user

    async def update(self, user_id: str, update_data: Dict[str, Any], ip_address: str = 'system') -> User:
        with self._db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(db.query(User).filter(User.id == user_id).first)
            if not user:
                raise UserNotFoundError("User not found.")

            for key, value in update_data.items():
                if hasattr(user, key) and key not in ['id', 'password_hash']:
                    setattr(user, key, value)

            # Log the event *inside* the transaction block
            self._db_manager.log_audit_event(user_id, "USER_UPDATED", ip_address,
                {"fields_changed": list(update_data.keys())}, db=db
            )

            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, user)
            return user

    async def delete(self, user_id: str, ip_address: str = 'system') -> None:
        with self._db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(db.query(User).filter(User.id == user_id).first)
            if not user:
                raise UserNotFoundError("User not found.")

            user_data = {c.name: getattr(user, c.name) for c in user.__table__.columns}
            archived_user = DeletedUser(user_id=user.id, email=user.email, data=user_data)
            db.add(archived_user)
            db.delete(user)

            # Log the event *inside* the transaction block
            self._db_manager.log_audit_event(user_id, "USER_DELETED", ip_address, {"archived": True}, db=db)
            await run_in_threadpool(db.commit)

    async def set_password(self, user_id: str, new_password: str, ip_address: str):
        with self._db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(db.query(User).filter(User.id == user_id).first)
            if not user:
                raise UserNotFoundError("User not found.")
            # Pass the session 'db' to ensure it's the same transaction
            user.set_password(new_password, ip_address, self._db_manager, db)
            await run_in_threadpool(db.commit)


class RoleManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'global'):
        with self._db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(db.query(User).filter(User.id == user_id).first)
            if not user: raise UserNotFoundError("User not found.")
            role = await run_in_threadpool(db.query(Role).filter(Role.name == role_name).first)
            if not role: raise RoleNotFoundError(f"Role '{role_name}' not found.")

            stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role.id,
                user_roles_association.c.scope == scope
            )
            if await run_in_threadpool(lambda: db.execute(stmt).first()):
                return

            stmt = user_roles_association.insert().values(
                user_id=user.id, role_id=role.id, scope=scope,
                given_by_id=assigner_id, given_at=time.time()
            )
            await run_in_threadpool(lambda: db.execute(stmt))

            # Log the event *inside* the transaction block
            self._db_manager.log_audit_event(user_id, "ROLE_ASSIGNED", "system",
                {"role": role_name, "scope": scope, "by": assigner_id}, db=db
            )
            await run_in_threadpool(db.commit)

    async def get_by_name(self, name: str) -> Optional[Role]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(Role).filter(Role.name == name).first)

    async def get_or_create(self, name: str, defaults: dict = None) -> Tuple[Role, bool]:
        role = await self.get_by_name(name)
        if role: return role, False
        create_params = defaults or {}
        new_role = await self.create(name, **create_params)
        return new_role, True

    async def create(self, name: str, description: str = "", system: bool = False) -> Role:
        with self._db_manager.get_context_manager_db() as db:
            if await run_in_threadpool(db.query(Role).filter(Role.name == name).first):
                raise ValueError(f"Role with name '{name}' already exists.")
            new_role = Role(name=name, description=description, system=system)
            db.add(new_role)
            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, new_role)
            return new_role

    async def add_permission_to_role(self, role_name: str, permission_name: str, adder_id: Optional[str] = None):
        with self._db_manager.get_context_manager_db() as db:
            role = await run_in_threadpool(db.query(Role).filter(Role.name == role_name).first)
            if not role: raise RoleNotFoundError(f"Role '{role_name}' not found.")
            permission = await run_in_threadpool(db.query(Permission).filter(Permission.name == permission_name).first)
            if not permission: raise PermissionNotFoundError(f"Permission '{permission_name}' not found.")
            stmt = select(role_permissions_association).where(
                role_permissions_association.c.role_id == role.id,
                role_permissions_association.c.permission_id == permission.id
            )
            if await run_in_threadpool(lambda: db.execute(stmt).first()): return
            stmt = role_permissions_association.insert().values(
                role_id=role.id, permission_id=permission.id, added_by_id=adder_id, added_at=time.time()
            )
            await run_in_threadpool(lambda: db.execute(stmt))
            await run_in_threadpool(db.commit)

    async def get_user_roles_with_scope(self, user_id: str) -> List[dict]:
        with self._db_manager.get_context_manager_db() as db:
            stmt = select(Role.name, user_roles_association.c.scope).join_from(
                user_roles_association, Role, user_roles_association.c.role_id == Role.id
            ).where(user_roles_association.c.user_id == user_id)
            results = await run_in_threadpool(db.execute(stmt).all)
            return [{"role_name": row[0], "scope": row[1]} for row in results]

    async def has_permission(self, user_id: str, permission_name: str, scope_prefix: Optional[str] = None) -> bool:
        with self._db_manager.get_context_manager_db() as db:
            stmt = select(Permission.id).join(
                role_permissions_association, Permission.id == role_permissions_association.c.permission_id
            ).join(
                user_roles_association, role_permissions_association.c.role_id == user_roles_association.c.role_id
            ).where(
                user_roles_association.c.user_id == user_id, Permission.name == permission_name
            )
            if scope_prefix:
                stmt = stmt.where(
                    or_(user_roles_association.c.scope == 'global',
                        user_roles_association.c.scope.startswith(scope_prefix))
                )
            result = await run_in_threadpool(lambda: db.execute(stmt).first())
            return result is not None


class PermissionManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_name(self, name: str) -> Optional[Permission]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(Permission).filter(Permission.name == name).first)

    async def get_or_create(self, name: str, defaults: dict = None) -> Tuple[Permission, bool]:
        perm = await self.get_by_name(name)
        if perm: return perm, False
        create_params = defaults or {}
        new_perm = await self.create(name, **create_params)
        return new_perm, True

    async def create(self, name: str, description: str = "") -> Permission:
        with self._db_manager.get_context_manager_db() as db:
            if await run_in_threadpool(db.query(Permission).filter(Permission.name == name).first):
                raise ValueError(f"Permission with name '{name}' already exists.")
            new_perm = Permission(name=name, description=description)
            db.add(new_perm)
            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, new_perm)
            return new_perm


class SessionManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_id(self, session_id: str) -> Optional[DBSession]:
        with self._db_manager.get_context_manager_db() as db:
            return await run_in_threadpool(db.query(DBSession).filter(DBSession.session_id == session_id).first)

    async def create(self, user_id: str, ip_address: str, region: str, device: str) -> DBSession:
        with self._db_manager.get_context_manager_db() as db:
            session = DBSession(
                session_id=encryption_utils.gen_random_string(32), user_id=user_id,
                create_ip=ip_address, last_ip=ip_address, region=region, device=device
            )
            db.add(session)
            # Log the event *inside* the transaction block
            self._db_manager.log_audit_event(user_id, "SESSION_CREATED", ip_address,
                                             {"device": device, "region": region}, db=db)
            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, session)
            return session

    async def terminate(self, session_id: str, ip_address: str, errors="ignore"):
        with self._db_manager.get_context_manager_db() as db:
            session = await run_in_threadpool(db.query(DBSession).filter(DBSession.session_id == session_id).first)
            if session:
                session.terminate(ip_address, self._db_manager, db)
                await run_in_threadpool(db.commit)
                return True
            if errors == "ignore": return False
            raise SessionNotFoundError("Session not found.")

    async def terminate_all_for_user(self, user_id: str, ip_address: str, except_session_id: Optional[str] = None):
        with self._db_manager.get_context_manager_db() as db:
            query = db.query(DBSession).filter(DBSession.user_id == user_id, DBSession.active == True)
            if except_session_id:
                query = query.filter(DBSession.session_id != except_session_id)
            sessions_to_terminate = await run_in_threadpool(query.all)
            for session in sessions_to_terminate:
                session.active = False

            self._db_manager.log_audit_event(user_id, "SESSIONS_TERMINATED_ALL", ip_address,
                                             {"except": except_session_id}, db=db)
            await run_in_threadpool(db.commit)


class TokenManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def create(self, user_id: str, purpose: str, expiry_seconds: Optional[int] = None) -> Token:
        with self._db_manager.get_context_manager_db() as db:
            expiry = expiry_seconds or settings.TOKENS_EXPIRY_SECONDS
            token = Token(id=encryption_utils.gen_random_string(32), purpose=purpose, user_id=user_id,
                          etime=time.time() + expiry)
            db.add(token)
            await run_in_threadpool(db.commit)
            await run_in_threadpool(db.refresh, token)
            return token

    async def validate(self, db: Session, token_id: str, purpose: str, ip_address: str) -> User:
        token_obj = await run_in_threadpool(
            db.query(Token).filter(Token.id == token_id, Token.purpose == purpose).first)
        if not token_obj: raise InvalidTokenError("Invalid token.")
        if token_obj.used: raise InvalidTokenError("Token has already been used.")
        user = await run_in_threadpool(db.query(User).filter(User.id == token_obj.user_id).first)
        if not user: raise InvalidTokenError("Token is not associated with a valid user.")
        if not token_obj.is_valid():
            new_token = await self.create(user.id, purpose)
            token_obj.mark_used(ip_address, self._db_manager, db)
            raise TokenExpiredError("Token expired. A new one has been generated.", new_token_id=new_token.id)
        token_obj.mark_used(ip_address, self._db_manager, db)
        return user


class AuthTunaAsync:
    """High-level facade for all authentication and authorization operations."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.users = UserManager(db_manager)
        self.roles = RoleManager(db_manager)
        self.permissions = PermissionManager(db_manager)
        self.sessions = SessionManager(db_manager)
        self.tokens = TokenManager(db_manager)

    async def signup(self, username: str, email: str, password: str, ip_address: str) -> Tuple[User, Optional[Token]]:
        user = await self.users.create(
            email=email, username=username, password=password, ip_address=ip_address,
            email_verified=not settings.EMAIL_ENABLED
        )
        token = None
        if settings.EMAIL_ENABLED:
            token = await self.tokens.create(user.id, "email_verification")
        return user, token

    async def login(self, username_or_email: str, password: str, ip_address: str, region: str, device: str) -> Tuple[
        User, DBSession]:
        with self.db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(
                db.query(User).filter(
                    (User.email == username_or_email) | (User.username == username_or_email)
                ).first()
            )
            if not user or not user.check_password(password, ip_address, self.db_manager, db):
                raise InvalidCredentialsError("Incorrect username/email or password.")

            if settings.EMAIL_ENABLED and not getattr(user, 'email_verified', True):
                raise EmailNotVerifiedError("Email Not Verified.")

            # Commit the login audit event from check_password
            await run_in_threadpool(db.commit)

            session = await self.sessions.create(user.id, ip_address, region, device)
            return user, session

    async def request_password_reset(self, email: str) -> Optional[Token]:
        with self.db_manager.get_context_manager_db() as db:
            user = await run_in_threadpool(db.query(User).filter(User.email == email).first())
            if not user: return None
            recent_tokens = await run_in_threadpool(
                db.query(Token).filter(
                    Token.user_id == user.id, Token.purpose == "password_reset", Token.ctime > time.time() - 86400
                ).count
            )
            if recent_tokens >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
                raise RateLimitError("Too many password reset requests.")
            return await self.tokens.create(user.id, "password_reset")

    async def reset_password(self, token_id: str, new_password: str, ip_address: str) -> User:
        """
        FIXED: Performs token validation and password reset in a single atomic transaction.
        """
        with self.db_manager.get_context_manager_db() as db:
            user = await self.tokens.validate(db, token_id, "password_reset", ip_address)
            user.set_password(new_password, ip_address, self.db_manager, db)
            await run_in_threadpool(db.commit)
            return user

    async def verify_email(self, token_id: str, ip_address: str) -> User:
        """
        FIXED: Performs email verification in a single atomic transaction.
        """
        with self.db_manager.get_context_manager_db() as db:
            user = await self.tokens.validate(db, token_id, "email_verification", ip_address)
            if not getattr(user, 'email_verified', False):
                user.email_verified = True
            await run_in_threadpool(db.commit)
            return user

