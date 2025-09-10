import time
from typing import Optional, Tuple, List, Dict, Any

import pyotp
from sqlalchemy import or_, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from authtuna.core.config import settings
from authtuna.core.database import (
    DatabaseManager, User, Role, Permission, DeletedUser,
    Session as DBSession, Token, user_roles_association, role_permissions_association, Session
)
from authtuna.core.encryption import encryption_utils
from authtuna.core.exceptions import (
    UserAlreadyExistsError, InvalidCredentialsError, EmailNotVerifiedError,
    InvalidTokenError, TokenExpiredError, RateLimitError, UserNotFoundError,
    SessionNotFoundError, RoleNotFoundError, PermissionNotFoundError
)
from authtuna.core.mfa import MFAManager


class UserManager:
    """Manages all CRUD and business logic operations related to Users, asynchronously."""

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_id(self, user_id: str, with_relations: bool = True, db: AsyncSession = None) -> Optional[User]:
        if db:
            stmt = select(User).where(User.id == user_id)
            if with_relations:
                stmt = stmt.options(joinedload(User.roles).joinedload(Role.permissions))
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()
        async with self._db_manager.get_db() as db:
            stmt = select(User).where(User.id == user_id)
            if with_relations:
                stmt = stmt.options(joinedload(User.roles).joinedload(Role.permissions))
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        async with self._db_manager.get_db() as db:
            stmt = select(User).where(User.email == email)
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()

    async def get_by_username(self, username: str) -> Optional[User]:
        async with self._db_manager.get_db() as db:
            stmt = select(User).where(User.username == username)
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()

    async def list(self, skip: int = 0, limit: int = 100) -> List[User]:
        async with self._db_manager.get_db() as db:
            stmt = select(User).offset(skip).limit(limit)
            result = await db.execute(stmt)
            return list(result.scalars().all())

    async def create(self, email: str, username: str, password: Optional[str] = None, ip_address: str = 'system',
                     **kwargs) -> User:
        """Creates a user, sets password, and logs audit event in a single atomic transaction."""
        async with self._db_manager.get_db() as db:
            stmt = select(User).where((User.email == email) | (User.username == username))
            existing_user = (await db.execute(stmt)).unique().scalar_one_or_none()
            if existing_user:
                raise UserAlreadyExistsError("A user with this email or username already exists.")

            new_user = User(
                id=encryption_utils.gen_random_string(32), email=email, username=username, **kwargs
            )
            db.add(new_user)

            if password:
                await new_user.set_password(password, ip_address, self._db_manager, db)

            await self._db_manager.log_audit_event(
                new_user.id, "USER_CREATED", ip_address,
                {"by": "system" if ip_address == 'system' else 'user_signup'}, db=db
            )

            await db.commit()
            await db.refresh(new_user)
            return new_user

    async def update(self, user_id: str, update_data: Dict[str, Any], ip_address: str = 'system') -> User:
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user:
                raise UserNotFoundError("User not found.")

            for key, value in update_data.items():
                if hasattr(user, key) and key not in ['id', 'password_hash']:
                    setattr(user, key, value)

            await self._db_manager.log_audit_event(user_id, "USER_UPDATED", ip_address,
                                                   {"fields_changed": list(update_data.keys())}, db=db)
            await db.commit()
            await db.refresh(user)
            return user

    async def delete(self, user_id: str, ip_address: str = 'system') -> None:
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user:
                raise UserNotFoundError("User not found.")

            user_data = {c.name: getattr(user, c.name) for c in user.__table__.columns}
            archived_user = DeletedUser(user_id=user.id, email=user.email, data=user_data)
            db.add(archived_user)

            await db.delete(user)
            await self._db_manager.log_audit_event(user_id, "USER_DELETED", ip_address, {"archived": True}, db=db)
            await db.commit()

    async def set_password(self, user_id: str, new_password: str, ip_address: str):
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user:
                raise UserNotFoundError("User not found.")
            await user.set_password(new_password, ip_address, self._db_manager, db)
            await db.commit()


class RoleManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'global'):
        async with self._db_manager.get_db() as db:
            user_stmt = select(User).where(User.id == user_id)
            user = (await db.execute(user_stmt)).unique().scalar_one_or_none()
            if not user: raise UserNotFoundError("User not found.")

            role_stmt = select(Role).where(Role.name == role_name)
            role = (await db.execute(role_stmt)).unique().scalar_one_or_none()
            if not role: raise RoleNotFoundError(f"Role '{role_name}' not found.")

            assoc_stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role.id,
                user_roles_association.c.scope == scope
            )
            if (await db.execute(assoc_stmt)).first():
                return

            insert_stmt = user_roles_association.insert().values(
                user_id=user.id, role_id=role.id, scope=scope,
                given_by_id=assigner_id, given_at=time.time()
            )
            await db.execute(insert_stmt)
            await self._db_manager.log_audit_event(user_id, "ROLE_ASSIGNED", "system",
                                                   {"role": role_name, "scope": scope, "by": assigner_id}, db=db)
            await db.commit()

    async def get_by_name(self, name: str) -> Optional[Role]:
        async with self._db_manager.get_db() as db:
            stmt = select(Role).where(Role.name == name)
            return (await db.execute(stmt)).unique().scalar_one_or_none()

    async def get_or_create(self, name: str, defaults: dict = None) -> Tuple[Role, bool]:
        role = await self.get_by_name(name)
        if role: return role, False
        new_role = await self.create(name, **(defaults or {}))
        return new_role, True

    async def create(self, name: str, description: str = "", system: bool = False) -> Role:
        async with self._db_manager.get_db() as db:
            if await self.get_by_name(name):
                raise ValueError(f"Role with name '{name}' already exists.")
            new_role = Role(name=name, description=description, system=system)
            db.add(new_role)
            await db.commit()
            await db.refresh(new_role)
            return new_role

    async def add_permission_to_role(self, role_name: str, permission_name: str, adder_id: Optional[str] = None):
        async with self._db_manager.get_db() as db:
            role = await self.get_by_name(role_name)
            if not role: raise RoleNotFoundError(f"Role '{role_name}' not found.")

            perm_stmt = select(Permission).where(Permission.name == permission_name)
            permission = (await db.execute(perm_stmt)).unique().scalar_one_or_none()
            if not permission: raise PermissionNotFoundError(f"Permission '{permission_name}' not found.")

            assoc_stmt = select(role_permissions_association).where(
                role_permissions_association.c.role_id == role.id,
                role_permissions_association.c.permission_id == permission.id
            )
            if (await db.execute(assoc_stmt)).first(): return

            insert_stmt = role_permissions_association.insert().values(
                role_id=role.id, permission_id=permission.id, added_by_id=adder_id, added_at=time.time()
            )
            await db.execute(insert_stmt)
            await db.commit()

    async def get_user_roles_with_scope(self, user_id: str) -> List[dict]:
        async with self._db_manager.get_db() as db:
            stmt = select(Role.name, user_roles_association.c.scope).join_from(
                user_roles_association, Role, user_roles_association.c.role_id == Role.id
            ).where(user_roles_association.c.user_id == user_id)
            results = (await db.execute(stmt)).all()
            return [{"role_name": row[0], "scope": row[1]} for row in results]

    async def has_permission(self, user_id: str, permission_name: str, scope_prefix: Optional[str] = None) -> bool:
        async with self._db_manager.get_db() as db:
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
            result = (await db.execute(stmt)).first()
            return result is not None


class PermissionManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_name(self, name: str) -> Optional[Permission]:
        async with self._db_manager.get_db() as db:
            stmt = select(Permission).where(Permission.name == name)
            return (await db.execute(stmt)).unique().scalar_one_or_none()

    async def get_or_create(self, name: str, defaults: dict = None) -> Tuple[Permission, bool]:
        perm = await self.get_by_name(name)
        if perm: return perm, False
        new_perm = await self.create(name, **(defaults or {}))
        return new_perm, True

    async def create(self, name: str, description: str = "") -> Permission:
        async with self._db_manager.get_db() as db:
            if await self.get_by_name(name):
                raise ValueError(f"Permission with name '{name}' already exists.")
            new_perm = Permission(name=name, description=description)
            db.add(new_perm)
            await db.commit()
            await db.refresh(new_perm)
            return new_perm


class SessionManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_id(self, session_id: str) -> Optional[DBSession]:
        async with self._db_manager.get_db() as db:
            stmt = select(DBSession).where(DBSession.session_id == session_id)
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()

    async def create(self, user_id: str, ip_address: str, region: str, device: str) -> DBSession:
        async with self._db_manager.get_db() as db:
            session = DBSession(
                session_id=encryption_utils.gen_random_string(32), user_id=user_id,
                create_ip=ip_address, last_ip=ip_address, region=region, device=device
            )
            db.add(session)
            await self._db_manager.log_audit_event(user_id, "SESSION_CREATED", ip_address,
                                                   {"device": device, "region": region}, db=db)
            await db.commit()
            await db.refresh(session)
            return session

    async def terminate(self, session_id: str, ip_address: str, errors="ignore"):
        async with self._db_manager.get_db() as db:
            stmt = select(DBSession).where(DBSession.session_id == session_id)
            session = (await db.execute(stmt)).unique().scalar_one_or_none()
            if session:
                await session.terminate(ip_address, self._db_manager, db)
                await db.commit()
                return True
            if errors == "ignore": return False
            raise SessionNotFoundError("Session not found.")

    async def terminate_all_for_user(self, user_id: str, ip_address: str, except_session_id: Optional[str] = None):
        async with self._db_manager.get_db() as db:
            stmt = select(DBSession).where(DBSession.user_id == user_id, DBSession.active == True)
            if except_session_id:
                stmt = stmt.where(DBSession.session_id != except_session_id)
            sessions_to_terminate = (await db.execute(stmt)).scalars().all()
            for session in sessions_to_terminate:
                session.active = False

            await self._db_manager.log_audit_event(user_id, "SESSIONS_TERMINATED_ALL", ip_address,
                                                   {"except": except_session_id}, db=db)
            await db.commit()

    async def get_all_for_user(self, user_id: str, session_id: str) -> List[DBSession]:
        async with self._db_manager.get_db() as db:
            stmt = select(DBSession).where(DBSession.user_id == user_id)
            all_sessions = (await db.execute(stmt)).scalars().all()
            for session in all_sessions:
                if session.session_id == session_id:
                    session.active = True
                    break
            return all_sessions

class TokenManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def create(self, user_id: str, purpose: str, expiry_seconds: Optional[int] = None) -> Token:
        async with self._db_manager.get_db() as db:
            expiry = expiry_seconds or settings.TOKENS_EXPIRY_SECONDS
            token = Token(id=encryption_utils.gen_random_string(32), purpose=purpose, user_id=user_id,
                          etime=time.time() + expiry)
            db.add(token)
            await db.commit()
            await db.refresh(token)
            return token

    async def validate(self, db: AsyncSession, token_id: str, purpose: str, ip_address: str) -> User:
        stmt = select(Token).where(Token.id == token_id, Token.purpose == purpose).options(joinedload(Token.user).joinedload(User.mfa_methods))
        token_obj = (await db.execute(stmt)).unique().scalar_one_or_none()
        if not token_obj: raise InvalidTokenError("Invalid token.")
        if token_obj.used: raise InvalidTokenError("Token has already been used.")
        user_stmt = select(User).where(User.id == token_obj.user_id)
        user = (await db.execute(user_stmt)).unique().scalar_one_or_none()
        if not user: raise InvalidTokenError("Token is not associated with a valid user.")

        if not token_obj.is_valid():
            new_token = await self.create(user.id, purpose)
            await token_obj.mark_used(ip_address, self._db_manager, db)
            raise TokenExpiredError("Token expired. Reload Page.", new_token_id=new_token.id)

        await token_obj.mark_used(ip_address, self._db_manager, db)
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
        self.mfa = MFAManager(db_manager)

    async def signup(self, username: str, email: str, password: str, ip_address: str) -> Tuple[User, Optional[Token]]:
        user = await self.users.create(
            email=email, username=username, password=password, ip_address=ip_address,
            email_verified=not settings.EMAIL_ENABLED
        )
        token = None
        if settings.EMAIL_ENABLED:
            token = await self.tokens.create(user.id, "email_verification")
        return user, token

    async def login(self, username_or_email: str, password: str, ip_address: str, region: str, device: str) -> tuple[
                                                                                                                   Any, Token] | \
                                                                                                               tuple[
                                                                                                                   Any, Session]:
        async with self.db_manager.get_db() as db:
            stmt = select(User).where((User.email == username_or_email) | (User.username == username_or_email))
            user = (await db.execute(stmt)).unique().scalar_one_or_none()
            password_valid = await user.check_password(password, ip_address, self.db_manager, db)
            if not user or password_valid is False:
                raise InvalidCredentialsError("Incorrect username/email or password.")
            elif password_valid is None:
                raise EmailNotVerifiedError("Email Not Verified.")
            elif password_valid is True:
                pass
            else:
                raise InvalidCredentialsError("Incorrect username/email or password (config error).")
            await db.commit()
            if user.mfa_enabled:
                return user, await self.tokens.create(user.id, "mfa_validation", expiry_seconds=300)
            else:
                return user, await self.sessions.create(user.id, ip_address, region, device)

    async def request_password_reset(self, email: str) -> Optional[Token]:
        async with self.db_manager.get_db() as db:
            user = await self.users.get_by_email(email)
            if not user: return None

            count_stmt = select(func.count()).select_from(Token).where(
                Token.user_id == user.id,
                Token.purpose == "password_reset",
                Token.ctime > time.time() - 86400
            )
            recent_tokens_count = (await db.execute(count_stmt)).scalar()

            if recent_tokens_count >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
                raise RateLimitError("Too many password reset requests.")

            return await self.tokens.create(user.id, "password_reset")

    async def reset_password(self, token_id: str, new_password: str, ip_address: str) -> User:
        """Performs token validation and password reset in a single atomic transaction."""
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, token_id, "password_reset", ip_address)
            await user.set_password(new_password, ip_address, self.db_manager, db)
            await db.commit()
            return user

    async def verify_email(self, token_id: str, ip_address: str) -> User:
        """Performs email verification in a single atomic transaction."""
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, token_id, "email_verification", ip_address)
            if not getattr(user, 'email_verified', False):
                user.email_verified = True
            await db.commit()
            return user

    async def validate_mfa_login(self, mfa_token: str, code: str, ip_address: str, device_data: dict) -> DBSession:
        """
        Handles the second step of an MFA login within a single transaction.
        """
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, mfa_token, "mfa_validation", ip_address)

            user_with_mfa = await self.users.get_by_id(user.id, with_relations=True, db=db)
            if not user_with_mfa or not user_with_mfa.mfa_methods:
                raise InvalidTokenError("MFA is not configured correctly for this user.")

            # Assuming one TOTP method for now
            totp_method = next((m for m in user_with_mfa.mfa_methods if m.method_type == 'totp'), None)
            if not totp_method or not totp_method.secret:
                raise InvalidTokenError("TOTP secret not found.")
            totp = pyotp.TOTP(totp_method.secret)
            is_valid_code = totp.verify(code)
            is_valid_recovery = False
            if not is_valid_code:
                is_valid_recovery = await self.mfa.verify_recovery_code(user, code, db)
            if not is_valid_code and not is_valid_recovery:
                raise InvalidTokenError("Invalid MFA code.")

            await db.commit()
        session = await self.sessions.create(
                user.id, ip_address, device_data["region"], device_data["device"]
        )
        return session

