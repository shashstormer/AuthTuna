import datetime
import time
from typing import Optional, Tuple, List, Dict, Any, Union, Literal

import pyotp
from sqlalchemy import or_, select, func, delete, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from authtuna.core.config import settings
from authtuna.core.database import (
    DatabaseManager, User, Role, Permission, DeletedUser,
    Session as DBSession, Token, user_roles_association, role_permissions_association, Session, AuditEvent,
    PasskeyCredential, Organization, Team, organization_members, team_members, ApiKey, ApiKeyScope
)
from authtuna.core.encryption import encryption_utils
from authtuna.core.exceptions import (
    UserAlreadyExistsError, InvalidCredentialsError, EmailNotVerifiedError,
    InvalidTokenError, TokenExpiredError, RateLimitError, UserNotFoundError,
    SessionNotFoundError, RoleNotFoundError, PermissionNotFoundError, OperationForbiddenError
)
from authtuna.core.mfa import MFAManager
from authtuna.core.passkeys import PasskeysCore
from authtuna.helpers import is_email_valid, is_permission_name_valid
from authtuna.helpers.mail import email_manager


class UserManager:
    """Manages all CRUD and business logic operations related to Users, asynchronously."""

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_by_id(self, user_id: str, with_relations: bool = True, db: AsyncSession = None) -> Optional[User]:
        async def _get(session: AsyncSession):
            stmt = select(User).where(User.id == user_id)
            if with_relations:
                stmt = stmt.options(
                    selectinload(User.roles).selectinload(Role.permissions),
                    selectinload(User.roles).selectinload(Role.can_assign_roles)
                )
            result = await session.execute(stmt)
            return result.unique().scalar_one_or_none()

        if db:
            return await _get(db)
        async with self._db_manager.get_db() as db:
            return await _get(db)

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
            result = (await db.execute(stmt)).unique()
            return list(result.scalars().all())

    async def create(self, email: str, username: str, password: Optional[str] = None, ip_address: str = 'system',
                     **kwargs) -> User:
        """Creates a user, sets password, and logs audit event in a single atomic transaction."""
        await is_email_valid(email)
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
                if hasattr(user, key) and key in ['username', 'email']:
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
            await self._db_manager.log_audit_event("system", "USER_DELETED", ip_address, {"archived": True}, db=db)
            await db.commit()

    async def set_password(self, user_id: str, new_password: str, ip_address: str):
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user:
                raise UserNotFoundError("User not found.")
            await user.set_password(new_password, ip_address, self._db_manager, db)
            await db.commit()

    async def suspend_user(self, user_id: str, admin_id: str, reason: str = "No reason provided.") -> User:
        """Suspends a user, preventing them from logging in."""
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user: raise UserNotFoundError("User not found.")
            user.is_active = False
            await self._db_manager.log_audit_event(
                user_id, "USER_SUSPENDED", "system", {"by": admin_id, "reason": reason}, db=db
            )
            await db.commit()
            await db.refresh(user)
            return user

    async def unsuspend_user(self, user_id: str, admin_id: str, reason: str = "No reason provided.") -> User:
        """Reactivates a suspended user."""
        async with self._db_manager.get_db() as db:
            user = await db.get(User, user_id)
            if not user: raise UserNotFoundError("User not found.")
            user.is_active = True
            await self._db_manager.log_audit_event(
                user_id, "USER_UNSUSPENDED", "system", {"by": admin_id, "reason": reason}, db=db
            )
            await db.commit()
            await db.refresh(user)
            return user

    # function to search users with filtering by email or username or roles he has or scopes he has
    async def search_users(
            self,
            *,
            identity: Optional[str] = None,
            role: Optional[str] = None,
            scope: Optional[str] = None,
            is_active: Optional[bool] = None,
            skip: int = 0,
            limit: int = 100
    ) -> List[User]:
        """
        Provides advanced, flexible filtering for users based on specific criteria.
        All filter parameters are optional and are combined with AND logic.
        """
        async with self._db_manager.get_db() as db:
            stmt = select(User)
            filters = []

            if identity:
                filters.append(or_(
                    User.email == identity,
                    User.username.ilike(f"%{identity}%")
                ))
            if is_active is not None:
                filters.append(User.is_active == is_active)

            if role or scope:
                stmt = stmt.join(user_roles_association).join(Role)
                if role:
                    filters.append(Role.name.ilike(f"%{role}%"))
                if scope:
                    filters.append(user_roles_association.c.scope.ilike(f"%{scope}%"))

            if filters:
                stmt = stmt.where(*filters)

            stmt = stmt.offset(skip).limit(limit).distinct()
            result = await db.execute(stmt)
            return list(result.unique().scalars().all())

    async def basic_search_users(self, *, identity: Optional[str] = None, skip: int = 0, limit: int = 100) -> List[
        Dict[str, str]]:
        """
        Provides basic filtering for users based on username or email.
        This function readcts the email for privacy and gives only username and userid.
        This function can be used to implement a search user route in your codebase.
        """
        users = await self.search_users(identity=identity, skip=skip, limit=limit)
        basic_users = []
        if users:
            for user in users:
                basic_users.append({
                    "user_id": user.id,
                    "username": user.username,
                })
        return basic_users


class RoleManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_all_roles(self) -> List[Role]:
        """Fetches all roles from the database."""
        async with self._db_manager.get_db() as db:
            stmt = select(Role).order_by(Role.level.desc().nullslast(), Role.name)
            result = await db.execute(stmt)
            return list(result.unique().scalars().all())

    async def get_assignable_roles_for_user(self, target_user_id: str, assigning_user: User) -> List[Role]:
        """
        Determines which roles an admin can assign, preventing privilege escalation.
        This function correctly checks all three authorization pathways:
        1. Direct permission override (e.g., 'roles:assign:SomeRole').
        2. Direct role-to-role assignment grants.
        3. Role level hierarchy (admin's level must be higher).
        """
        async with self._db_manager.get_db() as db:
            target_user = await db.get(User, target_user_id)
            if not target_user:
                raise UserNotFoundError("Target user not found.")
            all_roles = await self.get_all_roles()
            admin_max_level = -1
            if assigning_user.roles:
                admin_max_level = max(
                    (role.level for role in assigning_user.roles if role.level is not None),
                    default=-1
                )
            assignable_roles = []
            for role_to_check in all_roles:
                has_sufficient_level = False
                if role_to_check.level is not None and admin_max_level > role_to_check.level:
                    has_sufficient_level = True
                has_direct_grant = False
                for admin_role in assigning_user.roles:
                    if any(assignable.id == role_to_check.id for assignable in admin_role.can_assign_roles):
                        has_direct_grant = True
                        break
                required_permission = f"roles:assign:{role_to_check.name}"
                has_permission_override = await self.has_permission(assigning_user.id, required_permission, db=db)
                if has_sufficient_level or has_direct_grant or has_permission_override:
                    assignable_roles.append(role_to_check)
            return assignable_roles

    async def get_permission_scopes(self, user_id: str, permission_name: str, db: AsyncSession) -> List[str]:
        """
        Retrieves all scopes in which a user has a specific permission.
        """
        stmt = select(user_roles_association.c.scope).distinct().join_from(
            user_roles_association, Role, user_roles_association.c.role_id == Role.id
        ).join(
            role_permissions_association, Role.id == role_permissions_association.c.role_id
        ).join(
            Permission, role_permissions_association.c.permission_id == Permission.id
        ).where(
            user_roles_association.c.user_id == user_id,
            Permission.name == permission_name
        )
        result = await db.execute(stmt)
        return [row[0] for row in result.all()]

    async def get_role_scopes(self, user_id: str, role_name: str, db: AsyncSession) -> List[str]:
        """
        Retrieves all scopes in which a user has a specific role.
        Uses the provided AsyncSession (no new transaction/context manager).
        Returns a list of scope strings (may include 'global').
        """
        stmt = select(user_roles_association.c.scope).distinct().join_from(
            user_roles_association, Role, user_roles_association.c.role_id == Role.id
        ).where(
            user_roles_association.c.user_id == user_id,
            Role.name == role_name
        )
        result = await db.execute(stmt)
        return [row[0] for row in result.all()]

    async def get_self_assignable_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Returns a list of roles the current user can assign to themselves,
        including the scopes in which they can assign them.
        """
        async with self._db_manager.get_db() as db:
            user = await UserManager(self._db_manager).get_by_id(user_id, with_relations=True, db=db)
            if not user:
                return []

            all_roles = await self.get_all_roles()
            final_assignable_roles = []
            user_max_level = -1
            if user.roles:
                user_max_level = max((r.level for r in user.roles if r.level is not None), default=-1)

            for role in all_roles:
                assignable_scopes = set()

                # Pathway 1: Check for specific permission override and get its scopes
                required_permission = f"roles:assign:{role.name}"
                permission_scopes = await self.get_permission_scopes(user.id, required_permission, db)
                for scope in permission_scopes:
                    assignable_scopes.add(scope)

                # Pathways 2 & 3 are generally not scope-specific; they grant the ability to assign globally.
                is_authorized_globally = False

                # Pathway 2: Check for direct role assignment grant
                for user_role in user.roles:
                    if any(assignable.id == role.id for assignable in user_role.can_assign_roles):
                        is_authorized_globally = True
                        break

                if not is_authorized_globally:
                    # Pathway 3: Check role level hierarchy
                    if role.level is not None and user_max_level > role.level:
                        is_authorized_globally = True

                # If authorized globally (by hierarchy or direct grant), add 'global' scope.
                if is_authorized_globally:
                    assignable_scopes.add("global")

                # If we found any scopes for this role, add it to our results.
                if assignable_scopes:
                    final_assignable_roles.append({
                        "name": role.name,
                        "description": role.description,
                        "scopes": sorted(list(assignable_scopes))  # Sort for consistent output
                    })

        return final_assignable_roles

    async def get_users_for_role(self, role_name: str, scope: str = None) -> List[Dict[str, str]]:
        """Fetches all users who have a given role, along with the scope."""
        async with self._db_manager.get_db() as db:
            role = await self.get_by_name(role_name)
            if not role:
                return []
            stmt = select(User.username, user_roles_association.c.scope).join_from(
                user_roles_association, User, user_roles_association.c.user_id == User.id
            ).where(user_roles_association.c.role_id == role.id)
            if scope is not None:
                stmt = stmt.where(
                    user_roles_association.c.scope == scope,
                )
            results = (await db.execute(stmt)).all()
            return [{"username": row[0], "scope": row[1]} for row in results]

    async def _is_authorized_to_manage_role(self, manager_user: User, role_to_manage: Role, target_scope: str,
                                            db: AsyncSession) -> bool:
        """
        Private helper to check the 3 authorization pathways for role assignment.
        Now includes scope validation to prevent scope escalation.

        Args:
            manager_user: The user attempting to assign/revoke the role
            role_to_manage: The role being assigned/revoked
            target_scope: The scope in which the role is being assigned/revoked
            db: Database session

        Returns:
            True if authorized, False otherwise
        """
        # Pathway 1: Permission Override
        required_permission = f"roles:assign:{role_to_manage.name}"
        if await self.has_permission(manager_user.id, required_permission, scope_prefix=target_scope, db=db):
            return True

        # Pathway 2: Direct Grant
        for manager_role in manager_user.roles:
            if any(assignable.id == role_to_manage.id for assignable in manager_role.can_assign_roles):
                # Check if the manager has this role in a scope that encompasses the target scope
                manager_role_scopes = await self.get_role_scopes(manager_user.id, manager_role.name, db)

                # Check if manager has global scope or matching/parent scope
                if 'global' in manager_role_scopes:
                    return True

                # Check if target scope is covered by any of manager's scopes
                for manager_scope in manager_role_scopes:
                    if target_scope == manager_scope or target_scope.startswith(f"{manager_scope}/"):
                        return True

        # Pathway 3: Level Hierarchy
        if manager_user.roles:
            manager_max_level = max((role.level for role in manager_user.roles if role.level is not None), default=-1)
            if role_to_manage.level is not None and manager_max_level > role_to_manage.level:
                # Even with sufficient level, verify scope coverage
                stmt = select(user_roles_association.c.scope).where(
                    user_roles_association.c.user_id == manager_user.id
                )
                result = await db.execute(stmt)
                manager_scopes = [row[0] for row in result.all()]

                if 'global' in manager_scopes:
                    return True

                for manager_scope in manager_scopes:
                    if target_scope == manager_scope or target_scope.startswith(f"{manager_scope}/"):
                        return True

        return False

    async def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'none', db=None):
        async def _main(db):
            user_manager = UserManager(self._db_manager)
            assigner = await user_manager.get_by_id(assigner_id, with_relations=True, db=db)
            if not assigner:
                raise UserNotFoundError("Assigner user not found.")

            role_to_assign = await self.get_by_name(role_name, db=db)
            if not role_to_assign:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # Pass scope to authorization check
            can_manage_role = await self._is_authorized_to_manage_role(assigner, role_to_assign, scope, db)
            if not can_manage_role:
                raise OperationForbiddenError(
                    "You lack the required permission, direct grant, or sufficient role level/scope to assign this role."
                )

            target_user = await user_manager.get_by_id(user_id, db=db)
            if not target_user:
                raise UserNotFoundError("Target user not found.")

            assoc_stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role_to_assign.id,
                user_roles_association.c.scope == scope
            )
            if (await db.execute(assoc_stmt)).first():
                return

            insert_stmt = user_roles_association.insert().values(
                user_id=target_user.id, role_id=role_to_assign.id, scope=scope,
                given_by_id=assigner_id, given_at=time.time()
            )
            await db.execute(insert_stmt)
            await self._db_manager.log_audit_event(
                user_id, "ROLE_ASSIGNED", "system",
                {"role": role_name, "scope": scope, "by": assigner_id}, db=db
            )

        if db:
            await _main(db)
        else:
            async with self._db_manager.get_db() as db:
                await _main(db)
                await db.commit()

    async def remove_from_user(self, user_id: str, role_name: str, remover_id: str, scope: str = 'none',
                               db: AsyncSession = None):
        async def _remove(db):
            user_manager = UserManager(self._db_manager)
            remover = await user_manager.get_by_id(remover_id, with_relations=True, db=db)
            if not remover:
                raise UserNotFoundError("Remover user not found.")

            role_to_remove = await self.get_by_name(role_name, db=db)
            if not role_to_remove:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # Pass scope to authorization check
            can_manage_role = await self._is_authorized_to_manage_role(remover, role_to_remove, scope, db)
            if not can_manage_role:
                raise OperationForbiddenError(
                    "You lack the required permission, direct grant, or sufficient role level/scope to remove this role."
                )

            target_user = await user_manager.get_by_id(user_id, db=db)
            if not target_user:
                raise UserNotFoundError("Target user not found.")

            assoc_stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role_to_remove.id,
                user_roles_association.c.scope == scope,
            )
            if (await db.execute(assoc_stmt)).first():
                delete_stmt = user_roles_association.delete().where(
                    user_roles_association.c.user_id == user_id,
                    user_roles_association.c.role_id == role_to_remove.id,
                    user_roles_association.c.scope == scope,
                )
                await db.execute(delete_stmt)
                await self._db_manager.log_audit_event(
                    user_id, "ROLE_REMOVED", "system",
                    {"role": role_name, "scope": scope, "by": remover_id}, db=db
                )
            else:
                raise RoleNotFoundError(f"Role '{role_name}' not found for this user in scope '{scope}'.")

        if db:
            await _remove(db)
        else:
            async with self._db_manager.get_db() as session:
                await _remove(session)
                await session.commit()

    async def get_by_name(self, name: str, db=None) -> Optional[Role]:
        async def _get(db):
            stmt = select(Role).where(Role.name == name).options(selectinload(Role.can_assign_roles))
            return (await db.execute(stmt)).unique().scalar_one_or_none()
        if db:
            return await _get(db)
        async with self._db_manager.get_db() as db:
            return await _get(db)

    async def get_by_id(self, role_id: str) -> Optional[Role]:
        async with self._db_manager.get_db() as db:
            stmt = select(Role).where(Role.id == role_id).options(selectinload(Role.can_assign_roles))
            return (await db.execute(stmt)).unique().scalar_one_or_none()

    async def get_or_create(self, name: str, defaults: dict = None) -> Tuple[Role, bool]:
        role = await self.get_by_name(name)
        if role: return role, False
        new_role = await self.create(name, **(defaults or {}))
        return new_role, True

    async def create(self, name: str, description: str = "", system: bool = False, level: Optional[int] = None) -> Role:
        async with self._db_manager.get_db() as db:
            if await self.get_by_name(name):
                raise ValueError(f"Role with name '{name}' already exists.")
            new_role = Role(name=name, description=description, system=system, level=level)
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

    async def grant_relationship(self, granter_role_name: str, grantable_name: str,
                                 grantable_manager: Union["RoleManager", "Permission"], relationship_attr: Literal["can_assign_roles", "Permission"] = "can_assign_roles", db_override: AsyncSession = None):
        async def _action(db: AsyncSession):
            granter_role = await self.get_by_name(granter_role_name)
            if not granter_role:
                raise RoleNotFoundError(f"Granter role '{granter_role_name}' not found.")

            grantable_item = await grantable_manager.get_by_name(grantable_name)
            if not grantable_item:
                item_type = "Role" if relationship_attr == "can_assign_roles" else "Permission"
                raise RoleNotFoundError(f"{item_type} '{grantable_name}' not found.")

            relationship_list = getattr(granter_role, relationship_attr)
            if grantable_item not in relationship_list:
                relationship_list.append(grantable_item)
                await db.merge(granter_role)
                await db.commit()
            return granter_role, grantable_item

        if db_override:
            return await _action(db_override)
        async with self._db_manager.get_db() as _db:
            return await _action(_db)

    async def get_user_roles_with_scope(self, user_id: str) -> List[dict]:
        async with self._db_manager.get_db() as db:
            stmt = select(Role.name, user_roles_association.c.scope).join_from(
                user_roles_association, Role, user_roles_association.c.role_id == Role.id
            ).where(user_roles_association.c.user_id == user_id)
            results = (await db.execute(stmt)).all()
            return [{"role_name": row[0], "scope": row[1]} for row in results]

    async def get_user_roles(self, user_id: str, scope: Optional[str] = None, db: AsyncSession = None) -> List[Role]:
        """Get user roles, optionally filtered by scope."""
        async def _get(session: AsyncSession):
            stmt = select(Role).join(
                user_roles_association, Role.id == user_roles_association.c.role_id
            ).where(user_roles_association.c.user_id == user_id)

            if scope is not None:
                stmt = stmt.where(user_roles_association.c.scope == scope)

            result = await session.execute(stmt)
            return list(result.unique().scalars().all())

        if db:
            return await _get(db)
        async with self._db_manager.get_db() as session:
            return await _get(session)

    async def has_permission(self, user_id: str, permission_name: str, scope_prefix: Optional[str] = None,
                             db: AsyncSession = None) -> bool:
        async def _check(session: AsyncSession):
            stmt = select(Permission.id).join(
                role_permissions_association, Permission.id == role_permissions_association.c.permission_id
            ).join(
                user_roles_association, role_permissions_association.c.role_id == user_roles_association.c.role_id
            ).where(
                user_roles_association.c.user_id == user_id, Permission.name == permission_name
            )
            if scope_prefix:
                scopes_to_check = ['global']
                if scope_prefix:
                    parts = scope_prefix.split('/')
                    current_path = ""
                    for part in parts:
                        current_path = f"{current_path}/{part}" if current_path else part
                        scopes_to_check.append(current_path)
                stmt = stmt.where(
                    user_roles_association.c.scope.in_(scopes_to_check)
                )
            result = (await session.execute(stmt)).first()
            return result is not None

        if db:
            return await _check(db)
        async with self._db_manager.get_db() as db:
            return await _check(db)

    async def revoke_user_role_by_scope(self, user_id: str, role_name: str, scope: str, revoker_id: str,
                                        ip_address: str = "system"):
        """
        Revokes a specific role from a user within a specific scope, with authorization checks.
        """
        async with self._db_manager.get_db() as db:
            # 1. Fetch necessary objects
            user_manager = UserManager(self._db_manager)
            revoker = await user_manager.get_by_id(revoker_id, with_relations=True, db=db)
            if not revoker:
                raise UserNotFoundError("Revoker user not found.")

            role_to_revoke = await self.get_by_name(role_name)
            if not role_to_revoke:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # 2. Authorization Check
            required_permission = f"roles:revoke:{role_name}"
            has_permission_override = await self.has_permission(revoker_id, required_permission, db=db)

            has_sufficient_level = False
            if revoker.roles:
                revoker_max_level = max(role.level for role in revoker.roles if role.level is not None)
                if role_to_revoke.level is not None and revoker_max_level > role_to_revoke.level:
                    has_sufficient_level = True

            if not (has_permission_override or has_sufficient_level):
                raise OperationForbiddenError(
                    "You lack the required permission or a sufficient role level to revoke this role."
                )

            # 3. If authorized, proceed with revocation
            stmt = delete(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role_to_revoke.id,
                user_roles_association.c.scope == scope
            )
            result = await db.execute(stmt)
            await self._db_manager.log_audit_event(
                user_id, "ROLE_REVOKED", ip_address,
                {"role": role_name, "scope": scope, "by": revoker_id}, db=db
            )
            await db.commit()
            return result.rowcount > 0

    async def delete_role(self, role_name: str, deleter_id: str):
        """
        Deletes a role entirely from the system, with authorization checks.
        """
        async with self._db_manager.get_db() as db:
            # Authorization Check: Must have 'admin:manage:roles' permission
            if not await self.has_permission(deleter_id, "admin:manage:roles", db=db):
                raise OperationForbiddenError("You lack the required permission to delete roles.")

            role_to_delete = await self.get_by_name(role_name)
            if not role_to_delete:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # Prevent deletion of system roles
            if role_to_delete.system:
                raise OperationForbiddenError("System roles cannot be deleted.")

            await db.delete(role_to_delete)
            await db.commit()


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
        if not is_permission_name_valid(name):
            raise ValueError(f"Invalid permission name: {name}")
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

    async def terminate_all_for_user(self, user_id: str, ip_address: str, except_session_id: Optional[str] = None, db: AsyncSession=None):
        async def _ori(_db: AsyncSession):
            stmt = select(DBSession).where(DBSession.user_id == user_id, DBSession.active == True)
            if except_session_id:
                stmt = stmt.where(DBSession.session_id != except_session_id)
            sessions_to_terminate = (await _db.execute(stmt)).scalars().all()
            for session in sessions_to_terminate:
                session.active = False

            await self._db_manager.log_audit_event(user_id, "SESSIONS_TERMINATED_ALL", ip_address,
                                                   {"except": except_session_id}, db=_db)
            await _db.commit()
        if db:
            return await _ori(db)
        else:
            async with self._db_manager.get_db() as db:
                return await _ori(db)


    async def get_all_for_user(self, user_id: str, session_id: str, only_active=True) -> List[DBSession]:
        async with self._db_manager.get_db() as db:
            stmt = select(DBSession).where(DBSession.user_id == user_id)
            if only_active:
                stmt = stmt.where(DBSession.active == True)
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
        stmt = select(Token).where(Token.id == token_id, Token.purpose == purpose).options(
            joinedload(Token.user).joinedload(User.mfa_methods))
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


class PasskeyManager:
    """Manages the lifecycle of passkey credentials for users."""

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager
        self.core = PasskeysCore()

    async def get_for_user(self, user_id: str) -> List[PasskeyCredential]:
        """Retrieve all passkeys for a given user."""
        async with self._db_manager.get_db() as db:
            stmt = select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
            result = await db.execute(stmt)
            return list(result.scalars().all())

    async def get_credential_by_id(self, credential_id: bytes) -> Optional[PasskeyCredential]:
        """Retrieve a single credential by its raw ID."""
        async with self._db_manager.get_db() as db:
            return await db.get(PasskeyCredential, credential_id)

    async def save_new_credential(self, user_id: str, cred_data: Dict[str, Any], nickname: str) -> PasskeyCredential:
        """Saves a new, verified passkey to the database, including all metadata."""
        async with self._db_manager.get_db() as db:
            new_passkey = PasskeyCredential(
                id=cred_data["credential_id"],
                user_id=user_id,
                nickname=nickname,
                public_key=cred_data["public_key"],
                sign_count=cred_data["sign_count"],
                aaguid=cred_data.get("aaguid"),
                transports=cred_data.get("transports", []),
                is_discoverable=cred_data.get("is_discoverable", False),
                is_backup_eligible=cred_data.get("is_backup_eligible", False),
                is_backed_up=cred_data.get("is_backed_up", False),
            )
            db.add(new_passkey)
            await db.commit()
            return new_passkey

    async def update_credential_on_login(self, credential_id: bytes, new_sign_count: int):
        """Updates the sign count and last_used_at timestamp after a successful login."""
        async with self._db_manager.get_db() as db:
            cred = await db.get(PasskeyCredential, credential_id)
            if cred:
                cred.sign_count = new_sign_count
                cred.last_used_at = time.time()
                await db.commit()

    async def delete_credential(self, user_id: str, credential_id_b64: str) -> bool:
        """Deletes a credential for a user, identified by its base64url ID."""
        try:
            credential_id = encryption_utils.base64url_decode(credential_id_b64)
        except Exception:
            return False

        async with self._db_manager.get_db() as db:
            stmt = delete(PasskeyCredential).where(
                PasskeyCredential.id == credential_id,
                PasskeyCredential.user_id == user_id
            )
            result = await db.execute(stmt)
            await db.commit()
            return result.rowcount > 0


class AuditManager:
    """Manages querying the audit trail for security and administrative purposes."""

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def get_events_for_user(self, user_id: str, skip: int = 0, limit: int = 25) -> List[AuditEvent]:
        async with self._db_manager.get_db() as db:
            stmt = select(AuditEvent).where(AuditEvent.user_id == user_id).order_by(desc(AuditEvent.timestamp)).offset(
                skip).limit(limit)
            result = await db.execute(stmt)
            return list(result.scalars().all())

    async def get_events_by_type(self, event_type: str, skip: int = 0, limit: int = 100) -> List[AuditEvent]:
        async with self._db_manager.get_db() as db:
            stmt = select(AuditEvent).where(AuditEvent.event_type == event_type).order_by(
                desc(AuditEvent.timestamp)).offset(skip).limit(limit)
            result = await db.execute(stmt)
            return list(result.scalars().all())


class OrganizationManager:
    """Manages all CRUD and business logic for Organizations and Teams."""

    def __init__(self, db_manager: DatabaseManager, user_manager: UserManager, role_manager: RoleManager,
                 token_manager: TokenManager):
        self._db_manager = db_manager
        self.users = user_manager
        self.roles = role_manager
        self.tokens = token_manager

    async def _join_organization_internal(
            self, db: AsyncSession, user: User, organization: Organization,
            role_name: str, ip_address: str, joined_by: str
    ):
        """Private helper to add a user to an org and assign their role."""
        stmt_exists = select(organization_members).where(
            organization_members.c.user_id == user.id,
            organization_members.c.organization_id == organization.id
        )
        if (await db.execute(stmt_exists)).first():
            return
        stmt = organization_members.insert().values(
            user_id=user.id,
            organization_id=organization.id
        )
        await db.execute(stmt)
        org_scope = f"org:{organization.id}"
        await self.roles.assign_to_user(
            user_id=user.id,
            role_name=role_name,
            assigner_id="system",
            scope=org_scope,
            db=db,
        )
        await self._db_manager.log_audit_event(
            user.id, "ORG_JOINED", ip_address,
            {"org_id": organization.id, "role": role_name, "joined_by": joined_by}, db=db
        )

    async def create_organization(self, name: str, owner: User, ip_address: str) -> Organization:
        """Creates a new organization and assigns the owner."""
        async with self._db_manager.get_db() as db:
            new_org = Organization(name=name, owner_id=owner.id)
            db.add(new_org)
            await db.flush()
            await self._join_organization_internal(
                db=db,
                user=owner,
                organization=new_org,
                role_name="OrgOwner",
                ip_address=ip_address,
                joined_by="creator",
            )

            await self._db_manager.log_audit_event(
                owner.id, "ORG_CREATED", ip_address,
                {"org_id": new_org.id, "org_name": new_org.name}, db=db
            )
            await db.commit()
            await db.refresh(new_org)
            return new_org

    async def get_organization_by_name(self, name: str) -> Optional[Organization]:
        async with self._db_manager.get_db() as db:
            stmt = select(Organization).where(Organization.name == name)
            result = await db.execute(stmt)
            return result.unique().scalar_one_or_none()

    async def get_organization_by_id(self, org_id: str) -> Optional[Organization]:
        async with self._db_manager.get_db() as db:
            # Use await db.get() for primary key lookup
            return await db.get(Organization, org_id)

    async def get_org_members(self, org_id: str) -> list[dict[str, Any]]:
        """Fetches all members of an organization with their join time."""
        async with self._db_manager.get_db() as db:
            stmt = select(
                User.id, User.username, User.email, organization_members.c.joined_at
            ).join_from(
                organization_members, User, organization_members.c.user_id == User.id
            ).where(
                organization_members.c.organization_id == org_id
            )
            result = await db.execute(stmt)
            return [
                {"user_id": row.id, "username": row.username, "email": row.email, "joined_at": row.joined_at}
                for row in result.all()
            ]

    async def get_user_orgs(self, user_id: str, db=None) -> list[Organization]:
        """Fetches all organizations a user is a member of."""
        async def _main(db):
            stmt = select(Organization).join(
                organization_members, organization_members.c.organization_id == Organization.id
            ).where(
                organization_members.c.user_id == user_id
            )
            result = await db.execute(stmt)
            return list(result.scalars().all())
        if db:
            return await _main(db)
        async with self._db_manager.get_db() as db:
            return await _main(db)

    async def get_user_owned_orgs(self, user_id: str) -> list[Organization]:
        """Fetches all organizations a user owns."""
        async with self._db_manager.get_db() as db:
            stmt = select(Organization).where(
                Organization.owner_id == user_id
            )
            result = await db.execute(stmt)
            return list(result.scalars().all())

    async def invite_to_organization(self, org_id: str, invitee_email: str, role_name: str, inviter: User,
                                     ip_address: str, background_tasks=None) -> Optional[bool]:
        """
        Invites a user to an organization.
        If email is enabled, sends an email with a token.
        If email is disabled, automatically joins the user.
        """
        invitee = await self.users.get_by_email(invitee_email)
        if not invitee:
            raise UserNotFoundError(f"User with email {invitee_email} not found.")

        org = await self.get_organization_by_id(org_id)
        if not org:
            raise RoleNotFoundError(f"Organization {org_id} not found.")
        if org_id not in [o.id for o in await self.get_user_orgs(inviter.id)]:
            raise OperationForbiddenError("Inviter is not a member of the organization.")
        async with self._db_manager.get_db() as db:
            await self._db_manager.log_audit_event(
                inviter.id, "ORG_INVITE_SENT", ip_address,
                {"org_id": org_id, "org_name": org.name, "invitee_email": invitee_email, "role": role_name}, db=db
            )
            await db.commit()

        if settings.EMAIL_ENABLED:
            token_purpose = f"org_invite:{org_id}:{role_name}"
            invite_token = await self.tokens.create(invitee.id, token_purpose, expiry_seconds=604800)  # 7 days

            from authtuna.helpers.mail import email_manager
            await email_manager.send_org_invite_email(
                email=invitee_email,
                token=invite_token.id,
                org_name=org.name,
                inviter_name=inviter.username,
                background_tasks=background_tasks,
            )
            return True
        else:
            # Email is disabled, auto-join the user
            async with self._db_manager.get_db() as db:
                await self._join_organization_internal(
                    db=db,
                    user=invitee,
                    organization=org,
                    role_name=role_name,
                    ip_address=ip_address,
                    joined_by="auto-accept-no-email"
                )
                await db.commit()
            return None

    async def accept_organization_invite(self, token_id: str, ip_address: str) -> Organization:
        """Validates an invite token and adds the user to the organization."""
        async with self._db_manager.get_db() as db:
            token_obj = await db.get(Token, token_id)
            if not token_obj or not token_obj.purpose.startswith("org_invite:"):
                raise InvalidTokenError("Invalid or unknown invite token.")

            try:
                user = await self.tokens.validate(db, token_id, token_obj.purpose, ip_address)
            except (InvalidTokenError, TokenExpiredError) as e:
                raise OperationForbiddenError(f"Invalid or expired invite token: {e}")

            try:
                _, org_id, role_name = token_obj.purpose.split(":")
            except (ValueError, AttributeError):
                raise OperationForbiddenError("Invalid invite token format.")

            organization = await db.get(Organization, org_id)
            if not organization:
                raise RoleNotFoundError(f"Organization {org_id} not found.")

            await self._join_organization_internal(
                db=db,
                user=user,
                organization=organization,
                role_name=role_name,
                ip_address=ip_address,
                joined_by="token-invite"
            )

            await db.commit()
            return organization


    async def _join_team_internal(
            self, db: AsyncSession, user: User, team: Team,
            role_name: str, ip_address: str, joined_by: str
    ):
        """Private helper to add a user to a team and assign their role."""
        stmt_exists = select(team_members).where(
            team_members.c.user_id == user.id,
            team_members.c.team_id == team.id
        )
        if (await db.execute(stmt_exists)).first():
            return

        stmt = team_members.insert().values(
            user_id=user.id,
            team_id=team.id
        )
        await db.execute(stmt)

        team_scope = f"team:{team.id}"
        await self.roles.assign_to_user(
            user_id=user.id,
            role_name=role_name,
            assigner_id="system",
            scope=team_scope,
            db=db,
        )

        await self._db_manager.log_audit_event(
            user.id, "TEAM_JOINED", ip_address,
            {"org_id": team.organization_id, "team_id": team.id, "role": role_name, "joined_by": joined_by}, db=db
        )

    async def create_team(self, name: str, org_id: str, creator: User, ip_address: str) -> Team:
        """Creates a new team within an organization."""
        async with self._db_manager.get_db() as db:
            org = await db.get(Organization, org_id)
            if not org:
                raise RoleNotFoundError(f"Organization {org_id} not found.")

            new_team = Team(name=name, organization_id=org_id)
            db.add(new_team)
            await db.flush()
            await self._join_team_internal(
                db=db,
                user=creator,
                team=new_team,
                role_name="TeamLead",
                ip_address=ip_address,
                joined_by="creator"
            )
            await self._db_manager.log_audit_event(
                creator.id, "TEAM_CREATED", ip_address,
                {"org_id": org_id, "team_id": new_team.id, "team_name": new_team.name}, db=db
            )
            await db.commit()
            await db.refresh(new_team)
            return new_team

    async def get_team_by_id(self, team_id: str) -> Optional[Team]:
        async with self._db_manager.get_db() as db:
            return await db.get(Team, team_id)

    async def get_org_teams(self, org_id: str) -> list[Team]:
        """Fetches all teams within an organization."""
        async with self._db_manager.get_db() as db:
            stmt = select(Team).where(Team.organization_id == org_id)
            result = await db.execute(stmt)
            return list(result.scalars().all())

    async def get_team_members(self, team_id: str) -> list[dict[str, Any]]:
        """Fetches all members of a team with their join time."""
        async with self._db_manager.get_db() as db:
            stmt = select(
                User.id, User.username, User.email, team_members.c.joined_at
            ).join_from(
                team_members, User, team_members.c.user_id == User.id
            ).where(
                team_members.c.team_id == team_id
            )
            result = await db.execute(stmt)
            return [
                {"user_id": row.id, "username": row.username, "email": row.email, "joined_at": row.joined_at}
                for row in result.all()
            ]

    async def invite_to_team(self, team_id: str, invitee_email: str, role_name: str, inviter: User, ip_address: str) -> \
    Optional[bool]:
        """
        Invites a user to a team.
        If email is enabled, sends an email with a token.
        If email is disabled, automatically joins the user.
        """
        invitee = await self.users.get_by_email(invitee_email)
        if not invitee:
            raise UserNotFoundError(f"User with email {invitee_email} not found.")

        team = await self.get_team_by_id(team_id)
        if not team:
            raise RoleNotFoundError(f"Team {team_id} not found.")
        async with self._db_manager.get_db() as db:
            stmt_exists = select(team_members).where(
                team_members.c.user_id == invitee.id,
                team_members.c.team_id == team_id
            )
            exists = (await db.execute(stmt_exists)).first()
            if exists:
                return False
        async with self._db_manager.get_db() as db:
            await self._db_manager.log_audit_event(
                inviter.id, "TEAM_INVITE_SENT", ip_address,
                {"org_id": team.organization_id, "team_id": team_id, "invitee_email": invitee_email, "role": role_name},
                db=db
            )
            await db.commit()

        if settings.EMAIL_ENABLED:
            token_purpose = f"team_invite:{team_id}:{role_name}"
            invite_token = await self.tokens.create(invitee.id, token_purpose, expiry_seconds=604800)
            await email_manager.send_team_invite_email(email=invitee_email,
                                                       token=invite_token.id,
                                                       team_name=team.name,
                                                       inviter_name=inviter.username,
                                                       background_tasks=None)
            return True
        else:
            async with self._db_manager.get_db() as db:
                await self._join_team_internal(
                    db=db,
                    user=invitee,
                    team=team,
                    role_name=role_name,
                    ip_address=ip_address,
                    joined_by="auto-accept-no-email"
                )
                await db.commit()
            return None

    async def accept_team_invite(self, token_id: str, ip_address: str) -> Team:
        """Validates an invite token and adds the user to the team."""
        async with self._db_manager.get_db() as db:
            token_obj = await db.get(Token, token_id)
            if not token_obj or not token_obj.purpose.startswith("team_invite:"):
                raise InvalidTokenError("Invalid or unknown invite token.")

            try:
                user = await self.tokens.validate(db, token_id, token_obj.purpose, ip_address)
            except (InvalidTokenError, TokenExpiredError) as e:
                raise OperationForbiddenError(f"Invalid or expired invite token: {e}")

            try:
                _, team_id, role_name = token_obj.purpose.split(":")
            except (ValueError, AttributeError):
                raise OperationForbiddenError("Invalid invite token format.")

            team = await db.get(Team, team_id)
            if not team:
                raise RoleNotFoundError(f"Team {team_id} not found.")

            await self._join_team_internal(
                db=db,
                user=user,
                team=team,
                role_name=role_name,
                ip_address=ip_address,
                joined_by="token-invite"
            )

            await db.commit()
            return team

    async def get_user_teams(self, user_id: str, org_id: Optional[str]=None):
        """
        Get teams of an org where the user is a part of.
        :param user_id:
        :param org_id:
        :return:
        """
        if org_id:
            async with self._db_manager.get_db() as db:
                stmt = select(Team).join(
                    team_members, team_members.c.team_id == Team.id
                ).where(
                    team_members.c.user_id == user_id,
                    Team.organization_id == org_id
                )
                result = await db.execute(stmt)
                return result.all()
        user_orgs = await self.get_user_orgs(user_id)
        org_teams = {}
        async with self._db_manager.get_db() as db:
            for org in user_orgs:
                stmt = select(Team).join(
                    team_members, team_members.c.team_id == Team.id
                ).where(
                    team_members.c.user_id == user_id,
                    Team.organization_id == org.id
                )
                result = await db.execute(stmt)
                org_teams[org] = result.all()
        return org_teams


class APIKEYManager:
    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def create_key(self, user_id: str, name: str, key_type: Literal["secret", "master", "public", "test"], scopes: List[str]=None, valid_seconds: int=31536000) -> ApiKey:
        """Creates a new API key for the specified user.

        Scopes must reference existing (role, scope) tuples already granted to the user in `user_roles`.
        Accepted scope formats in the `scopes` list:
         - "RoleName" (interpreted as RoleName with scope 'global')
         - "RoleName:scope_value" (explicit role + scope)
        The returned ApiKey object will have a `plaintext` attribute attached with the full secret (public_id.secret)
        so callers can display it once. Only the hash is persisted.

        Behavior changes:
        - master keys: automatically inherit all roles+scopes the user already has (ignores provided `scopes`).
        - public keys: may not have scopes; they are identity-only (no ApiKeyScope rows are created).
        - secret/test keys: keep the current behaviour (must pass valid scopes that the user already has).
        """
        async with self._db_manager.get_db() as db:
            # Verify user exists
            user = await db.get(User, user_id)
            if not user:
                raise UserNotFoundError("User not found.")
            key_prefix = key_type.upper()
            key_type = key_type.upper()
            if key_prefix == 'TEST':
                key_prefix = "test"
            elif key_prefix == 'SECRET':
                key_prefix = settings.API_KEY_PREFIX_SECRET
            elif key_prefix == 'MASTER':
                key_prefix = settings.API_KEY_PREFIX_MASTER
            elif key_prefix == 'PUBLIC':
                key_prefix = settings.API_KEY_PREFIX_PUBLISHABLE
            else:
                raise ValueError("Invalid API Key type.")

            try:
                total_keys = await db.scalar(select(func.count()).select_from(ApiKey).where(ApiKey.user_id == user_id))
            except Exception:
                total_keys = 0
            if settings.MAX_API_KEYS_PER_USER and total_keys >= settings.MAX_API_KEYS_PER_USER:
                raise OperationForbiddenError(f"User has reached the maximum total API keys ({settings.MAX_API_KEYS_PER_USER}).")
            try:
                existing_master_keys = await db.scalar(
                    select(func.count()).select_from(ApiKey).where(
                        ApiKey.user_id == user_id,
                        ApiKey.key_type == 'MASTER'
                    )
                )
            except Exception:
                existing_master_keys = 0
            if key_type == 'MASTER' and settings.MAX_MASTER_KEYS_PER_USER and existing_master_keys >= settings.MAX_MASTER_KEYS_PER_USER:
                raise OperationForbiddenError(f"User has reached the maximum master keys ({settings.MAX_MASTER_KEYS_PER_USER}).")
            if key_type == 'SECRET' and settings.MAX_SCOPES_PER_SECRET_KEY and settings.MAX_SCOPES_PER_SECRET_KEY > 0:
                if scopes is None:
                    scope_count = 0
                else:
                    scope_count = len(scopes)
                if scope_count > settings.MAX_SCOPES_PER_SECRET_KEY:
                    raise OperationForbiddenError(f"A secret key cannot have more than {settings.MAX_SCOPES_PER_SECRET_KEY} scopes.")

            public_id = f"{key_prefix}_{encryption_utils.gen_random_string(28)}"
            secret = encryption_utils.gen_random_string(64)
            full_key = f"{public_id}.{secret}"
            hashed = encryption_utils.hash_key(full_key)

            new_api_key = ApiKey(
                id=public_id,
                hashed_key=hashed,
                user_id=user_id,
                key_type=key_type,
                name=name,
                created_at=time.time(),
                expires_at=time.time()+valid_seconds
            )
            db.add(new_api_key)
            await db.flush()

            if key_type == 'PUBLIC' or key_type == 'MASTER':
                # Made Master key roles resolve in integration from user roles at that time
                # Public keys have no roles/scopes and are identity only.
                if scopes:
                    raise ValueError("Public keys cannot have scopes.")
            else:
                for scope_entry in scopes:
                    if isinstance(scope_entry, str) and ':' in scope_entry:
                        role_name, scope_val = scope_entry.split(':', 1)
                    else:
                        role_name = scope_entry
                        scope_val = 'global'

                    role_obj = (await db.execute(select(Role).where(Role.name == role_name))).unique().scalar_one_or_none()
                    if not role_obj:
                        raise RoleNotFoundError(f"Role '{role_name}' not found.")
                    check_stmt = select(user_roles_association).where(
                        user_roles_association.c.user_id == user_id,
                        user_roles_association.c.role_id == role_obj.id,
                        user_roles_association.c.scope == scope_val
                    )
                    if not (await db.execute(check_stmt)).first():
                        raise OperationForbiddenError(f"User does not have role '{role_name}' with scope '{scope_val}'.")
                    api_scope = ApiKeyScope(api_key_id=new_api_key.id, user_id=user_id, role_id=role_obj.id, scope=scope_val)
                    db.add(api_scope)

            await self._db_manager.log_audit_event(user_id, "API_KEY_CREATED", "system", {"key_id": new_api_key.id, "name": name, "key_type": key_type}, db=db)
            await db.commit()
            await db.refresh(new_api_key)
            setattr(new_api_key, 'plaintext', full_key)
            return new_api_key

    async def validate_key(self, token: str) -> Optional[ApiKey]:
        """Validates an API key and returns the associated information if valid."""
        # Expect token format: <public_id>.<secret>
        if not token or '.' not in token:
            return None
        public_id = token.split('.', 1)[0]
        async with self._db_manager.get_db() as db:
            stmt = select(ApiKey).where(ApiKey.id == public_id).options(selectinload(ApiKey.api_key_scopes))
            api_key = (await db.execute(stmt)).unique().scalar_one_or_none()
            if not api_key:
                return None
            if not encryption_utils.verify_key(token, api_key.hashed_key):
                return None
            if api_key.expires_at and time.time() > api_key.expires_at:
                return None
            api_key.last_used_at = time.time()
            await db.commit()
            await db.refresh(api_key)
            return api_key

    async def extend_key_expiration(self, key_id: str, expire_time: float):
        """Extends the expiration time of a specific API key."""
        async with self._db_manager.get_db() as db:
            api_key = await db.get(ApiKey, key_id)
            if not api_key:
                raise ValueError("API key not found.")
            api_key.expires_at = expire_time
            await db.commit()
            await db.refresh(api_key)
            return api_key

    async def delete_key(self, key_id: str):
        """Deletes an API key."""
        async with self._db_manager.get_db() as db:
            api_key = await db.get(ApiKey, key_id)
            if not api_key:
                return False
            await db.delete(api_key)
            await self._db_manager.log_audit_event(api_key.user_id if getattr(api_key, 'user_id', None) else 'system', "API_KEY_DELETED", "system", {"key_id": key_id}, db=db)
            await db.commit()
            return True

    async def get_all_keys_for_user(self, user_id: str) -> List[ApiKey]:
        """Returns all keys associated with the given user ID."""
        async with self._db_manager.get_db() as db:
            stmt = select(ApiKey).where(ApiKey.user_id == user_id).options(selectinload(ApiKey.api_key_scopes))
            result = await db.execute(stmt)
            return list(result.unique().scalars().all())

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
        self.audit = AuditManager(db_manager)
        self.passkeys = PasskeyManager(db_manager)
        self.orgs = OrganizationManager(db_manager, self.users, self.roles, self.tokens)
        self.api = APIKEYManager(db_manager)

    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Gathers all necessary statistics for the admin dashboard."""
        async with self.db_manager.get_db() as db:
            # Get user counts
            total_users_count = await db.scalar(select(func.count(User.id)))
            active_users_count = await db.scalar(select(func.count(User.id)).where(User.is_active == True))
            unverified_users_count = await db.scalar(select(func.count(User.id)).where(User.email_verified == False))

            # Get recent registrations
            recent_users_stmt = select(User).order_by(User.created_at.desc()).limit(5)
            recent_registrations = list((await db.execute(recent_users_stmt)).unique().scalars().all())

            # Get recent login events
            recent_logins_stmt = select(AuditEvent).where(
                or_(AuditEvent.event_type == "LOGIN_SUCCESS", AuditEvent.event_type == "LOGIN_FAILED")
            ).order_by(AuditEvent.timestamp.desc()).limit(10)
            recent_logins = list((await db.execute(recent_logins_stmt)).unique().scalars().all())

            return {
                "total_users": total_users_count,
                "active_users": active_users_count,
                "unverified_users": unverified_users_count,
                "recent_registrations": recent_registrations,
                "recent_logins": recent_logins,
            }

    async def signup(self, username: str, email: str, password: str, ip_address: str) -> Tuple[User, Optional[Token]]:
        user = await self.users.create(
            email=email, username=username, password=password, ip_address=ip_address,
            email_verified=not settings.EMAIL_ENABLED
        )
        await self.roles.assign_to_user(user.id, "User", assigner_id="system", scope="global")
        await self.db_manager.log_audit_event(
            user.id, "USER_SIGNUP_COMPLETED", ip_address,
            {"email_verification_required": settings.EMAIL_ENABLED},
        )
        token = None
        if settings.EMAIL_ENABLED:
            token = await self.tokens.create(user.id, "email_verification")
        return user, token

    async def _check_login_rate_limit(self, db: AsyncSession, user_id: Optional[str], ip_address: str):
        """
        Checks if the user or IP address has exceeded login attempt limits.
        Raises RateLimitError if rate limit is exceeded.
        """
        current_time = time.time()
        window_start = current_time - settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS

        # Check IP-based rate limit
        ip_attempts_stmt = select(func.count()).select_from(AuditEvent).where(
            AuditEvent.event_type == "LOGIN_FAILED",
            AuditEvent.ip_address == ip_address,
            AuditEvent.timestamp > window_start
        )
        ip_attempts = await db.scalar(ip_attempts_stmt)

        if ip_attempts >= settings.MAX_LOGIN_ATTEMPTS_PER_IP:
            await self.db_manager.log_audit_event(
                user_id or "system", "LOGIN_RATE_LIMITED", ip_address,
                {"reason": "ip_rate_limit_exceeded", "attempts": ip_attempts}, db=db
            )
            raise RateLimitError(f"Too many login attempts from this IP address. Please try again after {settings.LOGIN_LOCKOUT_DURATION_SECONDS // 60} minutes.")

        # Check user-based rate limit if user_id is provided
        if user_id:
            user_attempts_stmt = select(func.count()).select_from(AuditEvent).where(
                AuditEvent.event_type == "LOGIN_FAILED",
                AuditEvent.user_id == user_id,
                AuditEvent.timestamp > window_start
            )
            user_attempts = await db.scalar(user_attempts_stmt)

            if user_attempts >= settings.MAX_LOGIN_ATTEMPTS_PER_USER:
                await self.db_manager.log_audit_event(
                    user_id, "LOGIN_RATE_LIMITED", ip_address,
                    {"reason": "user_rate_limit_exceeded", "attempts": user_attempts}, db=db
                )
                raise RateLimitError(f"Too many failed login attempts for this account. Please try again after {settings.LOGIN_LOCKOUT_DURATION_SECONDS // 60} minutes.")

    async def login(self, username_or_email: str, password: str, ip_address: str, region: str, device: str) -> Union[
        Tuple[Any, Token], Tuple[Any, Session]]:
        async with self.db_manager.get_db() as db:
            # Log login attempt
            await self.db_manager.log_audit_event(
                "system", "LOGIN_ATTEMPT", ip_address,
                {"username_or_email": username_or_email, "device": device, "region": region}, db=db
            )

            stmt = select(User).where((User.email == username_or_email) | (User.username == username_or_email))
            user = (await db.execute(stmt)).unique().scalar_one_or_none()

            if not user:
                # Check rate limit for IP even if user not found
                await self._check_login_rate_limit(db, None, ip_address)
                await self.db_manager.log_audit_event(
                    "system", "LOGIN_FAILED", ip_address,
                    {"reason": "user_not_found", "username_or_email": username_or_email}, db=db
                )
                await db.commit()
                raise InvalidCredentialsError("Incorrect username/email or password.")

            # Check rate limits before password verification
            await self._check_login_rate_limit(db, user.id, ip_address)

            password_valid = await user.check_password(password, ip_address, self.db_manager, db)
            if password_valid is False:
                await db.commit()
                raise InvalidCredentialsError("Incorrect username/email or password.")
            elif password_valid is None:
                await db.commit()
                raise EmailNotVerifiedError("Email Not Verified.")
            elif password_valid is True:
                pass
            else:
                await self.db_manager.log_audit_event(
                    user.id, "LOGIN_FAILED", ip_address, {"reason": "config_error"}, db=db
                )
                await db.commit()
                raise InvalidCredentialsError("Incorrect username/email or password (config error).")

            if not user.is_active:
                await self.db_manager.log_audit_event(
                    user.id, "LOGIN_FAILED", ip_address, {"reason": "user_suspended"}, db=db
                )
                await db.commit()
                raise OperationForbiddenError("This account has been suspended.")

            # Log successful login
            await self.db_manager.log_audit_event(
                user.id, "LOGIN_SUCCESS_VERIFIED", ip_address,
                {"device": device, "region": region, "mfa_required": user.mfa_enabled}, db=db
            )
            await db.commit()

            if user.mfa_enabled:
                return user, await self.tokens.create(user.id, "mfa_validation", expiry_seconds=300)
            else:
                return user, await self.sessions.create(user.id, ip_address, region, device)

    async def change_password(self, user: User, current_password: str, new_password: str, ip_address: str, current_session_id: str):
        """
        Allows a user to change their password after verifying their current one.
        Terminates all other active sessions for security.
        """
        async with self.db_manager.get_db() as db:
            # Re-fetch user inside the session to ensure it's attached
            user_in_session = await db.get(User, user.id)
            if not user_in_session:
                raise UserNotFoundError("User not found.")

            await self.db_manager.log_audit_event(
                user.id, "PASSWORD_CHANGE_ATTEMPT", ip_address, db=db
            )

            password_valid = await user_in_session.check_password(current_password, ip_address, db_manager_custom=self.db_manager, db=db)
            if not password_valid:
                await self.db_manager.log_audit_event(
                    user.id, "PASSWORD_CHANGE_FAILED", ip_address,
                    {"reason": "incorrect_current_password"}, db=db
                )
                await db.commit()
                raise InvalidCredentialsError("The current password you entered is incorrect.")

            await user_in_session.set_password(new_password, ip_address, db_manager_custom=self.db_manager, db=db)
            await self.sessions.terminate_all_for_user(user.id, ip_address, except_session_id=current_session_id, db=db)

            await self.db_manager.log_audit_event(
                user.id, "PASSWORD_CHANGED", ip_address,
                {"sessions_terminated": True}, db=db
            )
            await db.commit()

    async def request_password_reset(self, email: str, ip_address: str = 'unknown') -> Optional[Token]:
        async with self.db_manager.get_db() as db:
            user = await self.users.get_by_email(email)
            if not user:
                await self.db_manager.log_audit_event(
                    "system", "PASSWORD_RESET_REQUESTED", ip_address,
                    {"email": email, "result": "user_not_found"}, db=db
                )
                await db.commit()
                return None

            count_stmt = select(func.count()).select_from(Token).where(
                Token.user_id == user.id,
                Token.purpose == "password_reset",
                Token.ctime > time.time() - 86400
            )
            recent_tokens_count = (await db.execute(count_stmt)).scalar()

            if recent_tokens_count >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
                await self.db_manager.log_audit_event(
                    user.id, "PASSWORD_RESET_RATE_LIMITED", ip_address,
                    {"attempts": recent_tokens_count}, db=db
                )
                await db.commit()
                raise RateLimitError("Too many password reset requests.")

            await self.db_manager.log_audit_event(
                user.id, "PASSWORD_RESET_REQUESTED", ip_address, db=db
            )
            await db.commit()
            return await self.tokens.create(user.id, "password_reset")

    async def reset_password(self, token_id: str, new_password: str, ip_address: str) -> User:
        """Performs token validation and password reset in a single atomic transaction."""
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, token_id, "password_reset", ip_address)
            await user.set_password(new_password, ip_address, self.db_manager, db)
            await self.db_manager.log_audit_event(
                user.id, "PASSWORD_RESET_COMPLETED", ip_address, db=db
            )
            await db.commit()
            return user

    async def verify_email(self, token_id: str, ip_address: str) -> User:
        """Performs email verification in a single atomic transaction with rate limiting."""
        async with self.db_manager.get_db() as db:
            # Rate limit by IP to help prevent token enumeration
            current_time = time.time()
            window_start = current_time - settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS

            ip_attempts_stmt = select(func.count()).select_from(AuditEvent).where(
                AuditEvent.event_type == "EMAIL_VERIFICATION_FAILED",
                AuditEvent.ip_address == ip_address,
                AuditEvent.timestamp > window_start
            )
            ip_attempts = await db.scalar(ip_attempts_stmt)
            if ip_attempts >= settings.MAX_LOGIN_ATTEMPTS_PER_IP:
                await self.db_manager.log_audit_event(
                    "system", "EMAIL_VERIFICATION_RATE_LIMITED", ip_address,
                    {"reason": "ip_rate_limit_exceeded", "attempts": ip_attempts}, db=db
                )
                await db.commit()
                raise RateLimitError("Too many verification attempts from this IP address. Please try again later.")

            # Validate the token; catch and log failures as EMAIL_VERIFICATION_FAILED
            try:
                user = await self.tokens.validate(db, token_id, "email_verification", ip_address)
            except TokenExpiredError as e:
                details = {"reason": "token_expired"}
                if getattr(e, 'new_token_id', None):
                    details["new_token_id"] = e.new_token_id
                await self.db_manager.log_audit_event(
                    "system", "EMAIL_VERIFICATION_FAILED", ip_address, details, db=db
                )
                await db.commit()
                raise
            except InvalidTokenError:
                await self.db_manager.log_audit_event(
                    "system", "EMAIL_VERIFICATION_FAILED", ip_address,
                    {"reason": "invalid_token"}, db=db
                )
                await db.commit()
                raise

            # Check per-user failed verification attempts
            user_attempts_stmt = select(func.count()).select_from(AuditEvent).where(
                AuditEvent.event_type == "EMAIL_VERIFICATION_FAILED",
                AuditEvent.user_id == user.id,
                AuditEvent.timestamp > window_start
            )
            user_attempts = await db.scalar(user_attempts_stmt)
            if user_attempts >= settings.MAX_LOGIN_ATTEMPTS_PER_USER:
                await self.db_manager.log_audit_event(
                    user.id, "EMAIL_VERIFICATION_RATE_LIMITED", ip_address,
                    {"reason": "user_rate_limit_exceeded", "attempts": user_attempts}, db=db
                )
                await db.commit()
                raise RateLimitError("Too many verification attempts for this account. Please try again later.")

            if not getattr(user, 'email_verified', False):
                user.email_verified = True
                await self.db_manager.log_audit_event(
                    user.id, "EMAIL_VERIFIED", ip_address, db=db
                )
            await db.commit()
            return user

    async def validate_mfa_login(self, mfa_token: str, code: str, ip_address: str, device_data: dict, background_tasks=None) -> DBSession:
        """
        Handles the second step of an MFA login within a single transaction.
        """
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, mfa_token, "mfa_validation", ip_address)

            await self.db_manager.log_audit_event(
                user.id, "MFA_VALIDATION_ATTEMPT", ip_address,
                {"device": device_data.get("device"), "region": device_data.get("region")}, db=db
            )

            user_with_mfa = await self.users.get_by_id(user.id, with_relations=True, db=db)
            if not user_with_mfa or not user_with_mfa.mfa_methods:
                await self.db_manager.log_audit_event(
                    user.id, "MFA_VALIDATION_FAILED", ip_address,
                    {"reason": "mfa_not_configured"}, db=db
                )
                await db.commit()
                raise InvalidTokenError("MFA is not configured correctly for this user.")

            # Assuming one TOTP method for now
            totp_method = next((m for m in user_with_mfa.mfa_methods if m.method_type == 'totp'), None)
            if not totp_method or not totp_method.secret:
                await self.db_manager.log_audit_event(
                    user.id, "MFA_VALIDATION_FAILED", ip_address,
                    {"reason": "totp_secret_not_found"}, db=db
                )
                await db.commit()
                raise InvalidTokenError("TOTP secret not found.")

            totp = pyotp.TOTP(totp_method.secret)
            is_valid_code = totp.verify(code)
            is_valid_recovery = False
            if not is_valid_code:
                is_valid_recovery = await self.mfa.verify_recovery_code(user, code, db)

            if not is_valid_code and not is_valid_recovery:
                await self.db_manager.log_audit_event(
                    user.id, "MFA_VALIDATION_FAILED", ip_address,
                    {"reason": "invalid_code", "device": device_data.get("device")}, db=db
                )
                await db.commit()
                raise InvalidTokenError("Invalid MFA code.")

            await self.db_manager.log_audit_event(
                user.id, "MFA_VALIDATION_SUCCESS", ip_address,
                {"method": "recovery_code" if is_valid_recovery else "totp",
                 "device": device_data.get("device"), "region": device_data.get("region")}, db=db
            )
            await db.commit()
        session = await self.sessions.create(
            user.id, ip_address, device_data["region"], device_data["device"]
        )
        if settings.EMAIL_ENABLED:
            await email_manager.send_new_login_email(user.email, background_tasks, {
                "username": user.username,
                "region": device_data["region"],
                "ip_address": ip_address,
                "device": device_data["device"] ,
                "login_time": datetime.datetime.fromtimestamp(session.ctime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        return session

    async def request_passwordless_login(self, email: str, ip_address: str = 'unknown') -> Optional[Token]:
        async with self.db_manager.get_db() as db:
            user = await self.users.get_by_email(email)
            if not user:
                await self.db_manager.log_audit_event(
                    "system", "PASSWORDLESS_LOGIN_REQUESTED", ip_address,
                    {"email": email, "result": "user_not_found"}, db=db
                )
                await db.commit()
                return None

            count_stmt = select(func.count()).select_from(Token).where(
                Token.user_id == user.id,
                Token.purpose == "passwordless_login",
                Token.ctime > time.time() - 86400
            )
            recent_tokens_count = (await db.execute(count_stmt)).scalar()

            if recent_tokens_count >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
                await self.db_manager.log_audit_event(
                    user.id, "PASSWORDLESS_LOGIN_RATE_LIMITED", ip_address,
                    {"attempts": recent_tokens_count}, db=db
                )
                await db.commit()
                raise RateLimitError("Too many passwordless login requests.")

            await self.db_manager.log_audit_event(
                user.id, "PASSWORDLESS_LOGIN_REQUESTED", ip_address, db=db
            )
            await db.commit()
            return await self.tokens.create(user.id, "passwordless_login")

    async def login_with_token(self, token_id: str, ip_address: str, region: str = 'unknown', device: str = 'unknown') -> User:
        """Performs token validation and returns the user."""
        async with self.db_manager.get_db() as db:
            user = await self.tokens.validate(db, token_id, "passwordless_login", ip_address)
            await self.db_manager.log_audit_event(
                user.id, "PASSWORDLESS_LOGIN_SUCCESS", ip_address,
                {"device": device, "region": region}, db=db
            )
            await db.commit()
            return user
