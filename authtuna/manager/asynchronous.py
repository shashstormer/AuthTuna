import time
from typing import Optional, Tuple, List, Dict, Any, Union

import pyotp
from sqlalchemy import or_, select, func, delete, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from authtuna.core import encryption_utils
from authtuna.core.config import settings
from authtuna.core.database import (
    DatabaseManager, User, Role, Permission, DeletedUser,
    Session as DBSession, Token, user_roles_association, role_permissions_association, Session, AuditEvent
)
from authtuna.core.exceptions import (
    UserAlreadyExistsError, InvalidCredentialsError, EmailNotVerifiedError,
    InvalidTokenError, TokenExpiredError, RateLimitError, UserNotFoundError,
    SessionNotFoundError, RoleNotFoundError, PermissionNotFoundError, OperationForbiddenError
)
from authtuna.core.mfa import MFAManager


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

    async def _is_authorized_to_manage_role(self, manager_user: User, role_to_manage: Role, db: AsyncSession) -> bool:
        """Private helper to check the 3 authorization pathways for role assignment."""
        # Pathway 1: Permission Override
        required_permission = f"roles:assign:{role_to_manage.name}"
        if await self.has_permission(manager_user.id, required_permission, db=db):
            return True

        # Pathway 2: Direct Grant
        for manager_role in manager_user.roles:
            if any(assignable.id == role_to_manage.id for assignable in manager_role.can_assign_roles):
                return True

        # Pathway 3: Level Hierarchy
        if manager_user.roles:
            manager_max_level = max((role.level for role in manager_user.roles if role.level is not None), default=-1)
            if role_to_manage.level is not None and manager_max_level > role_to_manage.level:
                return True

        return False

    async def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'none'):
        async with self._db_manager.get_db() as db:
            # Step 1: Fetch all necessary objects
            user_manager = UserManager(self._db_manager)
            assigner = await user_manager.get_by_id(assigner_id, with_relations=True, db=db)
            if not assigner:
                raise UserNotFoundError("Assigner user not found.")

            role_to_assign = await self.get_by_name(role_name)
            if not role_to_assign:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # Step 2: Perform the 3-pathway 'OR' authorization check

            can_manage_role = await self._is_authorized_to_manage_role(assigner, role_to_assign, db)
            if not can_manage_role:
                raise OperationForbiddenError(
                    "You lack the required permission, direct grant, or sufficient role level to assign this role."
                )

            # Step 3: If authorized, proceed with the assignment
            target_user = await user_manager.get_by_id(user_id, db=db)
            if not target_user: raise UserNotFoundError("Target user not found.")

            assoc_stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role_to_assign.id,
                user_roles_association.c.scope == scope
            )
            if (await db.execute(assoc_stmt)).first():
                return  # Already assigned

            insert_stmt = user_roles_association.insert().values(
                user_id=target_user.id, role_id=role_to_assign.id, scope=scope,
                given_by_id=assigner_id, given_at=time.time()
            )
            await db.execute(insert_stmt)
            await self._db_manager.log_audit_event(
                user_id, "ROLE_ASSIGNED", "system",
                {"role": role_name, "scope": scope, "by": assigner_id}, db=db
            )
            await db.commit()

    async def remove_from_user(self, user_id: str, role_name: str, remover_id: str, scope: str = 'none'):
        async with self._db_manager.get_db() as db:
            # Step 1: Fetch all necessary objects
            user_manager = UserManager(self._db_manager)
            assigner = await user_manager.get_by_id(remover_id, with_relations=True, db=db)
            if not assigner:
                raise UserNotFoundError("Assigner user not found.")

            role_to_assign = await self.get_by_name(role_name)
            if not role_to_assign:
                raise RoleNotFoundError(f"Role '{role_name}' not found.")

            # Step 2: Perform the 3-pathway 'OR' authorization check

            can_manage_role = self._is_authorized_to_manage_role(assigner, role_to_assign, db)

            if not can_manage_role:
                raise OperationForbiddenError(
                    "You lack the required permission, direct grant, or sufficient role level to assign this role."
                )
            target_user = await user_manager.get_by_id(user_id, db=db)
            if not target_user: raise UserNotFoundError("Target user not found.")
            assoc_stmt = select(user_roles_association).where(
                user_roles_association.c.user_id == user_id,
                user_roles_association.c.role_id == role_to_assign.id,
                user_roles_association.c.scope == scope,
            )
            if (await db.execute(assoc_stmt)).first():
                delete_stmt = user_roles_association.delete().where(
                    user_roles_association.c.user_id == user_id,
                    user_roles_association.c.role_id == role_to_assign.id,
                    user_roles_association.c.scope == scope,
                )
                await db.execute(delete_stmt)
                await self._db_manager.log_audit_event(
                    user_id, "ROLE_REMOVED", "system",
                    {"role": role_name, "scope": scope, "by": remover_id}, db=db
                )
                await db.commit()
            else:
                raise RoleNotFoundError(f"Role '{role_name}' not found for this user.")

    async def get_by_name(self, name: str) -> Optional[Role]:
        async with self._db_manager.get_db() as db:
            stmt = select(Role).where(Role.name == name).options(selectinload(Role.can_assign_roles))
            return (await db.execute(stmt)).unique().scalar_one_or_none()

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
                                 grantable_manager, relationship_attr: str, db_override: AsyncSession = None):
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
                stmt = stmt.where(
                    or_(user_roles_association.c.scope == 'global',
                        user_roles_association.c.scope.startswith(scope_prefix))
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
        token = None
        if settings.EMAIL_ENABLED:
            token = await self.tokens.create(user.id, "email_verification")
        return user, token

    async def login(self, username_or_email: str, password: str, ip_address: str, region: str, device: str) -> Union[
        Tuple[Any, Token], Tuple[Any, Session]]:
        async with self.db_manager.get_db() as db:
            stmt = select(User).where((User.email == username_or_email) | (User.username == username_or_email))
            user = (await db.execute(stmt)).unique().scalar_one_or_none()
            if not user:
                raise InvalidCredentialsError("Incorrect username/email or password.")
            password_valid = await user.check_password(password, ip_address, self.db_manager, db)
            if password_valid is False:
                raise InvalidCredentialsError("Incorrect username/email or password.")
            elif password_valid is None:
                raise EmailNotVerifiedError("Email Not Verified.")
            elif password_valid is True:
                pass
            else:
                raise InvalidCredentialsError("Incorrect username/email or password (config error).")
            if not user.is_active:
                await self.db_manager.log_audit_event(
                    user.id, "LOGIN_FAILED", ip_address, {"reason": "user_suspended"}, db=db
                )
                await db.commit()
                raise OperationForbiddenError("This account has been suspended.")
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

            password_valid = await user_in_session.check_password(current_password, ip_address, db_manager_custom=self.db_manager, db=db)
            if not password_valid:
                raise InvalidCredentialsError("The current password you entered is incorrect.")

            await user_in_session.set_password(new_password, ip_address, db_manager_custom=self.db_manager, db=db)
            await self.sessions.terminate_all_for_user(user.id, ip_address, except_session_id=current_session_id, db=db)
            await db.commit()

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
