from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request
from starlette.concurrency import run_in_threadpool

from authtuna.core.database import User, db_manager, user_roles_association, Role
from authtuna.manager.asynchronous import AuthTunaAsync

# This service object is the single entry point for all core logic.
auth_service = AuthTunaAsync(db_manager)


async def get_current_user(request: Request) -> User:
    """
    FastAPI dependency that retrieves the current user based on the user_id
    populated by the session middleware.
    """
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    try:
        user = await auth_service.users.get_by_id(user_id, with_relations=False)  # No need for relations here
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found for this session",
            )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not retrieve user: {e}",
        )


class PermissionChecker:
    """
    A dependency factory class for checking user permissions.
    """

    def __init__(
            self,
            *permissions: str,
            mode: Literal['AND', 'OR'] = 'AND',
            scope_prefix: Optional[str] = None,
            scope_from_path: Optional[str] = None
    ):
        self.permissions = permissions
        self.mode = mode
        self.scope_prefix = scope_prefix
        self.scope_from_path = scope_from_path

    async def __call__(self, request: Request, user: User = Depends(get_current_user)):
        scope = None
        if self.scope_from_path:
            path_param_value = request.path_params.get(self.scope_from_path)
            if not path_param_value:
                raise HTTPException(
                    status_code=500,
                    detail=f"Scope parameter '{self.scope_from_path}' not found in URL path."
                )
            prefix = self.scope_prefix or self.scope_from_path.replace('_id', '')
            scope = f"{prefix}:{path_param_value}"

        if self.mode == 'AND':
            for perm in self.permissions:
                has_perm = await auth_service.roles.has_permission(user.id, perm, scope)
                if not has_perm:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required permission: '{perm}'"
                    )
        elif self.mode == 'OR':
            has_at_least_one_perm = False
            for perm in self.permissions:
                if await auth_service.roles.has_permission(user.id, perm, scope):
                    has_at_least_one_perm = True
                    break
            if not has_at_least_one_perm:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User must have at least one of: {', '.join(self.permissions)}"
                )
        return user


class RoleChecker:
    """
    A dependency factory for checking if a user has a specific role.
    """

    def __init__(self, *roles: str):
        self.roles = set(roles)

    async def __call__(self, request: Request, user: User = Depends(get_current_user)):
        with db_manager.get_context_manager_db() as db:
            user_roles = await run_in_threadpool(
                db.query(Role.name).join(user_roles_association).filter(
                    user_roles_association.c.user_id == user.id
                ).all
            )
            user_role_names = {role[0] for role in user_roles}

        if not self.roles.issubset(user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User lacks required role(s). Requires: {', '.join(self.roles)}"
            )
        return user

