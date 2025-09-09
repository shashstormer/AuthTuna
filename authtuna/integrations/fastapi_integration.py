from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request
from authtuna.core.database import User, db_manager, Role
from authtuna.manager.asynchronous import AuthTunaAsync


auth_service = AuthTunaAsync(db_manager)


async def get_current_user(request: Request) -> User:
    """
    FastAPI dependency that retrieves the current user based on the user_id
    populated by the session middleware.

    OPTIMIZATION: This function now caches the full user object with roles pre-loaded
    onto the request state. This ensures the database is hit only once per request
    for user data, even if multiple dependencies need the user object.
    """
    if hasattr(request.state, "user_object"):
        return request.state.user_object
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    try:
        user = await auth_service.users.get_by_id(user_id, with_relations=True)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found for this session",
            )
        request.state.user_object = user
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not retrieve user: {e}",
        )


class PermissionChecker:
    """
    A dependency factory class for checking user permissions. This class relies on the
    efficient `has_permission` method in the service layer.
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
    A dependency factory for checking if a user has specific roles.

    OPTIMIZATION: This class now uses the pre-loaded roles from the `user` object
    provided by the `get_current_user` dependency, avoiding a separate DB query.
    """

    def __init__(self, *roles: str):
        self.roles = set(roles)

    async def __call__(self, request: Request, user: User = Depends(get_current_user)):
        user_role_names = {role.name for role in user.roles}
        if not self.roles.issubset(user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User lacks required role(s). Requires: {', '.join(self.roles)}"
            )
        return user
