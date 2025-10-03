from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request

from authtuna.core.database import User, db_manager
from authtuna.manager.asynchronous import AuthTunaAsync

# The primary asynchronous service used by FastAPI dependencies.
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
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not retrieve user: {e}",
        )


async def get_current_user_optional(request: Request) -> Optional[User]:
    """
    Does the exact same thing as get current user but doesn't throw error if not authenticated.
    :param request:
    :return:
    """
    try:
        return await get_current_user(request)
    except HTTPException as e:
        if e.detail == "Not authenticated":
            pass
        else:
            raise e
    return None



def get_user_ip(request: Request) -> str:
    """
    If you using this obvio you have included the session middleware which sets this so ...
    """
    return request.state.user_ip_address

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
            scope_from_path: Optional[str] = None,
            raise_error: bool = True
    ):
        self.permissions = permissions
        self.mode = mode
        self.scope_prefix = scope_prefix
        self.scope_from_path = scope_from_path
        self.raise_error = raise_error

    async def __call__(self, request: Request, user: User = Depends(get_current_user)) -> Optional[User]:
        scope = "global"
        if self.scope_from_path:
            path_param_value = request.path_params.get(self.scope_from_path)
            if not path_param_value:
                if self.raise_error:
                    raise HTTPException(
                    status_code=500,
                    detail=f"Scope parameter '{self.scope_from_path}' not found in URL path."
                    )
                return None
            prefix = self.scope_prefix or self.scope_from_path.replace('_id', '')
            scope = f"{prefix}:{path_param_value}"

        if self.mode == 'AND':
            for perm in self.permissions:
                has_perm = await auth_service.roles.has_permission(user.id, perm, scope)
                if not has_perm:
                    if self.raise_error:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Missing required permission: '{perm}'"
                        )
                    return None
        elif self.mode == 'OR':
            has_at_least_one_perm = False
            for perm in self.permissions:
                if await auth_service.roles.has_permission(user.id, perm, scope):
                    has_at_least_one_perm = True
                    break
            if not has_at_least_one_perm:
                if self.raise_error:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"User must have at least one of: {', '.join(self.permissions)}"
                    )
                return None
        return user


class RoleChecker:
    """
    A dependency factory for checking if a user has specific roles.

    This implementation prefers a pre-loaded user object on request.state (as set by
    middleware or another dependency). If unavailable, it falls back to fetching the
    user by request.state.user_id. If neither is present, it raises 401.
    """

    def __init__(self, *roles: str, raise_error: bool= True):
        self.roles = set(roles)
        self.raise_error = raise_error

    async def __call__(self, request: Request) -> Optional[User]:
        if self.raise_error:
            user = await get_current_user(request)
        else:
            user = await get_current_user_optional(request)
            if user is None:
                return None
        user_role_names = {role.name for role in user.roles}
        if not self.roles.issubset(user_role_names):
            if self.raise_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User lacks required role(s). Requires: {', '.join(self.roles)}"
                )
            return None
        request.state.user_object = user
        return user
