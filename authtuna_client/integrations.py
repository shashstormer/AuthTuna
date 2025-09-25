from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request

from .manager import UserManagerClient, RoleManagerClient

user_manager_client = UserManagerClient()
role_manager_client = RoleManagerClient()

async def get_current_user(request: Request) -> dict:
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    user = user_manager_client.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found for this session",
        )
    return user

def get_user_ip(request: Request) -> Optional[str]:
    return getattr(request.state, "user_ip_address", None)

class PermissionChecker:
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

    async def __call__(self, request: Request, user: dict = Depends(get_current_user)):
        scope = "global"
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
                has_perm = role_manager_client.has_permission(user['id'], perm, scope)
                if not has_perm:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required permission: '{perm}'"
                    )
        elif self.mode == 'OR':
            has_at_least_one_perm = False
            for perm in self.permissions:
                if role_manager_client.has_permission(user['id'], perm, scope):
                    has_at_least_one_perm = True
                    break
            if not has_at_least_one_perm:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User must have at least one of: {', '.join(self.permissions)}"
                )
        return user

class RoleChecker:
    def __init__(self, *roles: str):
        self.roles = set(roles)

    async def __call__(self, request: Request):
        user: Optional[dict] = getattr(request.state, "user_object", None)
        if user is None:
            user_id = getattr(request.state, "user_id", None)
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated"
                )
            user = user_manager_client.get_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found for this session",
                )
        user_role_names = {role['name'] for role in user.get('roles', [])}
        if not self.roles.issubset(user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User lacks required role(s). Requires: {', '.join(self.roles)}"
            )
        request.state.user_object = user
        return user

# gRPC-backed integrations for authtuna-client will be implemented here
