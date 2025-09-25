from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request, Response

from .manager import UserManagerClient, RoleManagerClient, SessionManagerClient

user_manager_client = UserManagerClient()
role_manager_client = RoleManagerClient()
session_manager_client = SessionManagerClient()

async def get_current_user(request: Request) -> dict:
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    user = await user_manager_client.get_by_id(user_id)
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
                has_perm = await role_manager_client.has_permission(user['id'], perm, scope)
                if not has_perm:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required permission: '{perm}'"
                    )
        elif self.mode == 'OR':
            if not any([await role_manager_client.has_permission(user['id'], perm, scope) for perm in self.permissions]):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User lacks any of the required permissions: {', '.join(self.permissions)}"
                )
        else:
            raise HTTPException(status_code=500, detail="Invalid permission check mode.")
        return True

async def login_user(user_id: str, request: Request, response: Response, ip_address: str = None, region: str = None, device: str = None):
    # Create a new session for the user and set the session cookie
    session = await session_manager_client.create(user_id, ip_address or "127.0.0.1", region or "Unknown", device or "Unknown")
    if not session:
        raise HTTPException(status_code=500, detail="Failed to create session")
    response.set_cookie(
        key="session_id",
        value=session.get("session_id"),
        httponly=True,
        samesite="lax",
        max_age=60*60*24*7,  # 1 week
    )
    return session

async def logout_user(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id:
        await session_manager_client.terminate(session_id)
        response.delete_cookie("session_id")

async def get_current_session(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    return await session_manager_client.get_by_id(session_id)

# Starlette equivalents
from starlette.responses import Response as StarletteResponse

async def login_user_starlette(user_id: str, request: StarletteRequest, response: StarletteResponse, ip_address: str = None, region: str = None, device: str = None):
    session = await session_manager_client.create(user_id, ip_address or "127.0.0.1", region or "Unknown", device or "Unknown")
    if not session:
        raise Exception("Failed to create session")
    response.set_cookie(
        key="session_id",
        value=session.get("session_id"),
        httponly=True,
        samesite="lax",
        max_age=60*60*24*7,
    )
    return session

async def logout_user_starlette(request: StarletteRequest, response: StarletteResponse):
    session_id = request.cookies.get("session_id")
    if session_id:
        await session_manager_client.terminate(session_id)
        response.delete_cookie("session_id")

async def get_current_session_starlette(request: StarletteRequest):
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    return await session_manager_client.get_by_id(session_id)

# gRPC-backed integrations for authtuna-client will be implemented here
