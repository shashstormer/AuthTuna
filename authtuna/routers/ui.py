"""
This file gonna contain routes for ui (dashboards, user info and logins etc etc, gonna work on this soon)
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from fastapi import status
from sqlalchemy.exc import IntegrityError

from authtuna.core.config import settings
from authtuna.core.database import User
from authtuna.integrations.fastapi_integration import auth_service, RoleChecker
from authtuna.helpers.theme import get_theme_css

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory=settings.DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR)
templates.env.globals['get_theme_css'] = get_theme_css

class UserProfileUpdate(BaseModel):
    username: str

class SessionInfo(BaseModel):
    session_id: str
    region: str
    device: str
    last_ip: str
    mtime: float
    is_current: bool = False

    class Config:
        from_attributes = True

@router.get("/dashboard", name="ui_dashboard")
async def dashboard(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user dashboard page.
    """
    return templates.TemplateResponse("user_dashboard.html", {"request": request, "user": user})


@router.get("/profile", name="ui_profile")
async def profile(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user profile page.
    """
    return templates.TemplateResponse("user_profile.html", {"request": request, "user": user})


@router.get("/settings", name="ui_settings")
async def settings_page(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user settings page.
    """
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})


@router.patch("/profile", status_code=status.HTTP_200_OK)
async def update_profile(
    update_data: UserProfileUpdate,
    request: Request,
    user: User = Depends(RoleChecker("User"))
):
    """
    Update the current user's profile.
    """
    try:
        ip_address = request.state.user_ip_address
        updated_user = await auth_service.users.update(
            user_id=user.id,
            update_data={"username": update_data.username},
            ip_address=ip_address
        )
        return {"message": "Profile updated successfully!", "user": {"username": updated_user.username}}
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"An error occurred: {e}")

@router.get("/settings/sessions", response_model=List[SessionInfo])
async def get_user_sessions(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Fetches all active sessions for the current user.
    """
    current_session_id = request.state.session_id
    sessions = await auth_service.sessions.get_all_for_user(user.id, current_session_id)
    return sessions


@router.post("/settings/sessions/{session_id}/terminate", status_code=status.HTTP_200_OK)
async def terminate_session(session_id: str, request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Terminates a specific session for the current user.
    """
    session_to_terminate = await auth_service.sessions.get_by_id(session_id)
    if not session_to_terminate or session_to_terminate.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found or does not belong to user.")

    if session_to_terminate.session_id == request.state.session_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot terminate the current session.")

    ip_address = request.state.user_ip_address
    await auth_service.sessions.terminate(session_id, ip_address)
    return {"message": "Session terminated successfully."}

@router.post("/settings/sessions/terminate-all", status_code=status.HTTP_200_OK)
async def terminate_all_other_sessions(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Terminates all active sessions for the current user, except the current one.
    """
    current_session_id = request.state.session_id
    ip_address = request.state.user_ip_address
    await auth_service.sessions.terminate_all_for_user(user.id, ip_address, except_session_id=current_session_id)
    return {"message": "All other sessions have been terminated."}


# API Key Management Routes

class ApiKeyCreate(BaseModel):
    name: str
    key_type: str  # "secret", "master", "public", "test"
    scopes: List[str] = []
    valid_seconds: int = 31536000  # 1 year default

class ApiKeyInfo(BaseModel):
    id: str
    name: str
    key_type: str
    created_at: float
    expires_at: float
    last_used_at: Optional[float] = None

    class Config:
        from_attributes = True

@router.get("/settings/api-keys", response_model=List[ApiKeyInfo])
async def get_user_api_keys(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Fetches all API keys for the current user.
    """
    keys = await auth_service.api.get_all_keys_for_user(user.id)
    return keys


@router.get("/settings/available-scopes")
async def get_available_scopes(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Returns the user's available roles and scopes for creating API keys.
    """
    # Get user with roles
    user_with_roles = await auth_service.users.get_by_id(user.id, with_relations=True)

    scopes_info = []
    for role in user_with_roles.roles:
        # Get the scope from user_roles_association
        scope = getattr(role, '_sa_instance_state', None)
        scope_value = "global"  # default

        # Try to get the actual scope from the relationship
        # The scope is stored in the association table
        scopes_info.append({
            "role_name": role.name,
            "scope": "global",  # simplified for now
            "display": f"{role.name}:global"
        })

    return {"scopes": scopes_info}


@router.post("/settings/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: ApiKeyCreate,
    request: Request,
    user: User = Depends(RoleChecker("User"))
):
    """
    Creates a new API key for the current user.
    """
    try:
        api_key = await auth_service.api.create_key(
            user_id=user.id,
            name=key_data.name,
            key_type=key_data.key_type,
            scopes=key_data.scopes if key_data.scopes else None,
            valid_seconds=key_data.valid_seconds
        )
        return {
            "message": "API key created successfully",
            "api_key": {
                "id": api_key.id,
                "name": api_key.name,
                "key_type": api_key.key_type,
                "plaintext": api_key.plaintext,  # Only shown once!
                "created_at": api_key.created_at,
                "expires_at": api_key.expires_at
            }
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/settings/api-keys/{key_id}", status_code=status.HTTP_200_OK)
async def delete_api_key(
    key_id: str,
    request: Request,
    user: User = Depends(RoleChecker("User"))
):
    """
    Deletes a specific API key for the current user.
    """
    # Verify the key belongs to the user
    keys = await auth_service.api.get_all_keys_for_user(user.id)
    if not any(k.id == key_id for k in keys):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found or does not belong to user.")

    success = await auth_service.api.delete_key(key_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    return {"message": "API key deleted successfully."}
