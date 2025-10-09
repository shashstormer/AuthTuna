"""
This file gonna contain routes for ui (dashboards, user info and logins etc etc, gonna work on this soon)
"""
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from fastapi import status
from sqlalchemy.exc import IntegrityError

from authtuna.core.config import settings
from authtuna.core.database import User
from authtuna.integrations.fastapi_integration import get_current_user, auth_service

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory=settings.DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR)
class UserProfileUpdate(BaseModel):
    username: str

@router.get("/dashboard", name="ui_dashboard")
async def dashboard(request: Request, user: User = Depends(get_current_user)):
    """
    Renders the user dashboard page.
    """
    return templates.TemplateResponse("user_dashboard.html", {"request": request, "user": user})


@router.get("/profile", name="ui_profile")
async def profile(request: Request, user: User = Depends(get_current_user)):
    """
    Renders the user profile page.
    """
    return templates.TemplateResponse("user_profile.html", {"request": request, "user": user})


@router.get("/settings", name="ui_settings")
async def settings_page(request: Request, user: User = Depends(get_current_user)):
    """
    Renders the user settings page.
    """
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})


@router.patch("/profile", status_code=status.HTTP_200_OK)
async def update_profile(
    update_data: UserProfileUpdate,
    request: Request,
    user: User = Depends(get_current_user)
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
