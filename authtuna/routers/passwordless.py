import datetime
import logging

from fastapi import (APIRouter, Depends, status, Response, Request,
                     HTTPException, BackgroundTasks)
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from authtuna.core.config import settings
from authtuna.core.database import db_manager
from authtuna.core.exceptions import (InvalidTokenError,
                                      TokenExpiredError, RateLimitError)
from authtuna.helpers import create_session_and_set_cookie
from authtuna.helpers.mail import email_manager
from authtuna.integrations.fastapi_integration import auth_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/passwordless", tags=["passwordless"])


class PasswordlessLoginRequest(BaseModel):
    email: str


@router.post("/request", status_code=status.HTTP_202_ACCEPTED)
async def request_passwordless_login(
        request_data: PasswordlessLoginRequest,
        background_tasks: BackgroundTasks
):
    """
    Request a passwordless login. If the email exists, sends a login link.
    Always returns a generic message for security.
    """
    if not settings.EMAIL_ENABLED:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email functionality is disabled.")

    try:
        token = await auth_service.request_passwordless_login(request_data.email)
        if token:
            await email_manager.send_passwordless_login_email(request_data.email, token.id, background_tasks)
    except RateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except Exception as e:
        logger.error(f"Error during passwordless login request: {e}", exc_info=True)

    return {"message": "If an account with that email exists, a login link has been sent."}


@router.get("/login")
async def passwordless_login(
    token: str,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_manager.get_db)
):
    """
    Log in a user using a valid passwordless login token.
    """
    try:
        ip_address = request.state.user_ip_address
        region = request.state.device_data["region"]
        device = request.state.device_data["device"]
        user = await auth_service.login_with_token(token, ip_address)
        if user.id == "default-super-admin" or user.id == "default-admin":
            return {"message": "Session not created as default users are not allowed for magic link login."}
        if not user.is_active:
            return {"message": "Your account has been suspended. Please contact support."}
        if user.mfa_enabled:
            mfa_token = await auth_service.tokens.create(user.id, "mfa_validation", expiry_seconds=300)
            return RedirectResponse(url=f"/mfa/challenge?mfa_token={mfa_token.id}")
        await create_session_and_set_cookie(user, request, response, db)

        if settings.EMAIL_ENABLED:
            await email_manager.send_new_login_email(user.email, background_tasks, {
                "username": user.username,
                "region": region,
                "ip_address": ip_address,
                "device": device,
                "login_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        return {"message": "Login successful."}

    except (InvalidTokenError, TokenExpiredError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error during passwordless login: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")


passwordless_router = router
