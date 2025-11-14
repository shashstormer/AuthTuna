import datetime
import logging

from fastapi import (APIRouter, Depends, status, Response, Request,
                     HTTPException, BackgroundTasks)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import HTMLResponse

from authtuna.core.config import settings
from authtuna.core.database import db_manager, Token, User
from authtuna.core.exceptions import (UserAlreadyExistsError, InvalidCredentialsError,
                                      EmailNotVerifiedError, InvalidTokenError,
                                      TokenExpiredError, RateLimitError)
from authtuna.helpers import create_session_and_set_cookie
from authtuna.helpers.mail import email_manager
from authtuna.helpers.theme import get_theme_css
from authtuna.integrations.fastapi_integration import auth_service, RoleChecker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory=settings.HTML_TEMPLATE_DIR)
templates.env.globals['get_theme_css'] = get_theme_css


class UserSignup(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username_or_email: str
    password: str


class PasswordResetRequest(BaseModel):
    email: str


class PasswordUpdate(BaseModel):
    token: str
    new_password: str


class TokenValidation(BaseModel):
    token: str


class RoleInfo(BaseModel):
    """Defines the structure for a user's role and its scope."""
    role_name: str
    scope: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class UserInfoResponse(BaseModel):
    """The complete, secure, and useful user information payload."""
    user_id: str
    username: str
    email: str
    is_active: bool
    email_verified: bool
    mfa_enabled: bool
    # roles: List[RoleInfo]


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup_user(
        user_data: UserSignup,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(db_manager.get_db)
):
    """
    Register a new user. If email verification is enabled, sends a verification email.
    Otherwise, creates a session and logs the user in immediately.
    Returns a message indicating the result.
    """
    try:
        ip_address = request.state.user_ip_address
        user, token = await auth_service.signup(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            ip_address=ip_address
        )

        if token:  # Email verification is enabled
            await email_manager.send_verification_email(user.email, token.id, background_tasks)
            await email_manager.send_welcome_email(user.email, background_tasks, {"username": user.username})
            response.status_code = status.HTTP_202_ACCEPTED
            return {"message": "User created. A verification email has been sent."}
        else:  # Email verification is disabled
            await create_session_and_set_cookie(user, request, response, db)
            await email_manager.send_welcome_email(user.email, background_tasks, {"username": user.username})
            return {"message": "User created and logged in successfully."}

    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"Error during signup: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")


@router.post("/login")
async def login_user(
        login_data: UserLogin,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks
):
    """
    Authenticate a user and create a session. Sets the session cookie and sends a new login email if enabled.
    Returns a message indicating the result.
    """
    try:
        ip_address = request.state.user_ip_address
        user, session = await auth_service.login(
            username_or_email=login_data.username_or_email,
            password=login_data.password,
            ip_address=ip_address,
            region=request.state.device_data["region"],
            device=request.state.device_data["device"]
        )

        if isinstance(session, Token):
            return {"mfa_required": True, "mfa_token": session.id}

        response.set_cookie(
            key=settings.SESSION_TOKEN_NAME,
            value=session.get_cookie_string(),
            samesite=settings.SESSION_SAME_SITE,
            secure=settings.SESSION_SECURE,
            httponly=True,
            max_age=settings.SESSION_ABSOLUTE_LIFETIME_SECONDS,
            domain=settings.SESSION_COOKIE_DOMAIN,
        )

        if settings.EMAIL_ENABLED:
            await email_manager.send_new_login_email(user.email, background_tasks, {
                "username": user.username,
                "region": request.state.device_data["region"],
                "ip_address": ip_address,
                "device": request.state.device_data["device"],
                "login_time": datetime.datetime.fromtimestamp(session.ctime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        return {"message": "Login successful."}
    except (InvalidCredentialsError, EmailNotVerifiedError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except RateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")


@router.api_route("/logout", methods=["GET", "POST"])
async def logout_user(request: Request, response: Response):
    """
    Log out the current user by terminating the session and deleting the session cookie.
    """
    session_id = getattr(request.state, "session_id", None)
    if session_id:
        ip_address = request.state.user_ip_address
        deleted = await auth_service.sessions.terminate(session_id, ip_address)
        if deleted:
            response.delete_cookie(settings.SESSION_TOKEN_NAME)
            return {"message": "Logged out successfully."}
    return {"message": "Logout failed or no active session found."}


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(
        request_data: PasswordResetRequest,
        background_tasks: BackgroundTasks
):
    """
    Request a password reset. If the email exists, sends a password reset email (if enabled).
    Always returns a generic message for security.
    """
    if not settings.EMAIL_ENABLED:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email functionality is disabled.")

    try:
        token = await auth_service.request_password_reset(request_data.email)
        if token:
            await email_manager.send_password_reset_email(request_data.email, token.id, background_tasks)
    except RateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except Exception as e:
        logger.error(f"Error during password reset request: {e}", exc_info=True)

    return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
async def reset_password(
        password_data: PasswordUpdate,
        request: Request,
        background_tasks: BackgroundTasks
):
    """
    Reset the user's password using a valid reset token. Sends a password change email if successful.
    Returns a message indicating the result.
    """
    if not settings.EMAIL_ENABLED:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email functionality is disabled.")

    try:
        ip_address = request.state.user_ip_address
        user = await auth_service.reset_password(password_data.token, password_data.new_password, ip_address)
        await email_manager.send_password_change_email(user.email, background_tasks)
        return {"message": "Password has been reset successfully."}
    except (InvalidTokenError, TokenExpiredError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error during password reset: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
        password_data: PasswordChange,
        request: Request,
        background_tasks: BackgroundTasks,
        user: User = Depends(RoleChecker("User")),
):
    """
    Allows an authenticated user to change their own password.
    """
    try:
        ip_address = request.state.user_ip_address
        session_id = request.state.session_id

        await auth_service.change_password(
            user=user,
            current_password=password_data.current_password,
            new_password=password_data.new_password,
            ip_address=ip_address,
            current_session_id=session_id
        )
        # Email notification for security
        await email_manager.send_password_change_email(user.email, background_tasks)
        return {"message": "Password updated successfully. All other sessions have been logged out."}
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error(f"Error during password change: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.api_route("/user-info", methods=["GET", "POST"], response_model=UserInfoResponse)
async def get_current_user_info(
        user: User = Depends(RoleChecker("User"))
):
    """
    Returns a comprehensive, secure overview of the currently authenticated user,
    including their status and all their roles with scopes.
    """
    # roles_with_scope = await auth_service.roles.get_user_roles_with_scope(user.id)

    return UserInfoResponse(
        user_id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        # roles=[RoleInfo(**role) for role in roles_with_scope]
    )


## UI ROUTES (got mixed up above so moved down)

@router.get("/signup", response_class=HTMLResponse)
async def show_signup_page(request: Request):
    """
    Render the signup page (HTML form).
    """
    return templates.TemplateResponse("signup.html", {"request": request})


@router.get("/login", response_class=HTMLResponse)
async def show_login_page(request: Request):
    """
    Render the login page (HTML form), with social login options if enabled.
    """
    context = {
        "request": request,
        "google_login_enabled": bool(settings.GOOGLE_CLIENT_ID),
        "github_login_enabled": bool(settings.GITHUB_CLIENT_ID),
        "passwordless_login_enabled": settings.PASSWORDLESS_LOGIN_ENABLED,
    }
    return templates.TemplateResponse("login.html", context)


@router.get("/forgot-password", response_class=HTMLResponse)
async def show_forgot_password_page(request: Request):
    """
    Render the forgot password page (HTML form).
    """
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.get("/verify", response_class=HTMLResponse)
async def verify_email(
        token: str,
        request: Request
):
    """
    Verify a user's email address using a verification token. Renders a success or error page.
    """
    try:
        ip_address = request.state.user_ip_address
        await auth_service.verify_email(token, ip_address)
        return templates.TemplateResponse("verify_email.html", {"request": request})
    except (InvalidTokenError, TokenExpiredError) as e:
        return templates.TemplateResponse("error.html", {"request": request, "message": str(e)})
    except Exception as e:
        logger.error(f"Error during email verification: {e}", exc_info=True)
        return templates.TemplateResponse("error.html",
                                          {"request": request, "message": "An unexpected error occurred."})


@router.get("/reset-password", response_class=HTMLResponse)
async def show_reset_page(token: str, request: Request,
                          # db: AsyncSession = Depends(db_manager.get_db)
                          ):
    """
    Render the reset password page if the token is valid, otherwise show an error page.
    """
    async with db_manager.get_db() as db:
        stmt = select(Token).where(Token.id == token, Token.purpose == "password_reset")
        result = await db.execute(stmt)
        token_obj = result.unique().scalar_one_or_none()

        if not token_obj or not token_obj.is_valid():
            return templates.TemplateResponse("error.html",
                                              {"request": request, "message": "Invalid or expired token."})
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})
