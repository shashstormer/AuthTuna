import logging
import time

from fastapi import APIRouter, Depends, status, Response, Request, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from starlette.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from authtuna.core.database import db_manager, User, Session as DBSession, Token, DatabaseManager
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings
from starlette.concurrency import run_in_threadpool
from authtuna.helpers import create_session_and_set_cookie, get_remote_address
from authtuna.helpers.mail import email_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory=settings.HTML_TEMPLATE_DIR)


class UserSignup(BaseModel):
    """Pydantic model for user signup data."""
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    """
    Updated Pydantic model for user login credentials.
    Allows a single field for either username or email.
    """
    username_or_email: str
    password: str


class PasswordResetRequest(BaseModel):
    """Pydantic model for a password reset request."""
    email: str


class PasswordUpdate(BaseModel):
    """Pydantic model for updating a password."""
    token: str
    new_password: str


class TokenValidation(BaseModel):
    """Pydantic model for token validation."""
    token: str


async def _validate_token_and_get_user(
        db: Session,
        token_id: str,
        purpose: str,
        request: Request,
        db_manager_instance: DatabaseManager,
        background_tasks: BackgroundTasks,
) -> User:
    """
    A helper function to validate a token, mark it used, and return the associated user.
    If the token is expired but not used, a new one is generated and a refresh is requested.
    """
    token_obj = await run_in_threadpool(
        db.query(Token).filter(
            Token.id == token_id,
            Token.purpose == purpose,
        ).first
    )

    if not token_obj:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    if token_obj.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has already been used."
        )

    if token_obj.etime < time.time():
        if not settings.EMAIL_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired. Email functionality is disabled, so a new token cannot be sent."
            )

        recent_tokens_count = await run_in_threadpool(
            db.query(Token).filter(
                Token.user_id == token_obj.user_id,
                Token.purpose == purpose,
                Token.ctime > time.time() - 86400
            ).count
        )

        if recent_tokens_count >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many tokens have been requested. Please wait 24 hours before trying again."
            )

        new_token = Token(
            id=encryption_utils.gen_random_string(32),
            purpose=purpose,
            user_id=token_obj.user_id,
            etime=time.time() + settings.TOKENS_EXPIRY_SECONDS,
            new_gen_id=token_obj.id,
        )
        await run_in_threadpool(db.add, new_token)
        await run_in_threadpool(db.commit)

        await run_in_threadpool(token_obj.mark_used, await get_remote_address(request), db_manager_instance)
        await run_in_threadpool(db.commit)

        db_manager_instance.log_audit_event(
            user_id=token_obj.user_id,
            event_type="TOKEN_REFRESH",
            ip_address=await get_remote_address(request),
            details={"old_token": token_obj.id, "new_token": new_token.id, "purpose": purpose}
        )

        user_to_email = await run_in_threadpool(
            db.query(User).filter(User.id == token_obj.user_id).first
        )
        if purpose == "email_verification":
            await email_manager.send_verification_email(user_to_email.email, new_token.id, background_tasks)
        elif purpose == "password_reset":
            await email_manager.send_password_reset_email(user_to_email.email, new_token.id, background_tasks)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired. A new token has been sent to your email."
        )

    user = await run_in_threadpool(
        db.query(User).filter(User.id == token_obj.user_id).first
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    await run_in_threadpool(token_obj.mark_used, await get_remote_address(request), db_manager_instance)
    await run_in_threadpool(db.commit)

    return user


@router.get("/signup", response_class=HTMLResponse)
async def show_signup_page(request: Request):
    """Serves the signup page."""
    return templates.TemplateResponse("signup.html", {"request": request})


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup_user(
        user_data: UserSignup,
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db),
        background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Handles new user registration."""
    existing_user = await run_in_threadpool(
        db.query(User).filter(
            (User.email == user_data.email) | (User.username == user_data.username)
        ).first
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered."
        )

    new_user = User(
        id=encryption_utils.gen_random_string(32),
        username=user_data.username,
        email=user_data.email,
        email_verified=not settings.EMAIL_ENABLED,
    )
    await run_in_threadpool(db.add, new_user)
    await run_in_threadpool(db.commit)

    await run_in_threadpool(new_user.set_password, user_data.password, await get_remote_address(request), db_manager)
    await run_in_threadpool(db.commit)
    await run_in_threadpool(db.refresh, new_user)

    if settings.EMAIL_ENABLED:
        token = Token(
            id=encryption_utils.gen_random_string(32),
            purpose="email_verification",
            user_id=new_user.id,
            etime=time.time() + settings.TOKENS_EXPIRY_SECONDS,
        )
        await run_in_threadpool(db.add, token)
        await run_in_threadpool(db.commit)

        await email_manager.send_verification_email(new_user.email, token.id, background_tasks)
        await email_manager.send_welcome_email(new_user.email, background_tasks, {"username": new_user.username})

        return Response(
            status_code=status.HTTP_202_ACCEPTED,
            content="User created. A verification email has been sent. Please check your inbox."
        )
    else:
        await create_session_and_set_cookie(new_user, request, response, db)
        await email_manager.send_welcome_email(new_user.email, background_tasks, {"username": new_user.username})
        return Response(status_code=status.HTTP_201_CREATED, content="User created successfully. Logged in.")


@router.get("/login", response_class=HTMLResponse)
async def show_login_page(request: Request):
    """Serves the login page and indicates which social providers are enabled."""
    context = {
        "request": request,
        "google_login_enabled": bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET),
        "github_login_enabled": bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET),
    }
    return templates.TemplateResponse("login.html", context)


@router.post("/login")
async def login_user(
        login_data: UserLogin,
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db),
        background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Authenticates a user and creates a new session."""
    user = await run_in_threadpool(
        db.query(User).filter(
            (User.email == login_data.username_or_email) |
            (User.username == login_data.username_or_email)
        ).first
    )

    if not user or not isinstance(user, User):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password."
        )

    password_valid = await run_in_threadpool(
        user.check_password,
        login_data.password,
        await get_remote_address(request),
        db_manager
    )

    if settings.EMAIL_ENABLED and not user.is_email_verified():
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="Email Not Verified."
        )

    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password."
        )

    await run_in_threadpool(db.commit)

    await create_session_and_set_cookie(user, request, response, db)

    if settings.EMAIL_ENABLED:
        await email_manager.send_new_login_email(user.email, background_tasks, {
            "username": user.username,
            "region": request.state.device_data["region"],
            "ip_address": await get_remote_address(request),
            "device": request.state.device_data["device"],
        })

    return {"message": "Login successful."}


@router.post("/logout")
@router.get("/logout")
async def logout_user(
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db)
):
    """Invalidates the current session."""
    session_id = request.state.session_id
    if session_id:
        session = await run_in_threadpool(
            db.query(DBSession).filter(
                DBSession.session_id == session_id
            ).first
        )
        if session:
            await run_in_threadpool(session.terminate, await get_remote_address(request), db_manager)
            await run_in_threadpool(db.commit)

    response.delete_cookie(settings.SESSION_TOKEN_NAME)
    return {"message": "Logged out successfully."}


@router.get("/forgot-password", response_class=HTMLResponse)
async def show_forgot_password_page(request: Request):
    """Serves the forgot password page."""
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.post("/forgot-password")
async def forgot_password(
        request_data: PasswordResetRequest,
        background_tasks: BackgroundTasks,
        db: Session = Depends(db_manager.get_db)
):
    """Sends a password reset token via email."""
    if not settings.EMAIL_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email functionality is disabled. Password reset is not available."
        )

    user = await run_in_threadpool(
        db.query(User).filter(User.email == request_data.email).first
    )

    if not user:
        logger.warning(f"Password reset requested for non-existent email: {request_data.email}")
        return {"message": "If an account with that email exists, a password reset link has been sent."}

    recent_tokens_count = await run_in_threadpool(
        db.query(Token).filter(
            Token.user_id == user.id,
            Token.purpose == "password_reset",
            Token.ctime > time.time() - 86400
        ).count
    )

    if recent_tokens_count >= settings.TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please wait 24 hours before trying again."
        )

    token = Token(
        id=encryption_utils.gen_random_string(32),
        purpose="password_reset",
        user_id=user.id,
        etime=time.time() + settings.TOKENS_EXPIRY_SECONDS,
    )

    await run_in_threadpool(db.add, token)
    await run_in_threadpool(db.commit)

    await email_manager.send_password_reset_email(user.email, token.id, background_tasks)

    return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
async def reset_password(
        password_data: PasswordUpdate,
        request: Request,
        db: Session = Depends(db_manager.get_db),
        background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Resets a user's password using a valid token."""
    if not settings.EMAIL_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email functionality is disabled. Password reset is not available."
        )

    user = await _validate_token_and_get_user(
        db=db,
        token_id=password_data.token,
        purpose="password_reset",
        request=request,
        db_manager_instance=db_manager,
        background_tasks=background_tasks,
    )

    await run_in_threadpool(user.set_password, password_data.new_password, await get_remote_address(request),
                            db_manager)
    await run_in_threadpool(db.commit)

    await email_manager.send_password_change_email(user.email, background_tasks)

    return {"message": "Password has been reset successfully."}


@router.get("/verify", response_class=HTMLResponse)
async def verify_email(
        token: str,
        request: Request,
        db: Session = Depends(db_manager.get_db),
        background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Verifies a user's email address using a token."""
    try:
        user = await _validate_token_and_get_user(
            db=db,
            token_id=token,
            purpose="email_verification",
            request=request,
            db_manager_instance=db_manager,
            background_tasks=background_tasks,
        )

        user.email_verified = True
        await run_in_threadpool(db.commit)
        return templates.TemplateResponse("verify_email.html", {"request": request, "message": "Email verified successfully."})
    except HTTPException as e:
        return templates.TemplateResponse("error.html", {"request": request, "message": e.detail})
    except Exception as e:
        logger.error(f"An unexpected error occurred during email verification: {e}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "An unexpected error occurred."})


@router.post("/authorize", response_class=HTMLResponse)
async def authorize_action(
        authorize_data: TokenValidation,
        request: Request,
        db: Session = Depends(db_manager.get_db),
        background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Authorizes a user action using a token."""
    try:
        await _validate_token_and_get_user(
            db=db,
            token_id=authorize_data.token,
            purpose="authorize_action",
            request=request,
            db_manager_instance=db_manager,
            background_tasks=background_tasks,
        )
        return templates.TemplateResponse("authorize_action.html", {"request": request, "message": "Action authorized successfully."})
    except HTTPException as e:
        return templates.TemplateResponse("error.html", {"request": request, "message": e.detail})
    except Exception as e:
        logger.error(f"An unexpected error occurred during action authorization: {e}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "An unexpected error occurred."})


@router.get("/reset-password", response_class=HTMLResponse)
async def show_reset_page(token: str, request: Request, db: Session = Depends(db_manager.get_db)):
    """A placeholder for the password reset page."""
    token_obj = await run_in_threadpool(
        db.query(Token).filter(
            Token.id == token,
            Token.purpose == "password_reset",
        ).first
    )
    if not token_obj or not token_obj.is_valid():
        return templates.TemplateResponse("error.html", {"request": request, "message": "Invalid or expired token."})
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})
