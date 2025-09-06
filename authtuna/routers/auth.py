import logging
import time

from fastapi import APIRouter, Depends, status, Response, Request, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from authtuna.core.database import db_manager, User, Session as DBSession, Token
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings
from starlette.concurrency import run_in_threadpool
from authtuna.helpers import create_session_and_set_cookie, get_remote_address
from authtuna.helpers.mail import email_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


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
        email_verified=not settings.EMAIL_ENABLED,  # Auto-verify if email is disabled
    )
    await run_in_threadpool(db.add, new_user)
    await run_in_threadpool(db.commit)

    # Use the User model's method to set password and log audit event
    await run_in_threadpool(new_user.set_password, user_data.password, await get_remote_address(request), db_manager)
    await run_in_threadpool(db.commit)
    await run_in_threadpool(db.refresh, new_user)

    if settings.EMAIL_ENABLED:
        token = Token(
            id=encryption_utils.gen_random_string(32),
            purpose="email_verification",
            user_id=new_user.id,
            etime=time.time() + settings.SESSION_LIFETIME_SECONDS,
        )
        await run_in_threadpool(db.add, token)
        await run_in_threadpool(db.commit)

        # Send a verification email and a welcome email
        await email_manager.send_verification_email(new_user.email, token.id, background_tasks)
        await email_manager.send_welcome_email(new_user.email, background_tasks, {"username": new_user.username})

        return Response(
            status_code=status.HTTP_202_ACCEPTED,
            content="User created. A verification email has been sent. Please check your inbox."
        )
    else:
        # If email is disabled, we log the user in directly
        await create_session_and_set_cookie(new_user, request, response, db)
        await email_manager.send_welcome_email(new_user.email, background_tasks, {"username": new_user.username})
        return Response(status_code=status.HTTP_201_CREATED, content="User created successfully. Logged in.")


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

    # Use the User model's method to check password and log audit event
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

    # Send a new login email notification
    await email_manager.send_new_login_email(user.email, background_tasks, {"username": user.username})

    return {"message": "Login successful."}


@router.post("/logout")
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

    # Don't confirm if the email exists to prevent user enumeration attacks
    if not user:
        logger.warning(f"Password reset requested for non-existent email: {request_data.email}")
        return {"message": "If an account with that email exists, a password reset link has been sent."}

    # Create a password reset token
    token = Token(
        id=encryption_utils.gen_random_string(32),
        purpose="password_reset",
        user_id=user.id,
        etime=time.time() + settings.SESSION_LIFETIME_SECONDS,
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

    token = await run_in_threadpool(
        db.query(Token).filter(
            Token.id == password_data.token,
            Token.purpose == "password_reset",
        ).first
    )

    if not token or token.used or token.etime < time.time():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token."
        )

    user = await run_in_threadpool(
        db.query(User).filter(User.id == token.user_id).first
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    await run_in_threadpool(user.set_password, password_data.new_password, await get_remote_address(request),
                            db_manager)
    await run_in_threadpool(token.mark_used, await get_remote_address(request), db_manager)
    await run_in_threadpool(db.commit)

    # Send a password change confirmation email
    await email_manager.send_password_change_email(user.email, background_tasks)

    return {"message": "Password has been reset successfully."}
