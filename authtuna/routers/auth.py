import logging
import time
from fastapi import APIRouter, Depends, status, Response, Request, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from authtuna.core.database import db_manager, User, Session as DBSession
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings
from starlette.concurrency import run_in_threadpool
from authtuna.helpers import create_session_and_set_cookie, get_remote_address

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


@router.post("/signup")
async def signup_user(
        user_data: UserSignup,
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db)
):
    """Handles new user registration."""
    # Need to implement email verification will do soon (after i finish mail utils)
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
    )
    await run_in_threadpool(new_user.set_password, user_data.password, await get_remote_address(request))
    await run_in_threadpool(db.add, new_user)
    await run_in_threadpool(db.commit)
    await run_in_threadpool(db.refresh, new_user)
    await create_session_and_set_cookie(new_user, request, response, db)
    return Response(status_code=status.HTTP_201_CREATED, content="User created successfully. Logged in.")


@router.post("/login")
async def login_user(
        login_data: UserLogin,
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db)
):
    """Authenticates a user and creates a new session."""
    # Find the user by either email or username
    user = await run_in_threadpool(
        db.query(User).filter(
            (User.email == login_data.username_or_email) |
            (User.username == login_data.username_or_email)
        ).first
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password."
        )
    password_valid = await run_in_threadpool(user.check_password, login_data.password, await get_remote_address(request))
    if password_valid is None:
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED,
                             detail="Email Not Verified.")
    elif password_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password."
        )
    elif password_valid is True:
        pass
    else:
        raise HTTPException(status_code=500, detail="Internal Server Error (1041).")
    await run_in_threadpool(db.commit)
    if user is not None and isinstance(user, User):
        await create_session_and_set_cookie(user, request, response, db)
    else:
        logger.error(user)
        raise HTTPException(500)
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
            session.active = False
            session.mtime = time.time()
            await run_in_threadpool(db.commit)

    response.delete_cookie(settings.SESSION_TOKEN_NAME)
    return {"message": "Logged out successfully."}


@router.post("/forgot-password")
async def forgot_password(email: str):
    """Placeholder for sending a password reset token via email."""
    # Logic to send an email with a unique token to the user
    # This is a core part of a production system but is omitted here for brevity
    # It would involve creating a `Token` record in the database
    # Here also mail part req so after mail part is ready will get this done
    logger.info(f"Password reset requested for {email}.")
    return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
async def reset_password(token: str, new_password: str):
    """Placeholder for resetting a password using a token."""
    # Logic to validate the token and update the user's password
    # I left it coz i need mail part ready bfr finishing this
    logger.info("Password reset successful.")
    return {"message": "Password has been reset successfully."}
