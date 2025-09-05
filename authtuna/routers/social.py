import logging
import time

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse

from authtuna.core.database import db_manager, User, SocialAccount
from authtuna.core.encryption import encryption_utils
from authtuna.core.social import get_social_provider
from authtuna.helpers import create_session_and_set_cookie, generate_random_username, sanitize_username

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["social"])


@router.get("/{provider_name}/login")
async def social_login(provider_name: str, request: Request):
    """Redirects to the social provider's authorization page."""
    provider = get_social_provider(provider_name)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Social provider '{provider_name}' not found."
        )
    return await provider.authorize_redirect(request, f"/auth/{provider_name}/callback")


@router.get("/{provider_name}/callback")
async def social_callback(
        provider_name: str,
        request: Request,
        response: Response,
        db: Session = Depends(db_manager.get_db)
):
    """Handles the callback from the social provider."""
    provider = get_social_provider(provider_name)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Social provider '{provider_name}' not found."
        )

    try:
        # Fetch the token and user info from the provider
        token = await provider.authorize_access_token(request)
        user_info = await provider.parse_id_token(request, token)

        # Check if a social account already exists for this provider and user
        social_account = await run_in_threadpool(
            db.query(SocialAccount).filter(
                SocialAccount.provider == provider_name,
                SocialAccount.provider_user_id == str(user_info.get('sub'))
            ).first
        )

        if social_account:
            social_account.access_token = token.get('access_token')
            social_account.refresh_token = token.get('refresh_token')
            social_account.expires_at = token.get('expires_at')
            social_account.last_used_at = time.time()
            await run_in_threadpool(db.commit)
            user = social_account.user
        else:
            user_id = encryption_utils.gen_random_string(32)
            user_email = user_info.get('email')
            raw_username = user_info.get('name')
            sanitized_username = sanitize_username(raw_username)
            user_name = sanitized_username if sanitized_username else generate_random_username()
            existing_user_by_email = await run_in_threadpool(
                db.query(User).filter(User.email == user_email).first
            )
            if existing_user_by_email:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this email already exists. Please log in with your password and link your social account later."
                )
            user = User(
                id=user_id,
                username=user_name,
                email=user_email,
                email_verified=True,
                last_login=time.time()
            )
            await run_in_threadpool(db.add, user)
            await run_in_threadpool(db.flush)
            social_account = SocialAccount(
                user_id=user.id,
                provider=provider_name,
                provider_user_id=str(user_info.get('sub')),
                token_type=token.get('token_type'),
                access_token=token.get('access_token'),
                refresh_token=token.get('refresh_token'),
                expires_at=token.get('expires_at')
            )
            await run_in_threadpool(db.add, social_account)
            await run_in_threadpool(db.commit)

        # Create a new session for the user
        await create_session_and_set_cookie(user, request, response, db)

        return RedirectResponse(url="/")

    except OAuthError as e:
        logger.error(f"OAuth error for {provider_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {e}"
        )
