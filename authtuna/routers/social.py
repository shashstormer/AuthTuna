import logging
import time

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse

# Import necessary modules
from authtuna.core.database import db_manager, User, SocialAccount
from authtuna.core.encryption import encryption_utils
from authtuna.core.social import get_social_provider
from authtuna.helpers import create_session_and_set_cookie, generate_random_username, sanitize_username
from authtuna.helpers.mail import email_manager
from authtuna.core.config import settings

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
    return await provider.authorize_redirect(request, f"{settings.API_BASE_URL}/auth/{provider_name}/callback")


@router.get("/{provider_name}/callback")
async def social_callback(
        provider_name: str,
        request: Request,
        response: Response,
        # This is kept for dependency injection consistency but not used directly for the final return
        background_tasks: BackgroundTasks,
        db: Session = Depends(db_manager.get_db)
):
    """
    Handles the callback from the social provider.
    - If a user with the same email exists, it automatically links the social account.
    - If no user exists, it creates a new one.
    - Sends an email notification when a new account is created or linked.
    """
    provider = get_social_provider(provider_name)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Social provider '{provider_name}' not found."
        )

    try:
        # Fetch the token from the provider
        token = await provider.authorize_access_token(request)

        user_info_raw = {}
        if provider_name == 'google':
            # For OIDC providers like Google, parse the id_token
            user_info_raw = await provider.parse_id_token(request, token)
        elif provider_name == 'github':
            # For OAuth 2.0 providers like GitHub, use the token to fetch user info
            resp = await provider.get('user', token=token)
            resp.raise_for_status()
            profile = resp.json()
            user_info_raw = {
                'sub': str(profile['id']),
                'name': profile.get('name'),
                'email': profile.get('email'),
            }
            if not user_info_raw['email']:
                resp_email = await provider.get('user/emails', token=token)
                resp_email.raise_for_status()
                emails = resp_email.json()
                if emails:
                    primary_email = next((e['email'] for e in emails if e['primary']), None)
                    user_info_raw['email'] = primary_email
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider_name}")

        # Check if this specific social account is already linked
        social_account = await run_in_threadpool(
            db.query(SocialAccount).filter(
                SocialAccount.provider == provider_name,
                SocialAccount.provider_user_id == str(user_info_raw.get('sub'))
            ).first
        )

        if social_account:
            # Case 1: User has logged in with this social provider before.
            social_account.access_token = token.get('access_token')
            social_account.refresh_token = token.get('refresh_token')
            social_account.expires_at = token.get('expires_at')
            social_account.last_used_at = time.time()
            await run_in_threadpool(db.commit)
            user = social_account.user
        else:
            # Helper function to create the social account link and send the notification email.
            async def link_account_and_send_email(user_to_link: User):
                """Creates SocialAccount link and sends notification."""
                new_social_account = SocialAccount(
                    user_id=user_to_link.id,
                    provider=provider_name,
                    provider_user_id=str(user_info_raw.get('sub')),
                    token_type=token.get('token_type'),
                    access_token=token.get('access_token'),
                    refresh_token=token.get('refresh_token'),
                    expires_at=token.get('expires_at')
                )
                db.add(new_social_account)
                await email_manager.send_new_social_account_connected_email(
                    email=user_to_link.email,
                    background_tasks=background_tasks,
                    context={"username": user_to_link.username, "provider": provider_name.capitalize()}
                )

            # Case 2 & 3: This is a new social login. Check if the email exists.
            user_email = user_info_raw.get('email')
            if not user_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not retrieve a valid email address from the social provider."
                )

            user = await run_in_threadpool(
                db.query(User).filter(User.email == user_email).first
            )

            if user:
                # Case 2: Auto-link to an existing local account.
                await link_account_and_send_email(user)
            else:
                # Case 3: Create a new user from scratch.
                user_id = encryption_utils.gen_random_string(32)
                raw_username = user_info_raw.get('name')
                sanitized_username = sanitize_username(raw_username)
                user_name = sanitized_username if sanitized_username else generate_random_username()

                user = User(
                    id=user_id,
                    username=user_name,
                    email=user_email,
                    email_verified=True,
                    last_login=time.time()
                )
                db.add(user)
                await run_in_threadpool(db.flush)
                await link_account_and_send_email(user)
                await email_manager.send_welcome_email(
                    email=user.email,
                    background_tasks=background_tasks,
                    context={"username": user.username}
                )

            await run_in_threadpool(db.commit)

        redirect_response = RedirectResponse(url="/")
        await create_session_and_set_cookie(user, request, redirect_response, db)
        return redirect_response

    except OAuthError as e:
        logger.error(f"OAuth error for {provider_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {e}"
        )

