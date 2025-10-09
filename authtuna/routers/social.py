import logging
import time

from authlib.integrations.starlette_client import OAuthError
from fastapi import (APIRouter, Request, HTTPException, status,
                     Depends, BackgroundTasks)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import RedirectResponse

from authtuna.core.config import settings
from authtuna.core.database import db_manager, User, SocialAccount
from authtuna.core.encryption import encryption_utils
from authtuna.core.social import get_social_provider
from authtuna.helpers import (create_session_and_set_cookie,
                              generate_random_username, sanitize_username)
from authtuna.helpers.mail import email_manager
from authtuna.integrations.fastapi_integration import auth_service

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
    redirect_uri = f"{settings.API_BASE_URL}/auth/{provider_name}/callback"
    return await provider.authorize_redirect(request, redirect_uri)


@router.get("/{provider_name}/callback")
async def social_callback(
        provider_name: str,
        request: Request,
        background_tasks: BackgroundTasks,
        # db: AsyncSession = Depends(db_manager.get_db)
):
    """
    Handles the callback from the social provider, now fully asynchronous.
    """
    async with db_manager.get_db() as db:
        provider = get_social_provider(provider_name)
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Social provider '{provider_name}' not found."
            )

        try:
            token = await provider.authorize_access_token(request)
            user_info_raw = {}
            if provider_name == 'google':
                user_info_raw = await provider.userinfo(token=token)
            elif provider_name == 'github':
                resp = await provider.get('user', token=token)
                resp.raise_for_status()
                profile = resp.json()
                user_info_raw = {'sub': str(profile['id']), 'name': profile.get('name'), 'email': profile.get('email')}
                if not user_info_raw['email']:
                    email_resp = await provider.get('user/emails', token=token)
                    email_resp.raise_for_status()
                    emails = email_resp.json()
                    if emails:
                        user_info_raw['email'] = next((e['email'] for e in emails if e['primary']), None)
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider_name}")

            stmt = select(SocialAccount).options(
                selectinload(SocialAccount.user)
            ).where(
                SocialAccount.provider == provider_name,
                SocialAccount.provider_user_id == str(user_info_raw.get('sub'))
            )
            result = await db.execute(stmt)
            social_account = result.unique().scalar_one_or_none()

            if social_account:
                social_account.access_token = token.get('access_token')
                social_account.refresh_token = token.get('refresh_token')
                social_account.expires_at = token.get('expires_at')
                social_account.last_used_at = time.time()
                await db.commit()
                user = social_account.user
            else:
                user_email = user_info_raw.get('email')
                if not user_email:
                    raise HTTPException(status_code=400, detail="Could not retrieve email from provider.")

                user_stmt = select(User).where(User.email == user_email)
                user_result = await db.execute(user_stmt)
                user = user_result.unique().scalar_one_or_none()

                async def link_account_and_notify(user_to_link: User):
                    db.add(SocialAccount(
                        user_id=user_to_link.id, provider=provider_name,
                        provider_user_id=str(user_info_raw.get('sub')),
                        token_type=token.get('token_type'), access_token=token.get('access_token'),
                        refresh_token=token.get('refresh_token'), expires_at=token.get('expires_at')
                    ))
                    await email_manager.send_new_social_account_connected_email(
                        email=user_to_link.email, background_tasks=background_tasks,
                        context={"username": user_to_link.username, "provider_name": provider_name.capitalize()}
                    )

                if user:
                    await link_account_and_notify(user)
                else:
                    raw_username = user_info_raw.get('name')
                    sanitized = sanitize_username(raw_username)
                    user = User(
                        id=encryption_utils.gen_random_string(32),
                        username=sanitized if sanitized else generate_random_username(),
                        email=user_email, email_verified=True, last_login=time.time()
                    )
                    db.add(user)
                    await db.flush()
                    await link_account_and_notify(user)
                    await email_manager.send_welcome_email(
                        email=user.email, background_tasks=background_tasks,
                        context={"username": user.username}
                    )

                await db.commit()
                await db.refresh(user)

            return_url = request.cookies.get("return_url", "/ui/dashboard")

            if user.mfa_enabled:
                mfa_token = await auth_service.tokens.create(user.id, "mfa_validation", expiry_seconds=300)
                return RedirectResponse(url=f"/mfa/challenge?mfa_token={mfa_token.id}")

            redirect_response = RedirectResponse(url=return_url)
            redirect_response.delete_cookie("return_url")
            await create_session_and_set_cookie(user, request, redirect_response, db)
            return redirect_response

        except OAuthError as e:
            logger.error(f"OAuth error for {provider_name}: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth authentication failed: {e}"
            )
