import logging
import time

from authlib.integrations.starlette_client import OAuthError
from fastapi import (APIRouter, Request, HTTPException, status,
                     BackgroundTasks)
from starlette.responses import RedirectResponse

from authtuna.core.config import settings
from authtuna.core.database import db_manager
from authtuna.core.social import get_social_provider
from authtuna.helpers import (create_session_and_set_cookie)
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

            user_ip = request.client.host or "unknown"
            user_email = user_info_raw.get('email')
            if not user_email:
                 raise HTTPException(status_code=400, detail="Could not retrieve email from provider.")

            user, social_account = await auth_service.register_social_user(
                email=user_email,
                provider=provider_name,
                provider_user_id=str(user_info_raw.get('sub')),
                token_data=token,
                ip_address=user_ip,
                username_candidate=user_info_raw.get('name')
            )
            
            is_new_user = (time.time() - user.created_at) < 10
            if not is_new_user:
                 pass
            
            if is_new_user:
                await email_manager.send_welcome_email(
                    email=user.email, background_tasks=background_tasks,
                    context={"username": user.username}
                )
            else:
                pass
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
