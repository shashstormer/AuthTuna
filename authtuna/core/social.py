import logging
from authlib.integrations.starlette_client import OAuth, OAuthError

from authtuna.core.config import settings

logger = logging.getLogger(__name__)

# Initialize the OAuth registry. This object will manage all our social clients.
oauth = OAuth()

# --- OAuth Provider Registration ---


if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
    try:
        oauth.register(
            name='google',
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
    except OAuthError as e:
        logger.error(f"Failed to register Google OAuth client: {e}")


if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
    try:
        oauth.register(
            name='github',
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET.get_secret_value(),
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            api_base_url='https://api.github.com/',
            redirect_uri=settings.API_BASE_URL + '/auth/github/callback',
            client_kwargs={
                'scope': 'user:email read:user'
            }
        )
    except OAuthError as e:
        logger.error(f"Failed to register GitHub OAuth client: {e}")


def get_social_provider(provider_name: str):
    """
    Retrieves a registered social provider client by its name.

    Args:
        provider_name (str): The name of the provider (e.g., 'google', 'github').

    Returns:
        The OAuth client instance, or None if not found.
    """
    try:
        return getattr(oauth, provider_name, None)
    except AttributeError:
        return None
