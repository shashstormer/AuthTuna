import logging
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr
from typing import List, Optional, Any

logger = logging.getLogger(__name__)
import os

module_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
_settings_instance: Optional["Settings"] = None

use_env = os.getenv("AUTHTUNA_NO_ENV", "false").lower() in ("true", "1", "t")

class Settings(BaseSettings):
    """
    Manages all application configuration using Pydantic.
    Loads settings from environment variables for security and flexibility.
    """
    # Application settings
    APP_NAME: str = "AuthTuna"
    ALGORITHM: str = "HS256"  # JWT Encryption algorithm
    API_BASE_URL: str
    # Security settings
    JWT_SECRET_KEY: SecretStr = SecretStr("dev-secret-key-change-in-production")
    ENCRYPTION_PRIMARY_KEY: SecretStr = SecretStr("dev-encryption-key-change-in-production")
    ENCRYPTION_SECONDARY_KEYS: List[SecretStr] = []
    FERNET_KEYS: List[SecretStr] = []

    DEFAULT_SUPERADMIN_PASSWORD: Optional[SecretStr] = None
    DEFAULT_ADMIN_PASSWORD: Optional[SecretStr] = None
    DEFAULT_SUPERADMIN_EMAIL: str = "superadmin@example.com"
    DEFAULT_ADMIN_EMAIL: str = "admin@example.com"
    # Database settings
    DEFAULT_DATABASE_URI: str = "sqlite+aiosqlite:///./authtuna_dev.db"  # PROVIDE ASYNC URI
    DATABASE_USE_ASYNC_ENGINE: bool = True  # dosent do anything
    AUTO_CREATE_DATABASE: bool = True  # Automatically create the database tables if they don't exist
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 1800
    DATABASE_POOL_PRE_PING: bool = True

    # Session settings
    FINGERPRINT_HEADERS: List[str] = ["User-Agent", "Accept-Language"]
    SESSION_DB_VERIFICATION_INTERVAL: int = 10  # Time before rechecking if the token is still active in db
    SESSION_LIFETIME_SECONDS: int = 604800
    SESSION_ABSOLUTE_LIFETIME_SECONDS: int = 31536000
    SESSION_LIFETIME_FROM: str = "last_activity"  # "last_activity" or "creation"
    SESSION_SAME_SITE: str = "LAX"
    SESSION_SECURE: bool = True  # obvio its gon be httponly coz it auth bruh so not letting anyone config dat.
    SESSION_TOKEN_NAME: str = "session_token"
    SESSION_COOKIE_DOMAIN: Optional[str] = None

    # Email settings (disabled by default)
    EMAIL_ENABLED: bool = False
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    DKIM_PRIVATE_KEY_PATH: Optional[str] = None
    DKIM_DOMAIN: Optional[str] = None
    DKIM_SELECTOR: Optional[str] = None
    DEFAULT_SENDER_EMAIL: str = "noreply@example.com"
    EMAIL_DOMAINS: List[str] = ["gmail.com"]
    TOKENS_EXPIRY_SECONDS: int = 3600
    TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION: int = 5  # max 5 for email verification, max 5 password reset tokens etc etc...

    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True

    EMAIL_TEMPLATE_DIR: str = os.path.join(module_path, "templates/email")
    HTML_TEMPLATE_DIR: str = os.path.join(module_path, "templates/pages")
    DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR: str = os.path.join(module_path, "templates/dashboard")

    # OAuth settings
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[SecretStr] = None
    GOOGLE_REDIRECT_URI: Optional[str] = None

    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[SecretStr] = None
    GITHUB_REDIRECT_URI: Optional[str] = None

    # RPC settings
    RPC_ENABLED: bool = False  # was working on it, didnt work so left for now will get back to it later, parts of this removed
    RPC_AUTOSTART: bool = True  # If enabled then will autostart by default ()
    RPC_TOKEN: SecretStr = SecretStr("changeme-secure-token")
    RPC_TLS_CERT_FILE: Optional[str] = None
    RPC_TLS_KEY_FILE: Optional[str] = None
    RPC_ADDRESS: str = "[::]:50051"

    # Authentication strategy: "COOKIE" or "BEARER"
    STRATEGY: str = "COOKIE"  # Options: "COOKIE", "BEARER"

    model_config = SettingsConfigDict(env_file=os.getenv("ENV_FILE_NAME", ".env"), env_file_encoding='utf-8',
                                      extra='ignore')


def init_settings(**kwargs: Any) -> "Settings":
    """
    Initializes or re-initializes the global settings singleton. This should
    be called explicitly at the start of your application, especially for
    testing or when using a secrets manager.

    Args:
        **kwargs: Keyword arguments to override settings from the environment.
    """
    global _settings_instance
    if _settings_instance is not None:
        logger.warning("Settings have already been initialized. Re-initializing.")
    # The standard constructor loads from env/.env first, then overrides with kwargs.
    _settings_instance = Settings(**kwargs)
    return _settings_instance


def get_settings() -> "Settings":
    """
    Retrieves the global settings singleton.

    If settings have not been initialized manually via `init_settings()`, this
    function will attempt to auto-initialize them, unless the `AUTHTUNA_NO_ENV`
    flag is set.
    """

    global _settings_instance
    if _settings_instance is None:
        # Check if the user has explicitly disabled auto-initialization
        if use_env:
            raise RuntimeError(
                "AUTHTUNA_NO_ENV is set. Settings must be initialized manually "
                "by calling `init_settings()` at application startup."
            )
        else:
            # Auto-initialize for backward compatibility and simple use cases.
            logger.debug("Auto-initializing settings on first access.")
            _settings_instance = init_settings()

    return _settings_instance


# --- The Global Settings Proxy ---
# This proxy object allows other modules to do `from authtuna.core.config import settings`
# and use it as before. The magic happens in `__getattr__`, which calls `get_settings()`
# the very first time any attribute (e.g., `settings.APP_NAME`) is accessed.
# This provides the just-in-time, conditional initialization.

class _SettingsProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)


settings = _SettingsProxy()
