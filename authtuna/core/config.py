import logging
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, BaseModel
from typing import List, Optional, Any, Literal

logger = logging.getLogger(__name__)
import os

module_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
_settings_instance: Optional["Settings"] = None

dont_use_env = os.getenv("AUTHTUNA_NO_ENV", "false").lower() in ("true", "1", "t")

class ThemeMode(BaseModel):
    """Defines the color properties for a single theme mode (light or dark)."""
    background_start: str
    background_end: str
    foreground: str  # Primary text color
    muted_foreground: str  # Secondary/less important text
    card: str  # Card backgrounds
    card_foreground: str
    popover: str  # Popover/modal backgrounds
    popover_foreground: str
    primary: str  # Primary interactive element color (buttons, links)
    primary_foreground: str  # Text on primary elements
    secondary: str  # Secondary interactive element
    secondary_foreground: str
    muted: str  # Muted elements, like horizontal rules
    accent: str
    accent_foreground: str
    destructive: str  # Destructive actions (e.g., delete buttons)
    destructive_foreground: str
    border: str
    input: str  # Input field borders
    ring: str  # Focus rings for accessibility

class Theme(BaseModel):
    """Main container for theme settings."""
    mode: Literal["single", "multi", "system"] = "system"
    light: ThemeMode = ThemeMode(
        background_start="#F8FAFC",
        background_end="#FFFFFF",
        foreground="#020817",
        muted_foreground="#64748B",
        card="#FFFFFF",
        card_foreground="#020817",
        popover="#FFFFFF",
        popover_foreground="#020817",
        primary="#6D28D9",
        primary_foreground="#F8FAFC",
        secondary="#F1F5F9",
        secondary_foreground="#0F172A",
        muted="#F1F5F9",
        accent="#F1F5F9",
        accent_foreground="#0F172A",
        destructive="#EF4444",
        destructive_foreground="#F8FAFC",
        border="transparent",
        input="#E2E8F0",
        ring="#94A3B8",
    )
    dark: ThemeMode = ThemeMode(
        background_start="#0B0B0F",
        background_end="#020817",
        foreground="#F8FAFC",
        muted_foreground="#94A3B8",
        card="#777e9145",
        card_foreground="#F8FAFC",
        popover="#020817",
        popover_foreground="#F8FAFC",
        primary="#7C3AED",
        primary_foreground="#F8FAFC",
        secondary="#6572887d",
        secondary_foreground="#F8FAFC",
        muted="#1E293B",
        accent="#93b2e6a8",
        accent_foreground="#F8FAFC",
        destructive="#7F1D1D",
        destructive_foreground="#F8FAFC",
        border="transparent",
        input="#1E293B",
        ring="#475569",
    )


class Settings(BaseSettings):
    """
    Manages all application configuration using Pydantic.
    Loads settings from environment variables for security and flexibility.
    """
    # Application settings
    APP_NAME: str = "AuthTuna"
    ALGORITHM: str = "HS256"  # JWT Encryption algorithm
    API_BASE_URL: str
    TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN: bool = False

    # Security settings
    JWT_SECRET_KEY: SecretStr = SecretStr("dev-secret-key-change-in-production")
    ENCRYPTION_PRIMARY_KEY: SecretStr = SecretStr("dev-encryption-key-change-in-production")
    ENCRYPTION_SECONDARY_KEYS: List[SecretStr] = []
    FERNET_KEYS: List[SecretStr] = []

    # Enable and disable features as you want
    MFA_ENABLED: bool = True
    PASSKEYS_ENABLED: bool = True
    UI_ENABLED: bool = True
    ADMIN_ROUTES_ENABLED: bool = True
    PASSWORDLESS_LOGIN_ENABLED: bool = True
    ONLY_MIDDLEWARE: bool = False  # Use this setting on secondary servers, like you have deployed a instance with ui at auth.example.com and have another server at someapp.example.com then initialize only the session middleware

    # Default initialization settings, You need to manually update in db if already initialized, dosent detect changes
    DEFAULT_SUPERADMIN_PASSWORD: Optional[SecretStr] = None  # Just dont set this and logging into this account will be disabled.
    DEFAULT_ADMIN_PASSWORD: Optional[SecretStr] = None  # this also.
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
    LOCK_SESSION_REGION: bool = True  # Lock session to region based on IP geolocation, depending on security requirements and environments you may want to disable this.
    DISABLE_RANDOM_STRING: bool = False  # IN ENVIRONMENTS WHERE YOU HAVE LONG RUNNING CONNECTIONS, AND HIGH CONCURRENCY, DISABLING THIS WILL HELP PREVENT LOGOUTS DUE TO RANDOM STRING MISMATCH.
    RANDOM_STRING_GRACE: int = 300  # seconds, STORED RANDOM STRINGS IN THIS ROLLING TIMEFRAME WILL BE ACCEPTED.

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
    EMAIL_DOMAINS: List[str] = ["*"]
    TOKENS_EXPIRY_SECONDS: int = 3600
    TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION: int = 5  # max 5 for email verification, max 5 password reset tokens etc etc...
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True

    # Template Locations
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

    # Webauthn settings
    WEBAUTHN_ENABLED: bool = False  # works fully and already deployed on my instance.
    WEBAUTHN_RP_ID: str = "localhost"  # The domain of your site
    WEBAUTHN_RP_NAME: str = "AuthTuna"
    WEBAUTHN_ORIGIN: str = "http://localhost:8000"

    # Authentication strategy: "COOKIE" or "BEARER"
    STRATEGY: Literal["COOKIE", "BEARER", "AUTO"] = "AUTO"
    # Options: "COOKIE", "BEARER", "AUTO", bearer has higher priority works but no way to get token and all yet so will do later. Just use api keys (coming soon).
    # BEARER = API KEY ONLY
    # COOKIE = BROWSER COOKIES AUTH ONLY
    # AUTO = BROWSER COOKIES AUTH OR API KEY (higher pref to bearer token).

    # API KEY CONFIGURATION
    API_KEY_PREFIX_SECRET: str = "sk"
    API_KEY_PREFIX_PUBLISHABLE: str = "pk"
    API_KEY_PREFIX_MASTER: str = "mk"
    API_KEY_PREFIX_OTHER: str = "key"
    MAX_MASTER_KEYS_PER_USER: int = 5
    MAX_API_KEYS_PER_USER: int = 100
    MAX_SCOPES_PER_SECRET_KEY: int = 0  # 0 = unlimited
    KEY_HASH_ALGORITHM: Literal["SHA256", "SHA384", "SHA512"] = "SHA384"

    # Rate limiting settings for login
    MAX_LOGIN_ATTEMPTS_PER_IP: int = 10  # Max login attempts per IP address
    MAX_LOGIN_ATTEMPTS_PER_USER: int = 5  # Max login attempts per user account
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 900  # 15 minutes window for rate limiting
    LOGIN_LOCKOUT_DURATION_SECONDS: int = 1800  # 30 minutes lockout after exceeding limits

    # THEME CONFIG
    THEME: Theme = Theme()
    model_config = SettingsConfigDict(env_file=None if dont_use_env else os.getenv("ENV_FILE_NAME", ".env"), env_file_encoding='utf-8',
                                      extra='ignore')


def init_settings(**kwargs: Any) -> "Settings":
    """
    Initializes or re-initializes the global settings singleton. This should
    be called explicitly at the start of your application, especially for
    testing or when using a secrets manager.

    Args:
        **kwargs: Keyword arguments to initialize settings with.
        If you want to override specific settings in your environment, pass USE_ENV=True with params to override.
    """
    global _settings_instance, dont_use_env
    if _settings_instance is not None:
        logger.warning("Settings have already been initialized. Re-initializing.")
    dont_use_env = kwargs.get("dont_use_env", True)
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
        if dont_use_env:
            raise RuntimeError(
                "AUTHTUNA_NO_ENV is set. Settings must be initialized manually "
                "by calling `init_settings()` at application startup."
            )
        else:
            logger.debug("Auto-initializing settings on first access.")
            _settings_instance = init_settings(dont_use_env=False)
    return _settings_instance


# --- The Global Settings Proxy ---
# This proxy object allows other modules to do `from authtuna.core.config import settings`
# and use it as before. The magic happens in `__getattr__`, which calls `get_settings()`
# the very first time any attribute (e.g., `settings.APP_NAME`) is accessed.
# This provides the just-in-time, conditional initialization.

class _SettingsProxy:
    def __getattr__(self, name: str) -> Any:  # WAS TRYING TO ADD TYPEHINT SO AUTOCOMPLETE WILL WORK FOR `settings.VAR` BUT ITS NOT WORKING IF SOMEONE KNOWS HLP.
        return getattr(get_settings(), name)


settings = _SettingsProxy()
