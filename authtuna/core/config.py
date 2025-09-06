import logging
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr
from typing import List, Optional

logger = logging.getLogger(__name__)
import os
import dotenv

dotenv.load_dotenv()
module_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


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

    # Database settings
    DEFAULT_DATABASE_URI: str = "sqlite:///./authtuna_dev.db"

    # Session settings
    FINGERPRINT_HEADERS: List[str] = ["User-Agent", "Accept-Language"]
    SESSION_DB_VERIFICATION_INTERVAL: int = 10  # Time before rechecking if the token is still active in db
    SESSION_LIFETIME_SECONDS: int = 604800
    SESSION_ABSOLUTE_LIFETIME_SECONDS: int = 31536000
    SESSION_LIFETIME_FROM: str = "last_activity"  # "last_activity" or "creation"
    SESSION_SAME_SITE: str = "LAX"
    SESSION_SECURE: bool = True  # obvio its gon be httponly coz it auth bruh
    SESSION_TOKEN_NAME: str = "session_token"

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
    # OAuth settings
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[SecretStr] = None
    GOOGLE_REDIRECT_URI: Optional[str] = None

    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[SecretStr] = None
    GITHUB_REDIRECT_URI: Optional[str] = None

    model_config = SettingsConfigDict(env_file=os.getenv("ENV_FILE_NAME", ".env"), env_file_encoding='utf-8',
                                      extra='ignore')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.EMAIL_ENABLED:
            assert self.SMTP_HOST, "SMTP_HOST must be set if email is enabled"
            assert self.SMTP_PORT, "SMTP_PORT must be set if email is enabled"
            assert self.DEFAULT_SENDER_EMAIL != "noreply@example.com", "DEFAULT_SENDER_EMAIL must be set if email is enabled"
            if self.DKIM_PRIVATE_KEY_PATH:
                assert self.DKIM_DOMAIN, "DKIM_DOMAIN must be set if DKIM private key path is set"
                assert self.DKIM_SELECTOR, "DKIM_SELECTOR must be set if DKIM private key path is set"
        if self.DEFAULT_DATABASE_URI == "sqlite:///./authtuna_dev.db":
            logger.warning("DEFAULT_DATABASE_URI is set to default value. Change it in production.")
        if self.JWT_SECRET_KEY.get_secret_value() == "dev-secret-key-change-in-production":
            logger.warning("JWT_SECRET_KEY is set to default value. Change it in production.")
        if self.ENCRYPTION_PRIMARY_KEY.get_secret_value() == "dev-encryption-key-change-in-production":
            logger.warning("ENCRYPTION_PRIMARY_KEY is set to default value. Change it in production.")


# Instantiate settings to be imported by other modules
settings = Settings()
