import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr
from typing import Optional

class ClientSettings(BaseSettings):
    """
    Configuration for authtuna-client, loaded from environment variables or .env file.
    """
    RPC_ADDRESS: str = os.getenv("AUTHTUNA_CLIENT_RPC_ADDRESS", "localhost:50051")
    RPC_TOKEN: SecretStr = SecretStr(os.getenv("AUTHTUNA_CLIENT_RPC_TOKEN", "changeme-secure-token"))
    RPC_TLS_CERT_FILE: Optional[str] = os.getenv("AUTHTUNA_CLIENT_RPC_TLS_CERT_FILE")
    RPC_USE_TLS: bool = os.getenv("AUTHTUNA_CLIENT_RPC_USE_TLS", "false").lower() in ("true", "1", "t")

    model_config = SettingsConfigDict(env_file=os.getenv("ENV_FILE_NAME", ".env"), env_file_encoding='utf-8', extra='ignore')

settings = ClientSettings()

