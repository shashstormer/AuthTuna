import base64
import hashlib
import json
import logging
import secrets
import string
import time
from typing import Optional, Sequence
import bcrypt
from cryptography.fernet import Fernet, MultiFernet
from jose import jwt, JWTError
from authtuna.core.config import settings

logger = logging.getLogger(__name__)


class EncryptionUtils:
    """
    A utility class for handling both password hashing and data encryption with key rotation.
    """

    def __init__(self):
        """
        Initializes the EncryptionUtils with a list of base64-encoded Fernet keys.
        The first key in the list is the primary key for encryption.
        The subsequent keys are used for decryption of older data.
        """
        fernet_keys = settings.FERNET_KEYS
        self.fernet_initialized = True
        if not fernet_keys:
            self.fernet_initialized = False
        if fernet_keys is None or not isinstance(fernet_keys, Sequence) or not fernet_keys:
            logger.debug("RANDOM GENERATED FERNET KEY: " + self.generate_new_key())
            raise ValueError("A sequence of at least one Fernet key must be provided.")
        self.fernet_keys = [Fernet(k.get_secret_value().encode('utf-8')) for k in fernet_keys]
        self.multi_fernet = MultiFernet(self.fernet_keys)
        self.jwt_secret = settings.JWT_SECRET_KEY.get_secret_value()
        self.jwt_algorithm = settings.ALGORITHM

    @staticmethod
    def hash_password(password: str, bcrypt_rounds: int = 12) -> str:
        """
        Hashes a password using bcrypt.
        """
        salt = bcrypt.gensalt(bcrypt_rounds)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verifies a plain-text password against a bcrypt hash.
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    @staticmethod
    def hash_key(key: str):
        hasher = hashlib.new(settings.KEY_HASH_ALGORITHM)
        string_bytes = key.encode('utf-8')
        hasher.update(string_bytes)
        key_digest = hasher.digest()
        hashed_key = bcrypt.hashpw(key_digest, bcrypt.gensalt(rounds=12))
        return hashed_key.decode('utf-8')

    @staticmethod
    def verify_key(key: str, hashed_key: str) -> bool:
        """
        Verifies a plain-text key against a hashed key.
        """
        hasher = hashlib.new(settings.KEY_HASH_ALGORITHM)
        string_bytes = key.encode('utf-8')
        hasher.update(string_bytes)
        key_digest = hasher.digest()
        return bcrypt.checkpw(key_digest, hashed_key.encode('utf-8'))

    def encrypt_data(self, data: bytes) -> str:
        """
        Encrypts data using the primary (newest) Fernet key.
        """
        if not self.fernet_initialized:
            raise ValueError("Fernet is not initialized.")
        return self.fernet_keys[0].encrypt(data).decode('utf-8')

    def decrypt_data(self, data: bytes) -> str:
        """
        Decrypts data by attempting all keys in the rotation.
        """
        if not self.fernet_initialized:
            raise ValueError("Fernet is not initialized.")
        return self.multi_fernet.decrypt(data).decode('utf-8')

    @staticmethod
    def gen_random_string(length: int = 8, symbol_set: Optional[Sequence] = None):
        """
        Generates a cryptographically secure random string.
        """
        symbol_set = (string.ascii_letters + string.digits) if symbol_set is None else symbol_set
        return ''.join(secrets.choice(symbol_set) for _ in range(length))

    @staticmethod
    def generate_new_key() -> str:
        """
        Generates a new, URL-safe base64-encoded Fernet key.
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')

    def create_jwt_token(self, data: dict, expires_delta: Optional[int] = None) -> str:
        """
        Creates a new JWT token with an optional expiration time.

        Args:
            data (dict): The payload to be encoded in the JWT.
            expires_delta (Optional[int]): The lifetime of the token in seconds.

        Returns:
            str: The signed JWT token string.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = time.time() + expires_delta
        else:
            expire = time.time() + settings.SESSION_LIFETIME_SECONDS

        to_encode.update({"exp": expire})
        return jwt.encode({"session": self.encrypt_data(json.dumps(to_encode).encode("utf-8"))}, self.jwt_secret, algorithm=self.jwt_algorithm)

    def decode_jwt_token(self, token: str) -> Optional[dict]:
        """
        Decodes a JWT token and returns its payload if valid.

        Args:
            token (str): The JWT token string to decode.

        Returns:
            Optional[dict]: The decoded payload, or None if decoding fails.
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            payload = json.loads(self.decrypt_data(payload["session"]))
            if "exp" in payload and time.time() > payload["exp"]:
                return None
            return payload
        except JWTError as e:
            logger.debug(f"JWT decoding failed: {e}")
            return None

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """
        Encodes bytes to a base64url string without padding.
        """
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """
        Decodes a base64url string without padding to bytes.
        """
        padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
        return base64.urlsafe_b64decode(data + padding)


encryption_utils = EncryptionUtils()
