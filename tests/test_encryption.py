import pytest
from authtuna.core.encryption import EncryptionUtils

@pytest.fixture
def encryption_utils():
    """Fixture to create an EncryptionUtils instance."""
    return EncryptionUtils()

def test_hash_and_verify_password(encryption_utils):
    """Test that password hashing and verification works correctly."""
    password = "test_password"
    hashed_password = encryption_utils.hash_password(password)
    assert encryption_utils.verify_password(password, hashed_password)
    assert not encryption_utils.verify_password("wrong_password", hashed_password)

def test_encrypt_and_decrypt_data(encryption_utils):
    """Test that data encryption and decryption works correctly."""
    data = b"test_data"
    encrypted_data = encryption_utils.encrypt_data(data)
    decrypted_data = encryption_utils.decrypt_data(encrypted_data.encode("utf-8"))
    assert decrypted_data == data.decode("utf-8")

def test_create_and_decode_jwt_token(encryption_utils):
    """Test that JWT token creation and decoding works correctly."""
    data = {"user_id": "123"}
    token = encryption_utils.create_jwt_token(data)
    decoded_data = encryption_utils.decode_jwt_token(token)
    assert "user_id" in decoded_data
    assert decoded_data["user_id"] == data["user_id"]