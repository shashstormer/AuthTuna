import pytest
import time
from unittest.mock import MagicMock, patch
from authtuna.core.passkeys import PasskeysCore
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings
import json
import cbor2
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes

@pytest.fixture
def passkeys_core():
    """Provides a PasskeysCore instance for testing."""
    return PasskeysCore()

def test_generate_registration_options(passkeys_core):
    """
    Tests the generation of registration options to ensure they are well-formed.
    """
    user_id = "test_user_id"
    username = "test_user"
    existing_credentials = []

    options, session_challenge = passkeys_core.generate_registration_options(
        user_id, username, existing_credentials
    )

    # Validate the structure of the options dictionary
    assert "rp" in options
    assert "user" in options
    assert "challenge" in options
    assert "pubKeyCredParams" in options
    assert "authenticatorSelection" in options

    # Validate user information
    assert options["user"]["name"] == username
    assert options["user"]["displayName"] == username

    # Validate the session challenge
    assert "challenge" in session_challenge
    assert "timestamp" in session_challenge
    assert options["challenge"] == session_challenge["challenge"]

def test_generate_authentication_options(passkeys_core):
    """
    Tests the generation of authentication options to ensure they are well-formed.
    """
    options, session_challenge = passkeys_core.generate_authentication_options(
        existing_credentials=[]
    )

    # Validate the structure of the options dictionary
    assert "challenge" in options
    assert "allowCredentials" in options
    assert "userVerification" in options
    assert options["userVerification"] == "required"

    # Validate the session challenge
    assert "challenge" in session_challenge
    assert "timestamp" in session_challenge
    assert options["challenge"] == session_challenge["challenge"]

def test_generate_auth_options_with_credentials(passkeys_core):
    """
    Tests generation of authentication options with existing credentials.
    """
    class MockCredential:
        def __init__(self, cred_id):
            self.id = cred_id

    existing_credentials = [MockCredential(b'cred1'), MockCredential(b'cred2')]

    options, _ = passkeys_core.generate_authentication_options(existing_credentials)

    assert len(options["allowCredentials"]) == 2
    assert options["allowCredentials"][0]["type"] == "public-key"
    assert "id" in options["allowCredentials"][0]

@pytest.fixture
def mock_session_challenge():
    return {
        "challenge": encryption_utils.base64url_encode(b"test_challenge"),
        "timestamp": time.time(),
    }

def test_verify_registration_expired_challenge(passkeys_core, mock_session_challenge, monkeypatch):
    """
    Tests that registration verification fails if the challenge has expired.
    """
    monkeypatch.setattr(time, "time", lambda: mock_session_challenge["timestamp"] + 300)
    with pytest.raises(ValueError, match="Challenge expired"):
        passkeys_core.verify_registration({}, mock_session_challenge)

def test_verify_registration_challenge_mismatch(passkeys_core, mock_session_challenge):
    """
    Tests that registration verification fails if the client data challenge does not match.
    """
    client_data = {
        "type": "webauthn.create",
        "challenge": encryption_utils.base64url_encode(b"wrong_challenge"),
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
        }
    }
    with pytest.raises(ValueError, match="Challenge mismatch"):
        passkeys_core.verify_registration(response, mock_session_challenge)

def test_verify_registration_invalid_type(passkeys_core, mock_session_challenge):
    """
    Tests that verification fails if the client data type is not 'webauthn.create'.
    """
    client_data = {
        "type": "webauthn.get",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
        }
    }
    with pytest.raises(ValueError, match="Invalid client data type"):
        passkeys_core.verify_registration(response, mock_session_challenge)

def test_verify_registration_invalid_origin(passkeys_core, mock_session_challenge):
    """
    Tests that verification fails if the origin does not match the RP ID.
    """
    client_data = {
        "type": "webauthn.create",
        "challenge": mock_session_challenge["challenge"],
        "origin": "https://evil.com",
    }
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
        }
    }
    with pytest.raises(ValueError, match="not valid for RP ID"):
        passkeys_core.verify_registration(response, mock_session_challenge)

def _create_mock_attestation_object(correct_rp_id=True, correct_flags=True, key_type='ec'):
    """Helper function to create a mock attestation object for testing."""
    if key_type == 'ec':
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        cose_key = {
            1: 2, 3: -7, -1: 1,
            -2: public_numbers.x.to_bytes(32, 'big'),
            -3: public_numbers.y.to_bytes(32, 'big'),
        }
    elif key_type == 'rsa':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        cose_key = {
            1: 3, 3: -257,
            -1: public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big'),
            -2: public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big'),
        }

    rp_id = settings.WEBAUTHN_RP_ID if correct_rp_id else "evil.com"
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()

    flags = 0b01000001 if correct_flags else 0b00000000 # User Present and Attested Credential Data
    sign_count = 0
    aaguid = os.urandom(16)
    credential_id = os.urandom(16)
    credential_id_len = len(credential_id).to_bytes(2, 'big')

    auth_data = (
        rp_id_hash +
        flags.to_bytes(1, 'big') +
        sign_count.to_bytes(4, 'big') +
        aaguid +
        credential_id_len +
        credential_id +
        cbor2.dumps(cose_key)
    )

    attestation_object = {
        "fmt": "none",
        "authData": auth_data,
        "attStmt": {},
    }
    return attestation_object, credential_id, private_key, cose_key

def test_verify_registration_success(passkeys_core, mock_session_challenge):
    """
    Tests a successful registration verification.
    """
    client_data = {
        "type": "webauthn.create",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    attestation_object, credential_id, _, _ = _create_mock_attestation_object()
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
            "attestationObject": encryption_utils.base64url_encode(cbor2.dumps(attestation_object)),
        }
    }
    result = passkeys_core.verify_registration(response, mock_session_challenge)
    assert result["credential_id"] == credential_id

def test_verify_registration_rp_id_hash_mismatch(passkeys_core, mock_session_challenge):
    """
    Tests that registration verification fails if the RP ID hash does not match.
    """
    client_data = {
        "type": "webauthn.create",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    attestation_object, _, _, _ = _create_mock_attestation_object(correct_rp_id=False)
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
            "attestationObject": encryption_utils.base64url_encode(cbor2.dumps(attestation_object)),
        }
    }
    with pytest.raises(ValueError, match="RP ID hash mismatch"):
        passkeys_core.verify_registration(response, mock_session_challenge)

def test_verify_registration_user_present_flag_not_set(passkeys_core, mock_session_challenge):
    """
    Tests that registration verification fails if the user present flag is not set.
    """
    client_data = {
        "type": "webauthn.create",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    attestation_object, _, _, _ = _create_mock_attestation_object(correct_flags=False)
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
            "attestationObject": encryption_utils.base64url_encode(cbor2.dumps(attestation_object)),
        }
    }
    with pytest.raises(ValueError, match="User Present flag not set"):
        passkeys_core.verify_registration(response, mock_session_challenge)

def test_verify_authentication_expired_challenge(passkeys_core, mock_session_challenge, monkeypatch):
    """
    Tests that authentication verification fails if the challenge has expired.
    """
    monkeypatch.setattr(time, "time", lambda: mock_session_challenge["timestamp"] + 300)
    with pytest.raises(ValueError, match="Challenge expired"):
        passkeys_core.verify_authentication({}, mock_session_challenge, MagicMock())

def test_verify_authentication_challenge_mismatch(passkeys_core, mock_session_challenge):
    """
    Tests that authentication verification fails if the client data challenge does not match.
    """
    client_data = {
        "type": "webauthn.get",
        "challenge": encryption_utils.base64url_encode(b"wrong_challenge"),
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
        }
    }
    with pytest.raises(ValueError, match="Challenge mismatch"):
        passkeys_core.verify_authentication(response, mock_session_challenge, MagicMock())

def test_verify_authentication_invalid_origin(passkeys_core, mock_session_challenge):
    """
    Tests that authentication verification fails if the origin does not match the RP ID.
    """
    client_data = {
        "type": "webauthn.get",
        "challenge": mock_session_challenge["challenge"],
        "origin": "https://evil.com",
    }
    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(json.dumps(client_data).encode()),
        }
    }
    with pytest.raises(ValueError, match="not valid for RP ID"):
        passkeys_core.verify_authentication(response, mock_session_challenge, MagicMock())

def test_verify_authentication_success_ec(passkeys_core, mock_session_challenge):
    """
    Tests a successful authentication verification with an EC key.
    """
    _, _, private_key, cose_key = _create_mock_attestation_object(key_type='ec')
    mock_credential = MagicMock()
    mock_credential.public_key = cbor2.dumps(cose_key)
    mock_credential.sign_count = 0

    client_data = {
        "type": "webauthn.get",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    client_data_json_bytes = json.dumps(client_data).encode()

    rp_id_hash = hashlib.sha256(settings.WEBAUTHN_RP_ID.encode("utf-8")).digest()
    flags = 0b00000101  # User Present and User Verified
    sign_count = 1
    auth_data = (
        rp_id_hash +
        flags.to_bytes(1, 'big') +
        sign_count.to_bytes(4, 'big')
    )

    signed_data = auth_data + hashlib.sha256(client_data_json_bytes).digest()
    signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(client_data_json_bytes),
            "authenticatorData": encryption_utils.base64url_encode(auth_data),
            "signature": encryption_utils.base64url_encode(signature),
        }
    }
    new_sign_count = passkeys_core.verify_authentication(response, mock_session_challenge, mock_credential)
    assert new_sign_count == sign_count

def test_verify_authentication_success_rsa(passkeys_core, mock_session_challenge):
    """
    Tests a successful authentication verification with an RSA key.
    """
    _, _, private_key, cose_key = _create_mock_attestation_object(key_type='rsa')
    mock_credential = MagicMock()
    mock_credential.public_key = cbor2.dumps(cose_key)
    mock_credential.sign_count = 0

    client_data = {
        "type": "webauthn.get",
        "challenge": mock_session_challenge["challenge"],
        "origin": f"https://{settings.WEBAUTHN_RP_ID}",
    }
    client_data_json_bytes = json.dumps(client_data).encode()

    rp_id_hash = hashlib.sha256(settings.WEBAUTHN_RP_ID.encode("utf-8")).digest()
    flags = 0b00000101
    sign_count = 1
    auth_data = (
        rp_id_hash +
        flags.to_bytes(1, 'big') +
        sign_count.to_bytes(4, 'big')
    )

    signed_data = auth_data + hashlib.sha256(client_data_json_bytes).digest()
    signature = private_key.sign(
        signed_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    response = {
        "response": {
            "clientDataJSON": encryption_utils.base64url_encode(client_data_json_bytes),
            "authenticatorData": encryption_utils.base64url_encode(auth_data),
            "signature": encryption_utils.base64url_encode(signature),
        }
    }
    new_sign_count = passkeys_core.verify_authentication(response, mock_session_challenge, mock_credential)
    assert new_sign_count == sign_count
