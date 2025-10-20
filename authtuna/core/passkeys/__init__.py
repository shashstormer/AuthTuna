import hashlib
import json
import os
import time
from io import BytesIO
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519

from authtuna.core.config import settings
from authtuna.core.database import PasskeyCredential as DBPasskey
from authtuna.core.encryption import encryption_utils

# Define a constant for challenge lifetime in seconds (e.g., 2 minutes)
CHALLENGE_LIFETIME_SECONDS = 120


class PasskeysCore:
    """
    Handles the core WebAuthn logic from scratch. This version is hardened for
    MFA-grade compliance, supporting modern extensions and robust validation.
    """

    def generate_registration_options(
            self, user_id: str, username: str, existing_credentials: List[DBPasskey]
    ) -> tuple[dict, dict]:
        """Generate options for a passkey registration ceremony."""
        challenge = os.urandom(32)
        exclude_credentials = [
            {"type": "public-key", "id": encryption_utils.base64url_encode(cred.id)}
            for cred in existing_credentials
        ]

        options = {
            "rp": {"name": settings.WEBAUTHN_RP_NAME, "id": settings.WEBAUTHN_RP_ID},
            "user": {
                "id": encryption_utils.base64url_encode(user_id.encode("utf-8")),
                "name": username,
                "displayName": username,
            },
            "challenge": encryption_utils.base64url_encode(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -8},  # EdDSA (Ed25519)
                {"type": "public-key", "alg": -257},  # RS256
                {"type": "public-key", "alg": -35},  # ES384
                {"type": "public-key", "alg": -36},  # ES512
                {"type": "public-key", "alg": -37},  # PS256
            ],
            # Omit authenticatorAttachment for maximum compatibility (hybrid flow).
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "preferred",
            },
            "timeout": 120000,
            "attestation": "none",
            "extensions": {
                "credProps": True,
                "largeBlob": {"support": "preferred"},
                "credProtect": 2,  # Level 2 protection: User verification required.
            },
        }

        session_challenge = {"challenge": encryption_utils.base64url_encode(challenge), "timestamp": time.time()}
        return options, session_challenge

    def verify_registration(
            self, response: dict, session_challenge: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Manually verify the client's response from a registration ceremony.
        """
        challenge = encryption_utils.base64url_decode(session_challenge.get("challenge"))
        timestamp = session_challenge.get("timestamp")

        # 1.  Robust Challenge Validation with Skew Tolerance
        if not isinstance(timestamp, (int, float)) or abs(time.time() - timestamp) > CHALLENGE_LIFETIME_SECONDS:
            raise ValueError("Challenge expired or has an invalid timestamp.")

        try:
            client_data_json_bytes = encryption_utils.base64url_decode(response["response"]["clientDataJSON"])
            client_data = json.loads(client_data_json_bytes)

            if client_data["type"] != "webauthn.create": raise ValueError("Invalid client data type.")
            if encryption_utils.base64url_decode(client_data["challenge"]) != challenge: raise ValueError(
                "Challenge mismatch.")

            # 2.  Robust Origin Parsing
            origin_host = urlparse(client_data["origin"]).hostname or ""
            if not (origin_host == settings.WEBAUTHN_RP_ID or origin_host.endswith("." + settings.WEBAUTHN_RP_ID)):
                raise ValueError(f"Origin host '{origin_host}' not valid for RP ID.")

            attestation_object = cbor2.loads(
                encryption_utils.base64url_decode(response["response"]["attestationObject"]))
            auth_data = attestation_object["authData"]

            # 3.  Attestation Format Fallback
            fmt = attestation_object.get("fmt")
            if fmt not in ("none", "packed", "fido-u2f"):
                raise ValueError(f"Unsupported attestation format: {fmt}")

            rp_id_hash, flags, sign_count = auth_data[:32], auth_data[32], int.from_bytes(auth_data[33:37], "big")

            if rp_id_hash != hashlib.sha256(settings.WEBAUTHN_RP_ID.encode("utf-8")).digest():
                raise ValueError("RP ID hash mismatch.")
            if not (flags & 0x01): raise ValueError("User Present flag not set.")
            if not (flags & 0x40): raise ValueError("Attested Credential Data flag not set.")

            # 4.  AAGUID and Safe Remaining Bytes Parsing
            aaguid = auth_data[37:53]
            cred_id_len = int.from_bytes(auth_data[53:55], "big")
            credential_id = auth_data[55: 55 + cred_id_len]

            # Use a stream to safely parse the CBOR-encoded public key and extensions.
            cose_stream = BytesIO(auth_data[55 + cred_id_len:])
            public_key_cose = cbor2.load(cose_stream)
            remaining_bytes = cose_stream.read()

            is_backup_eligible, is_backed_up = False, False
            if flags & 0x80 and remaining_bytes:  # ED (Extension Data) flag is set
                auth_data_extensions = cbor2.loads(remaining_bytes)
                is_backup_eligible = auth_data_extensions.get("be", False)
                is_backed_up = auth_data_extensions.get("bs", False)

            client_extensions = response.get("clientExtensionResults", {})
            is_discoverable = client_extensions.get("credProps", {}).get("rk", False)

            return {
                "credential_id": credential_id,
                "public_key": cbor2.dumps(public_key_cose),
                "sign_count": sign_count,
                "aaguid": aaguid,
                "transports": response.get("response", {}).get("transports", []),
                "is_discoverable": is_discoverable,
                "is_backup_eligible": is_backup_eligible,
                "is_backed_up": is_backed_up,
            }
        except (ValueError, KeyError, IndexError, cbor2.CBORDecodeError) as e:
            raise ValueError(f"Registration verification failed: {e}")

    def generate_authentication_options(
            self, existing_credentials: Optional[List[DBPasskey]] = None
    ) -> tuple[dict, dict]:
        challenge = os.urandom(32)
        allow_credentials = [
            {"type": "public-key", "id": encryption_utils.base64url_encode(cred.id)}
            for cred in (existing_credentials or [])
        ]
        options = {
            "challenge": encryption_utils.base64url_encode(challenge),
            "allowCredentials": allow_credentials,
            "userVerification": "required",
            "rpId": settings.WEBAUTHN_RP_ID,
            "timeout": 120000,
            "extensions": {"largeBlob": {"read": True}},
        }
        session_challenge = {"challenge": encryption_utils.base64url_encode(challenge), "timestamp": time.time()}
        return options, session_challenge

    def verify_authentication(
            self, response: dict, session_challenge: Dict[str, Any], credential: DBPasskey,
    ) -> int:
        challenge = encryption_utils.base64url_decode(session_challenge.get("challenge"))
        timestamp = session_challenge.get("timestamp")

        if not isinstance(timestamp, (int, float)) or abs(time.time() - timestamp) > CHALLENGE_LIFETIME_SECONDS:
            raise ValueError("Challenge expired or has an invalid timestamp.")

        try:
            client_data_json_bytes = encryption_utils.base64url_decode(response["response"]["clientDataJSON"])
            client_data = json.loads(client_data_json_bytes)

            if client_data["type"] != "webauthn.get": raise ValueError("Invalid client data type.")
            if encryption_utils.base64url_decode(client_data["challenge"]) != challenge: raise ValueError(
                "Challenge mismatch.")

            origin_host = urlparse(client_data["origin"]).hostname or ""
            if not (origin_host == settings.WEBAUTHN_RP_ID or origin_host.endswith("." + settings.WEBAUTHN_RP_ID)):
                raise ValueError(f"Origin host '{origin_host}' not valid for RP ID.")

            auth_data = encryption_utils.base64url_decode(response["response"]["authenticatorData"])
            rp_id_hash, flags, new_sign_count = auth_data[:32], auth_data[32], int.from_bytes(auth_data[33:37], "big")

            if rp_id_hash != hashlib.sha256(settings.WEBAUTHN_RP_ID.encode("utf-8")).digest():
                raise ValueError("RP ID hash mismatch.")
            if not (flags & 0x01): raise ValueError("User Present flag not set.")
            if not (flags & 0x04): raise ValueError("User Verified flag not set.")
            if new_sign_count <= credential.sign_count and credential.sign_count != 0:
                raise ValueError("Sign count is not greater than the stored value. Possible clone detected.")

            signature = encryption_utils.base64url_decode(response["response"]["signature"])
            signed_data = auth_data + hashlib.sha256(client_data_json_bytes).digest()

            cose_key = cbor2.loads(credential.public_key)
            key_type, alg = cose_key.get(1), cose_key.get(3)

            if key_type == 1 and alg == -8:  # OKP / EdDSA (Ed25519)
                x = cose_key.get(-2)
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(x)
                public_key.verify(signature, signed_data)

            elif key_type == 2:  # EC2
                crv, x, y = cose_key.get(-1), cose_key.get(-2), cose_key.get(-3)
                curve_map = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
                hash_map = {-7: hashes.SHA256(), -35: hashes.SHA384(), -36: hashes.SHA512()}
                curve, hash_alg = curve_map.get(crv), hash_map.get(alg)
                if not curve or not hash_alg: raise ValueError(f"Unsupported EC curve/alg: {crv}/{alg}")
                public_key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, 'big'), int.from_bytes(y, 'big'),
                                                           curve).public_key()
                public_key.verify(signature, signed_data, ec.ECDSA(hash_alg))

            elif key_type == 3:  # RSA
                n, e = cose_key.get(-1), cose_key.get(-2)
                public_key = rsa.RSAPublicNumbers(int.from_bytes(e, 'big'), int.from_bytes(n, 'big')).public_key()

                if alg == -257:  # RS256
                    public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
                elif alg in [-37, -38, -39]:  # PSS Algorithms
                    hash_alg = {-37: hashes.SHA256(), -38: hashes.SHA384(), -39: hashes.SHA512()}[alg]
                    public_key.verify(
                        signature, signed_data,
                        padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
                        hash_alg
                    )
                else:
                    raise ValueError(f"Unsupported RSA algorithm: {alg}")
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            return new_sign_count

        except (InvalidSignature, ValueError, KeyError, IndexError, cbor2.CBORDecodeError) as e:
            raise ValueError(f"Authentication verification failed: {e}")
