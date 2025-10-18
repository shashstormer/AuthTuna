"""
Core logic for handling the WebAuthn protocol for passkeys.
This module is responsible for generating challenges and verifying assertions,
acting as a stateless interface to the webauthn library.
"""
from typing import List, Optional

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication

from authtuna.core.config import settings
from authtuna.core.database import User, PasskeyCredential as DBPasskeyCredential


class PasskeyLogic:
    """Handles the server-side logic for the WebAuthn protocol."""

    def __init__(self):
        self.rp_id = settings.WEBAUTHN_RP_ID
        self.rp_name = settings.WEBAUTHN_RP_NAME
        self.expected_origin = settings.WEBAUTHN_ORIGIN

    def generate_registration_options(
        self, user: User, existing_credentials: List[DBPasskeyCredential]
    ) -> PublicKeyCredentialCreationOptions:
        """
        Generate the options for the browser to create a new passkey credential.
        """
        # Exclude already registered credentials to prevent re-registration of the same device
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=cred.id.encode()) for cred in existing_credentials
        ]

        return generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user.id.encode(),
            user_name=user.username,
            exclude_credentials=exclude_credentials,
        )

    def verify_registration(
        self, response_data: dict, challenge: bytes
    ) -> VerifiedRegistration:
        """
        Verify the response from the browser after a registration attempt.
        """
        return verify_registration_response(
            credential=RegistrationCredential(**response_data),
            expected_challenge=challenge,
            expected_origin=self.expected_origin,
            expected_rp_id=self.rp_id,
            require_user_verification=True,  # Enforce user presence (e.g., biometrics/PIN)
        )

    def generate_authentication_options(
        self, allow_credentials: Optional[List[DBPasskeyCredential]] = None
    ) -> PublicKeyCredentialRequestOptions:
        """
        Generate the options for the browser to authenticate with a passkey.
        """

        allow_credentials_descriptors = []
        if allow_credentials:
            allow_credentials_descriptors = [
                PublicKeyCredentialDescriptor(id=cred.id.encode()) for cred in allow_credentials
            ]

        return generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow_credentials_descriptors,
        )

    def verify_authentication(
        self,
        response_data: dict,
        stored_credential: DBPasskeyCredential,
        challenge: bytes,
    ) -> VerifiedAuthentication:
        """
        Verify the response from the browser after an authentication attempt.
        Returns the verified authentication data, including the new sign count.
        """
        return verify_authentication_response(
            credential=AuthenticationCredential(**response_data),
            expected_challenge=challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.expected_origin,
            credential_public_key=stored_credential.public_key.encode(),
            credential_current_sign_count=stored_credential.sign_count,
            require_user_verification=True,
        )
