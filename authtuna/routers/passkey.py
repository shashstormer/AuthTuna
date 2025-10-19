"""
API endpoints for managing and authenticating with passkeys (WebAuthn).
"""
import base64
from fastapi import APIRouter, Depends, Request, HTTPException, status, Body
from pydantic import BaseModel, Field
from typing import List, Optional

from authtuna.integrations import get_current_user, auth_service
from webauthn.helpers.structs import PublicKeyCredentialUserEntity
from authtuna.core.database import User
from authtuna.core.exceptions import InvalidTokenError
from authtuna.helpers import create_session_and_set_cookie


def to_camel_case(snake_str: str) -> str:
    """Converts a snake_case string to camelCase."""
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])

def convert_keys_to_camel_case(obj):
    """Recursively converts keys in a dictionary or object to camelCase."""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            new_key = to_camel_case(k)
            new_obj[new_key] = convert_keys_to_camel_case(v)
        return new_obj
    elif isinstance(obj, list):
        return [convert_keys_to_camel_case(item) for item in obj]
    elif isinstance(obj, PublicKeyCredentialUserEntity):
        return convert_keys_to_camel_case(obj.__dict__)
    else:
        return obj


class PasskeyRegistrationResponse(BaseModel):
    id: str
    rawId: str
    response: dict
    type: str
    clientExtensionResults: dict
    authenticatorAttachment: Optional[str] = None


class PasskeyAuthenticationResponse(BaseModel):
    id: str
    rawId: str
    response: dict
    type: str
    clientExtensionResults: dict
    authenticatorAttachment: Optional[str] = None


class NewPasskey(BaseModel):
    name: str = Field(..., description="A user-friendly name for the new passkey, e.g., 'My Laptop'.")
    registration_response: PasskeyRegistrationResponse


class PasskeyInfo(BaseModel):
    id: str
    name: str


router = APIRouter(prefix="/passkeys", tags=["Passkeys"])


@router.get("/", response_model=List[PasskeyInfo])
async def get_user_passkeys(user: User = Depends(get_current_user)):
    """Retrieves a list of all passkeys registered by the current user."""
    credentials = await auth_service.passkeys.get_credentials_for_user(user.id)
    return [{"id": cred.id, "name": cred.name} for cred in credentials]


@router.post("/register-options", status_code=status.HTTP_200_OK)
async def generate_registration_options(request: Request, user: User = Depends(get_current_user)):
    """
    Generate registration options for creating a new passkey.
    The server generates a challenge that is stored in the session for verification.
    """
    existing_credentials = await auth_service.passkeys.get_credentials_for_user(user.id)
    options = auth_service.passkeys.logic.generate_registration_options(
        user=user,
        existing_credentials=existing_credentials
    )
    options = options.__dict__
    options_dict = convert_keys_to_camel_case(options)
    options_dict['challenge'] = base64.urlsafe_b64encode(options["challenge"]).decode('ascii')
    request.session['passkey_registration_challenge'] = options_dict['challenge']
    if options_dict.get("excludeCredentials") is None:
        options_dict["excludeCredentials"] = []
    if options_dict.get("hints") is None:
        options_dict["hints"] = []
    return options_dict


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def verify_and_save_registration(
        payload: NewPasskey,
        request: Request,
        user: User = Depends(get_current_user)
):
    """
    Verify the browser's registration response and save the new passkey credential.
    """
    challenge_b64 = request.session.pop('passkey_registration_challenge', None)
    if not challenge_b64:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No registration challenge found in session.")

    try:
        await auth_service.passkeys.register_new_credential(
            user=user,
            name=payload.name,
            registration_response=payload.registration_response.model_dump(),
            challenge=base64.urlsafe_b64decode(challenge_b64)
        )
        return {"message": f"Passkey '{payload.name}' registered successfully."}
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/authenticate-options", status_code=status.HTTP_200_OK)
async def generate_authentication_options(request: Request):
    """
    Generate authentication options to challenge the user for a passkey login.
    """
    options = auth_service.passkeys.logic.generate_authentication_options()
    options = options.__dict__
    options_camel_case = convert_keys_to_camel_case(options)

    options_camel_case['challenge'] = base64.urlsafe_b64encode(options['challenge']).decode('ascii')
    request.session['passkey_authentication_challenge'] = options_camel_case['challenge']

    if options_camel_case.get("allowCredentials") is None:
        options_camel_case["allowCredentials"] = []

    return options_camel_case


@router.post("/authenticate", status_code=status.HTTP_200_OK)
async def verify_authentication(
        request: Request,
        response_data: PasskeyAuthenticationResponse = Body(...)
):
    """
    Verify a passkey authentication and, if successful, create a new session for the user.
    """
    challenge_b64 = request.session.pop('passkey_authentication_challenge', None)
    if not challenge_b64:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No authentication challenge found in session.")

    try:
        user = await auth_service.passkeys.verify_authentication_and_get_user(
            authentication_response=response_data.model_dump(),
            challenge=base64.urlsafe_b64decode(challenge_b64)
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")

        response = await create_session_and_set_cookie(user, request)
        return response

    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))