"""
API endpoints for managing and authenticating with passkeys (WebAuthn).
"""
from fastapi import APIRouter, Depends, Request, HTTPException, status, Body
from pydantic import BaseModel, Field
from typing import List, Optional

from authtuna.integrations import get_current_user, auth_service
from authtuna.core.database import User
from authtuna.core.exceptions import InvalidTokenError
from authtuna.helpers import create_session_and_set_cookie


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

    request.session['passkey_registration_challenge'] = options.challenge.decode('utf-8')

    return options.model_dump()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def verify_and_save_registration(
        payload: NewPasskey,
        request: Request,
        user: User = Depends(get_current_user)
):
    """
    Verify the browser's registration response and save the new passkey credential.
    """
    challenge_str = request.session.pop('passkey_registration_challenge', None)
    if not challenge_str:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No registration challenge found in session.")

    try:
        await auth_service.passkeys.register_new_credential(
            user=user,
            name=payload.name,
            registration_response=payload.registration_response.model_dump(),
            challenge=challenge_str.encode('utf-8')
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

    request.session['passkey_authentication_challenge'] = options['challenge'].decode('utf-8')

    return options


@router.post("/authenticate", status_code=status.HTTP_200_OK)
async def verify_authentication(
        request: Request,
        response_data: PasskeyAuthenticationResponse = Body(...)
):
    """
    Verify a passkey authentication and, if successful, create a new session for the user.
    """
    challenge_str = request.session.pop('passkey_authentication_challenge', None)
    if not challenge_str :
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No authentication challenge found in session.")
    if not isinstance(challenge_str, str):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error: challenge str is not str")
    try:
        user = await auth_service.passkeys.verify_authentication_and_get_user(
            authentication_response=response_data.model_dump(),
            challenge=challenge_str.encode('utf-8')
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")

        response = await create_session_and_set_cookie(user, request)
        return response

    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
