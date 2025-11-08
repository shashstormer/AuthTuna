import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status, Response, BackgroundTasks
from pydantic import BaseModel, Field

from authtuna import settings
from authtuna.core.database import User
from authtuna.core.encryption import encryption_utils
from authtuna.core.exceptions import UserNotFoundError, InvalidTokenError, TokenExpiredError
from authtuna.helpers import create_session_and_set_cookie, get_remote_address
from authtuna.helpers.mail import email_manager
from authtuna.integrations import auth_service, RoleChecker

router = APIRouter(prefix="/passkeys", tags=["Passkeys"])


# --- Pydantic Models ---
class PasskeyRegistrationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    registration_response: Dict[str, Any]


class PasskeyAuthenticationRequest(BaseModel):
    response: Dict[str, Any]


class PasskeyResponse(BaseModel):
    id: str
    name: str


class PasskeyMFALoginRequest(BaseModel):
    mfa_token: str
    response: Dict[str, Any]



@router.post("/register-options", summary="Generate options for passkey registration")
async def generate_register_options(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Generates the challenge and options needed to start a passkey registration ceremony.
    The challenge is stored in the user's server-side session for verification.
    """
    # Invalidate any old challenge before creating a new one.
    if "passkey_registration_challenge" in request.session:
        del request.session["passkey_registration_challenge"]

    existing_credentials = await auth_service.passkeys.get_for_user(user.id)
    options, session_challenge = auth_service.passkeys.core.generate_registration_options(
        user_id=user.id, username=user.username, existing_credentials=existing_credentials
    )
    request.session["passkey_registration_challenge"] = session_challenge
    return options


@router.post("/register", status_code=status.HTTP_201_CREATED, summary="Register a new passkey")
async def register_passkey(payload: PasskeyRegistrationRequest, request: Request,
                           user: User = Depends(RoleChecker("User"))):
    """
    Verifies the response from the browser's registration ceremony and saves the new credential.
    """
    session_challenge = request.session.pop("passkey_registration_challenge", None)
    if not session_challenge:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No registration challenge found. Please try again.")
    try:
        verified_data = auth_service.passkeys.core.verify_registration(
            response=payload.registration_response, session_challenge=session_challenge
        )
        await auth_service.passkeys.save_new_credential(
            user_id=user.id, cred_data=verified_data, nickname=payload.name
        )
        return {"status": "ok", "verified": True}
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.post("/login-options", summary="Generate options for passwordless passkey login")
async def generate_login_options(request: Request):
    """
    Generates options for a passwordless login. This endpoint is public.
    """
    if "passkey_authentication_challenge" in request.session:
        del request.session["passkey_authentication_challenge"]

    options, session_challenge = auth_service.passkeys.core.generate_authentication_options()
    request.session["passkey_authentication_challenge"] = session_challenge
    return options


@router.post("/login", summary="Verify passkey authentication and create a session")
async def login_with_passkey(payload: PasskeyAuthenticationRequest, request: Request, response: Response, background_tasks: BackgroundTasks):
    """
    Verifies a passkey assertion and, if successful, creates a new user session.
    """
    session_challenge = request.session.pop("passkey_authentication_challenge", None)
    if not session_challenge:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No authentication challenge found. Please try again.")

    try:
        credential_id = encryption_utils.base64url_decode(payload.response["id"])
        db_credential = await auth_service.passkeys.get_credential_by_id(credential_id)

        if not db_credential:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "This passkey is not registered with our service.")

        new_sign_count = auth_service.passkeys.core.verify_authentication(
            response=payload.response, session_challenge=session_challenge, credential=db_credential
        )

        await auth_service.passkeys.update_credential_on_login(credential_id, new_sign_count)

        user = await auth_service.users.get_by_id(db_credential.user_id)
        if not user or not user.is_active:
            raise UserNotFoundError("The user associated with this passkey is not found or is inactive.")

        await create_session_and_set_cookie(user, request, response, auth_service.db_manager.get_db())
        if settings.EMAIL_ENABLED:
            await email_manager.send_new_login_email(user.email, background_tasks, {
                "username": user.username,
                "region": request.state.device_data["region"],
                "ip_address": await get_remote_address(request),
                "device": request.state.device_data["device"],
                "login_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        return {"status": "ok", "message": "Login successful."}
    except (ValueError, UserNotFoundError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.get("/", response_model=List[PasskeyResponse], summary="List all passkeys for the current user")
async def list_passkeys(user: User = Depends(RoleChecker("User"))):
    """
    Returns a list of all passkeys registered to the current user.
    """
    credentials = await auth_service.passkeys.get_for_user(user.id)
    return [
        PasskeyResponse(id=encryption_utils.base64url_encode(cred.id), name=cred.nickname)
        for cred in credentials
    ]


@router.delete("/{credential_id_b64}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a passkey")
async def delete_passkey(credential_id_b64: str, user: User = Depends(RoleChecker("User"))):
    """
    Deletes a specific passkey for the currently authenticated user.
    """
    success = await auth_service.passkeys.delete_credential(user.id, credential_id_b64)
    if not success:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found or you do not have permission to delete it.")


@router.post("/mfa-login", summary="Verify passkey as a second factor and create a session")
async def mfa_login_with_passkey(payload: PasskeyMFALoginRequest, request: Request, response: Response):
    """
    Handles the second factor of a login flow using a passkey.
    It validates the initial mfa_token and the passkey assertion.
    """
    # 1. Validate the MFA token from the first login step
    try:
        async with auth_service.db_manager.get_db() as db:
            ip_address = request.state.user_ip_address
            user = await auth_service.tokens.validate(db, payload.mfa_token, "mfa_validation", ip_address)
            await db.commit()  # Commit the token usage
    except (InvalidTokenError, TokenExpiredError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # 2. Proceed with passkey verification
    session_challenge = request.session.pop("passkey_authentication_challenge", None)
    if not session_challenge:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No authentication challenge found. Please try again.")

    try:
        credential_id = encryption_utils.base64url_decode(payload.response["id"])
        db_credential = await auth_service.passkeys.get_credential_by_id(credential_id)

        if not db_credential or db_credential.user_id != user.id:
            raise ValueError("This passkey is not registered to your account.")

        new_sign_count = auth_service.passkeys.core.verify_authentication(
            response=payload.response, session_challenge=session_challenge, credential=db_credential
        )

        await auth_service.passkeys.update_credential_on_login(credential_id, new_sign_count)

        # 3. If verification is successful, create a new session for the user
        await create_session_and_set_cookie(user, request, response, auth_service.db_manager.get_db())

        return {"status": "ok", "message": "Login successful."}
    except (ValueError, UserNotFoundError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


passkey_router = router
