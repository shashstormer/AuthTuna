import io
import logging

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks, status
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.templating import Jinja2Templates

from authtuna.core.config import settings
from authtuna.core.database import User
from authtuna.core.exceptions import InvalidTokenError, OperationForbiddenError
from authtuna.helpers import get_remote_address
from authtuna.helpers.mail import email_manager
from authtuna.helpers.theme import get_theme_css
from authtuna.integrations.fastapi_integration import auth_service, RoleChecker

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mfa", tags=["mfa"])
templates = Jinja2Templates(directory=settings.HTML_TEMPLATE_DIR)
templates.env.globals['get_theme_css'] = get_theme_css


class MFACodePayload(BaseModel):
    code: str


class MFAValidationPayload(BaseModel):
    mfa_token: str
    code: str

class MFALoginValidate(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=11)


@router.post("/setup")
async def setup_mfa(
        user: User = Depends(RoleChecker("User")),
):
    """
    Initiates the TOTP setup process for the currently authenticated user.
    Returns a provisioning URI to be rendered as a QR code by the frontend.
    """
    try:
        _, provisioning_uri = await auth_service.mfa.setup_totp(user, issuer_name=settings.APP_NAME)
        return {"provisioning_uri": provisioning_uri}
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/verify")
async def verify_mfa_setup(
        payload: MFACodePayload,
        user: User = Depends(RoleChecker("User")),
        background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Verifies the TOTP code to complete the setup process and enable MFA.
    Returns a list of one-time recovery codes.
    """
    try:
        recovery_codes = await auth_service.mfa.verify_and_enable_totp(user, payload.code)
        await email_manager.send_mfa_added_email(user.email, background_tasks)
        return {"recovery_codes": recovery_codes}
    except (InvalidTokenError, OperationForbiddenError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/qr-code")
async def get_qr_code(uri: str):
    """
    Generates and returns a QR code image from a given URI.
    This is used by the frontend to display the QR code for scanning.
    """
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@router.post("/validate-login")
async def validate_mfa_login(login_data: MFALoginValidate, request: Request, background_tasks: BackgroundTasks):
    """
    Validates the MFA code during login to complete the authentication process by
    calling the dedicated service method.
    """
    try:
        session = await auth_service.validate_mfa_login(
            mfa_token=login_data.mfa_token,
            code=login_data.code,
            ip_address=await get_remote_address(request),
            device_data=request.state.device_data,
            background_tasks=background_tasks,
        )
        response = JSONResponse({"message": "Login successful."})
        response.set_cookie(
            key=settings.SESSION_TOKEN_NAME,
            value=session.get_cookie_string(),
            samesite=settings.SESSION_SAME_SITE,
            secure=settings.SESSION_SECURE,
            httponly=True,
            max_age=settings.SESSION_ABSOLUTE_LIFETIME_SECONDS,
            domain=settings.SESSION_COOKIE_DOMAIN,
        )
        return response
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error during MFA validation: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred.")



@router.post("/disable")
async def disable_mfa(
        user: User = Depends(RoleChecker("User")),
        background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Disables MFA for the currently authenticated user.
    """
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is not enabled for this user.")

    await auth_service.mfa.disable_mfa(user)
    await email_manager.send_mfa_removed_email(user.email, background_tasks)
    return {"message": "MFA has been successfully disabled."}


@router.get("/setup")
async def show_mfa_setup_page(request: Request, user: User = Depends(RoleChecker("User"))):
    """Serves the MFA setup page with a new QR code and setup token."""
    try:
        setup_token, qr_code_uri = await auth_service.mfa.setup_totp(user, settings.APP_NAME)
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request,
            "setup_token": setup_token,
            "qr_code_uri": qr_code_uri
        })
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get("/challenge")
async def show_mfa_challenge_page(request: Request):
    """Serves the page where users enter their MFA code to complete a login."""
    return templates.TemplateResponse("mfa_challenge.html", {"request": request})