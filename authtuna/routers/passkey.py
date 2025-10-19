# WAS USING WEBAUTHN the library too trash. IMA BUILD NEW PASSKEY SYSTEM FROM SCRATCH WITH W3C STANDARDS.
from fastapi import APIRouter

router = APIRouter(prefix="/passkeys", tags=["passkeys"])

passkey_router = router
