"""
Session middleware for AuthTuna (FastAPI).

This middleware validates and refreshes DB-backed sessions on every request. It uses a dual-state model (server-side session + JWT cookie) and actively checks for session hijacking (region/device/random_string). Integrates tightly with FastAPI and is fully async.
"""

import logging
import time
from typing import Callable, Set, Union

from authtuna.core.config import settings
from authtuna.core.database import Session as DBSession
from authtuna.core.database import db_manager
from authtuna.core.encryption import encryption_utils
from authtuna.helpers import get_device_data, get_remote_address
from fastapi import Request
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class DatabaseSessionMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that validates and refreshes AuthTuna DB-backed sessions.

    - Reads the session cookie and decodes the JWT.
    - Periodically verifies session validity against the database (interval configurable).
    - Checks for session hijack (region/device/random_string mismatch) and invalidates if detected.
    - Refreshes the random_string to prevent replay attacks.
    - Injects request.state.user_id and request.state.session_id for downstream dependencies.
    - Handles public routes and FastAPI docs as unauthenticated by default.
    """

    def __init__(
            self,
            app,
            region_kwargs: dict = None,
            public_routes: Union[Set[str], Callable[[Request], bool]] = None,
            raise_errors: bool = False,
            public_docs: bool = True,
    ):
        """
        Initializes the middleware.

        Args:
            app: The FastAPI application instance.
            region_kwargs: Keyword arguments for device data helper.
            public_routes: A set of public path strings OR a function that takes a
                           Request and returns True if the route is public.
            raise_errors: If True, middleware errors will be raised instead of handled.
            public_docs: If True, /docs and /openapi.json are considered public.
        """
        super().__init__(app)
        self.region_kwargs = region_kwargs or {}
        self.raise_errors = raise_errors
        self.public_fastapi_docs = public_docs
        self.default_public_routes = {
            "/auth/login", "/auth/signup", "/auth/forgot-password", "/auth/reset-password", "/auth/verify", "/mfa/validate-login"
        }
        if public_routes is None:
            self.public_routes = self.default_public_routes_function
        else:
            self.public_routes = set(public_routes) if isinstance(public_routes, list) else public_routes

    def default_public_routes_function(self, request: Request) -> bool:
        if request.url.path in self.default_public_routes:
            return True
        elif request.url.path.startswith("/auth/") and (request.url.path.rstrip("/").endswith("/callback") or request.url.path.endswith("/login")):
            return True
        return False

    async def _is_public_route(self, request: Request) -> bool:
        """
        Checks if the current request is for a public route (e.g., login/signup/docs).
        Returns True if the route is public, False otherwise.
        """
        path = request.url.path
        if self.public_fastapi_docs and path.startswith(("/docs", "/openapi.json")):
            return True
        if callable(self.public_routes):
            return self.public_routes(request)

        return path in self.public_routes
    async def _cookie_helper(self, session_token: str, request: Request):
        """Validates and refreshes COOKIE-based session tokens (JWT)."""
        session_data = encryption_utils.decode_jwt_token(session_token)

        if session_data:
            last_db_check = session_data.get("database_checked", 0)
            needs_db_check = time.time() - last_db_check > settings.SESSION_DB_VERIFICATION_INTERVAL

            if needs_db_check:
                async with db_manager.get_db() as db:
                    stmt = select(DBSession).where(
                        DBSession.session_id == session_data.get("session"),
                        DBSession.user_id == session_data.get("user_id"),
                        DBSession.active == True,
                    )
                    result = await db.execute(stmt)
                    db_session = result.scalar_one_or_none()

                    if db_session and await db_session.is_valid(
                            region=request.state.device_data["region"],
                            device=request.state.device_data["device"],
                            random_string=session_data.get("random_string"),
                            ip=request.state.user_ip_address,
                            db=db
                    ):
                        await db_session.update_last_ip(await get_remote_address(request), db=db)
                        await db_session.update_random_string()
                        request.state.user_id = db_session.user_id
                        request.state.session_id = db_session.session_id
                        session_token = db_session.get_cookie_string()
                    else:
                        session_token = None
                    await db.commit()
            else:
                request.state.user_id = session_data.get("user_id")
                request.state.session_id = session_data.get("session")
        else:
            session_token = None
        return session_token

    async def _bearer_helper(self, api_key_token: str, request: Request):
        """Validates BEARER API key tokens and sets user_id on request.state."""
        try:
            from authtuna.manager.asynchronous import AuthTunaAsync
            auth_service = AuthTunaAsync(db_manager)
            api_key = await auth_service.api.validate_key(api_key_token)
            if api_key:
                request.state.user_id = api_key.user_id
                request.state.api_key = api_key
                return True
            else:
                request.state.user_id = None
                return False
        except Exception as e:
            logger.error(f"Error validating API key: {e}", exc_info=True)
            request.state.user_id = None
            return False

    async def dispatch(self, request: Request, call_next):
        """
        Main middleware entrypoint. Validates session, injects user/session info, and refreshes cookies.
        If session is invalid or hijacked, deletes the session cookie.
        """
        request.state.user_id = None
        request.state.session_id = None
        request.state.device_data = await get_device_data(request, region_kwargs=self.region_kwargs)
        request.state.user_ip_address = await get_remote_address(
            request)  # For now im just using cf ip, afterwards ill add params to config it one day.
        if await self._is_public_route(request):
            return await call_next(request)
        token_method = None
        session_token = None
        if settings.STRATEGY == "COOKIE" or settings.STRATEGY == "AUTO":
            session_token = request.cookies.get(settings.SESSION_TOKEN_NAME)
            if session_token:
                token_method = "COOKIE"
        if settings.STRATEGY == "BEARER" or settings.STRATEGY == "AUTO":
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                session_token = auth_header.split(" ", 1)[1]
                token_method = "BEARER"
        request.state.token_method = token_method
        try:
            if session_token:
                if token_method == "COOKIE":
                    session_token = await self._cookie_helper(session_token, request)
                elif token_method == "BEARER":
                    # For BEARER tokens, validate the API key and set user_id
                    # Don't need to refresh/update the token like cookies
                    await self._bearer_helper(session_token, request)
                    # Keep session_token for BEARER (not used for cookie setting)
            else:
                session_token = None

            response = await call_next(request)

        except Exception as e:
            if self.raise_errors:
                raise e
            logger.error(f"Error in session middleware: {e}", exc_info=True)
            request.state.user_id = None
            session_token = None
            response = await call_next(request)

        if response:
            if token_method == "COOKIE":
                if session_token is None:
                    response.delete_cookie(settings.SESSION_TOKEN_NAME)
                else:
                    response.set_cookie(
                    key=settings.SESSION_TOKEN_NAME,
                    value=session_token,
                    samesite=settings.SESSION_SAME_SITE,
                    secure=settings.SESSION_SECURE,
                    httponly=True,
                    max_age=settings.SESSION_ABSOLUTE_LIFETIME_SECONDS,
                    domain=settings.SESSION_COOKIE_DOMAIN,
                )
        return response
