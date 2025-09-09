import logging
import time
from typing import Callable, Set, Union

from authtuna.core.config import settings
from authtuna.core.database import db_manager, Session
from authtuna.core.encryption import encryption_utils
from authtuna.helpers import get_device_data, get_remote_address
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class DatabaseSessionMiddleware(BaseHTTPMiddleware):
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
        """
        super().__init__(app)
        self.region_kwargs = region_kwargs or {}
        self.raise_errors = raise_errors
        self.public_fastapi_docs = public_docs
        if public_routes is None:
            # Default set of public routes for convenience
            self.public_routes = {
                "/auth/login", "/auth/signup", "/auth/forgot-password", "/auth/reset-password",
                "/auth/github/callback", "/auth/github/login",
                "/auth/google/callback", "/auth/google/login",
                "/auth/logout",
            }
        else:
            # If a list is provided, convert it to a set for performance.
            # If it's a function, keep it as is.
            self.public_routes = set(public_routes) if isinstance(public_routes, list) else public_routes

    async def _is_public_route(self, request: Request) -> bool:
        """
        Checks if the current request is for a public route,
        handling both a set of paths and a callable function.
        """
        path = request.url.path

        # Handle built-in FastAPI docs
        if self.public_fastapi_docs and path.startswith(("/docs", "/openapi.json")):
            return True

        # Check if public_routes is a function
        if callable(self.public_routes):
            # If the user provided a function, call it with the request
            return self.public_routes(request)

        # Otherwise, assume it's a set and check for membership
        return path in self.public_routes

    async def dispatch(self, request: Request, call_next):
        # Initialize request state
        request.state.user_id = None
        request.state.session_id = None
        request.state.device_data = await get_device_data(request, region_kwargs=self.region_kwargs)

        # Bypass session validation for public endpoints using the new helper
        if await self._is_public_route(request):
            return await call_next(request)

        session_cookie = request.cookies.get(settings.SESSION_TOKEN_NAME)
        response = None

        try:
            if session_cookie:
                session_data = encryption_utils.decode_jwt_token(session_cookie)

                last_db_check = session_data.get("database_checked", 0)
                needs_db_check = time.time() - last_db_check > settings.SESSION_DB_VERIFICATION_INTERVAL

                if needs_db_check:
                    with db_manager.get_context_manager_db() as db:
                        db_session = db.query(Session).filter(
                            Session.session_id == session_data.get("session"),
                            Session.user_id == session_data.get("user_id")
                        ).first()

                        if db_session and db_session.is_valid(
                                region=request.state.device_data["region"],
                                device=request.state.device_data["device"],
                                random_string=session_data.get("random_string"),
                                db=db
                        ):
                            db_session.update_last_ip(await get_remote_address(request), db=db)
                            db_session.update_random_string()
                            request.state.user_id = db_session.user_id
                            request.state.session_id = db_session.session_id
                            session_cookie = db_session.get_cookie_string()
                            db.commit()
                        else:
                            session_cookie = None
                else:
                    request.state.user_id = session_data.get("user_id")
                    request.state.session_id = session_data.get("session")
            else:
                session_cookie = None

            response = await call_next(request)

        except Exception as e:
            if self.raise_errors:
                raise e
            logger.error(f"Error in session middleware: {e}", exc_info=True)
            request.state.user_id = None
            session_cookie = None
            response = await call_next(request)

        if response:
            if session_cookie is None:
                response.delete_cookie(settings.SESSION_TOKEN_NAME)
            else:
                response.set_cookie(
                    key=settings.SESSION_TOKEN_NAME,
                    value=session_cookie,
                    samesite=settings.SESSION_SAME_SITE,
                    secure=settings.SESSION_SECURE,
                    httponly=True,
                    max_age=settings.SESSION_ABSOLUTE_LIFETIME_SECONDS
                )
        return response

