import logging
import time

from authtuna.core.config import settings
from authtuna.core.database import db_manager, Session
from authtuna.core.encryption import encryption_utils
from authtuna.helpers import get_device_data, get_remote_address
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class DatabaseSessionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, region_kwargs=None):
        super().__init__(app)
        self.region_kwargs = region_kwargs or {}

    async def dispatch(self, request: Request, call_next):
        device_data = await get_device_data(request, region_kwargs=self.region_kwargs)
        session_cookie = request.cookies.get(settings.SESSION_TOKEN_NAME)
        request.state.user_id = None
        request.state.session_id = None
        request.state.device_data = device_data
        try:
            if session_cookie:
                session_data = encryption_utils.decode_jwt_token(session_cookie)
                session_data = session_data if session_data else {}
                last_db_check = session_data.get("database_checked", 0)

            else:
                last_db_check = time.time()
                session_data = {}
            if session_data and time.time() - last_db_check > settings.SESSION_DB_VERIFICATION_INTERVAL:
                with db_manager.get_context_manager_db() as db:
                    db_session = db.query(Session).filter(
                        Session.session_id == session_data["session"],
                        Session.user_id == session_data["user_id"]
                    ).first()

                    if db_session and db_session.is_valid(
                        region=device_data["region"],
                        device=device_data["device"],
                        random_string=session_data["random_string"],
                    ):
                        db_session.update_last_ip(await get_remote_address(request))
                        db_session.update_random_string()
                        db.commit()
                        request.state.user_id = db_session.user_id
                        request.state.session_id = db_session.session_id
                        request.state.device_data = device_data
                        session_cookie = db_session.get_cookie_string()
            else:
                request.state.user_id = session_data.get("user_id")
                request.state.session_id = session_data.get("session")
            try:
                response = await call_next(request)
            except HTTPException as exc:
                raise exc
            except Exception as e:
                logger.error(e)
                response = Response(status_code=500, content="Internal Server Error")
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            response = Response(status_code=401, content="Authentication failed.")
            raise e

        if session_cookie is None:
            response.delete_cookie(settings.SESSION_TOKEN_NAME)
        else:
            response.set_cookie(settings.SESSION_TOKEN_NAME, session_cookie, samesite=settings.SESSION_SAME_SITE,
                                secure=settings.SESSION_SECURE, httponly=True)
        return response
