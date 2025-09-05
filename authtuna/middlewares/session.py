import logging
import time
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from authtuna.core.database import db_manager, Session
from authtuna.core.encryption import encryption_utils
from authtuna.helpers import get_device_data, get_remote_address
from authtuna.core.config import settings

logger = logging.getLogger(__name__)


class DatabaseSessionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        public_routes = ["/", "/login/", "/auth/callback/"]
        is_public = any(request.url.path.startswith(route) for route in public_routes)
        if is_public:
            return await call_next(request)

        session_token = request.cookies.get("session_token")
        if not session_token:
            raise HTTPException(401)

        try:
            session_data = encryption_utils.decode_jwt_token(session_token)
            last_db_check = session_data.get("database_checked", 0)

            if time.time() - last_db_check > settings.SESSION_DB_VERIFICATION_INTERVAL:
                with db_manager.get_db() as db:
                    db_session = db.query(Session).filter(
                        Session.session_id == session_data["session"],
                        Session.user_id == session_data["user_id"]
                    ).first()
                    device_data = await get_device_data(db_session)
                    if not db_session or not db_session.is_valid(
                        region=device_data["region"],
                        device=device_data["device"],
                        random_string=session_data["random_string"],
                    ):
                        raise HTTPException(401)

                    db_session.update_last_ip(get_remote_address(request))
                    db_session.update_random_string()
                    db.commit()
                    request.state.user_id = db_session.user_id
                    request.state.session_id = db_session.session_id
                    session_cookie = db_session.get_cookie_string()
            else:
                request.state.user_id = session_data.get("user_id")
                request.state.session_id = session_data.get("session")

            response = await call_next(request)
            response.set_cookie("session_token", session_cookie)
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise HTTPException(401)
        return response
