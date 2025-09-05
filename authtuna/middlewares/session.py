import logging
import time
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from authtuna.core.database import db_manager, Session
from authtuna.core.encryption import encryption_utils
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

        jwt_token = request.cookies.get("session_token")
        if not jwt_token:
            raise HTTPException(401)

        try:
            session_data = encryption_utils.decode_jwt_token(jwt_token)
            last_db_check = session_data.get("database_checked", 0)

            if time.time() - last_db_check > 10:
                with db_manager.get_db() as db:
                    db_session = db.query(Session).filter(
                        Session.session_id == session_data["session"],
                        Session.user_id == session_data["user_id"]
                    ).first()
                    if not db_session or not db_session.is_valid():
                        raise HTTPException(401)

                    db_session.update_last_ip(request.client.host)
                    db.commit()
                    request.state.user_id = db_session.user_id
                    request.state.session_id = db_session.session_id
            else:
                request.state.user_id = session_data.get("user_id")
                request.state.session_id = session_data.get("session")

            response = await call_next(request)
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise HTTPException(401)
        return response
