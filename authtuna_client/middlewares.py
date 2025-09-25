from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from .manager import SessionManagerClient
from authtuna.helpers import get_remote_address

session_manager_client = SessionManagerClient()

class RPCSessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get("session_token")
        if session_id:
            session = session_manager_client.get_by_id(session_id)
            if session and session.active:
                request.state.user_id = session.user_id
                request.state.session_id = session.session_id
                request.state.user_ip_address = get_remote_address(request)
        response = await call_next(request)
        return response
