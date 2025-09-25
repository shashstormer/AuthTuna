# gRPC-backed middlewares for authtuna-client will be implemented here
# authtuna-client package init

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from .manager import SessionManagerClient

session_manager_client = SessionManagerClient()

class RPCSessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get("session_id") or request.headers.get("X-Session-Id")
        if session_id:
            session = await session_manager_client.get_by_id(session_id)
            if session and session.get("active", False):
                request.state.user_id = session.get("user_id")
                request.state.session_id = session_id
                request.state.user_ip_address = session.get("create_ip")
        response = await call_next(request)
        return response

# Starlette integration: Middleware and dependency for Starlette apps
from starlette.requests import Request as StarletteRequest

def get_current_user_starlette(request: StarletteRequest):
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise Exception("Not authenticated")
    # In Starlette, user fetching should be async as well, but for demo, return user_id
    return user_id
