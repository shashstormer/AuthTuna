import pytest
from fastapi import FastAPI, Request, status
from httpx import AsyncClient, ASGITransport
from starlette.responses import JSONResponse

from authtuna.middlewares.session import DatabaseSessionMiddleware

# A minimal app for testing the middleware
app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/protected")
async def protected_route(request: Request):
    if not request.state.user_id:
        return JSONResponse({"detail": "Not authenticated"}, status_code=status.HTTP_401_UNAUTHORIZED)
    return {"user_id": request.state.user_id}

@pytest.mark.asyncio
async def test_middleware_no_token():
    """Test that the middleware blocks access without a token."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/protected")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_middleware_with_valid_token(auth_tuna_async):
    """Test that the middleware allows access with a valid token."""
    await auth_tuna_async.signup(
        username="middleware_user",
        email="middleware@example.com",
        password="ValidPassword123",
        ip_address="127.0.0.1"
    )
    user, session = await auth_tuna_async.login(
        username_or_email="middleware_user",
        password="ValidPassword123",
        ip_address="127.0.0.1",
        region="",
        device="",
    )
    session_token = session.get_cookie_string()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/protected", cookies={ "session_token": session_token })
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["user_id"] == user.id