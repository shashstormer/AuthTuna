import pytest
from authtuna.manager.asynchronous import AuthTunaAsync
from authtuna.core.database import db_manager
from authtuna.core import encryption_utils  # Import for decoding JWT
from fastapi import Request, Response
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_database_manager_initialize_and_audit():
    """Tests user creation and audit logging."""
    service = AuthTunaAsync(db_manager)
    user = await service.users.create(email="test1@example.com", username="testuser1", password="pass",
                                      ip_address="1.1.1.1")

    await db_manager.log_audit_event(user.id, "TEST_EVENT", "127.0.0.1", {"k": 1})

    events = await service.audit.get_events_for_user(user_id=user.id)
    assert any(ev.event_type == "TEST_EVENT" for ev in events)


@pytest.mark.asyncio
async def test_session_cookie_roundtrip_and_rotation():
    """Tests that a session cookie can be created, decoded, and rotated."""
    service = AuthTunaAsync(db_manager)
    user = await service.users.create(email="test@example.com", username="testuser", password="pass",
                                      ip_address="1.1.1.1")
    session = await service.sessions.create(user.id, ip_address="1.1.1.1", region="Test", device="TestDevice")

    cookie_string = session.get_cookie_string()

    data = encryption_utils.decode_jwt_token(cookie_string)

    assert data["session"] == session.session_id
    assert data["user_id"] == user.id

    old_rs = session.random_string
    await session.update_random_string()

    # --- FIX: Persist the updated session to the database ---
    async with db_manager.get_db() as db:
        db.add(session)
        await db.commit()

    session2 = await service.sessions.get_by_id(session.session_id)
    assert session2.random_string != old_rs


@pytest.mark.asyncio
async def test_middleware_public_and_protected_routes(app):
    """Tests that middleware correctly handles public and unauthenticated protected routes."""
    client = TestClient(app)
    r = client.get("/public")
    assert r.status_code == 200 and r.json()["ok"] is True
    r2 = client.get("/protected")
    assert r2.status_code == 200 and r2.json()["user_id"] is None


@pytest.mark.asyncio
async def test_middleware_sets_cookie_on_login_flow(app):
    """Tests the full login flow: creating a user, setting a cookie, and accessing a protected route."""
    client = TestClient(app)
    service = AuthTunaAsync(db_manager)
    user = await service.users.create(email="login@example.com", username="LoginUser", password="pass",
                                      ip_address="1.1.1.1")

    @app.get("/do-login")
    async def do_login(request: Request):
        response = Response()
        ip = request.headers.get("CF-Connecting-IP", request.client.host)
        device = request.headers.get("user-agent", "Unknown Device")
        session = await service.sessions.create(user.id, ip, "Test", device)

        response.set_cookie(
            key="session",
            value=session.get_cookie_string(),
            httponly=True,
            samesite="lax",
        )
        return response

    resp = client.get("/do-login", headers={"CF-Connecting-IP": "127.0.0.1", "user-agent": "TestAgent"})
    assert resp.status_code == 200
    assert "set-cookie" in resp.headers

    r2 = client.get("/protected", headers={"CF-Connecting-IP": "127.0.0.1", "user-agent": "TestAgent"})
    assert r2.status_code == 200
    assert r2.json() == str(user.id)

