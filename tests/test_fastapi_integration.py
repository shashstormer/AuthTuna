import pytest
from fastapi import FastAPI, Depends, Request, status
from httpx import ASGITransport, AsyncClient
from authtuna.integrations.fastapi_integration import (
    get_current_user,
    get_current_user_optional,
    PermissionChecker,
    RoleChecker,
    get_user_ip
)
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.core.database import User
from authtuna.manager.asynchronous import AuthTunaAsync

# --- Setup Test App ---
@pytest.fixture
def integration_app():
    app = FastAPI()
    app.add_middleware(DatabaseSessionMiddleware)

    @app.get("/protected")
    async def protected_route(user: User = Depends(get_current_user)):
        return {"user_id": user.id, "username": user.username}

    @app.get("/optional")
    async def optional_route(user: User = Depends(get_current_user_optional)):
        if user:
            return {"user_id": user.id}
        return {"user_id": None}

    @app.get("/perm-and")
    async def perm_and_route(user: User = Depends(PermissionChecker("read", "write", mode="AND"))):
        return {"status": "ok"}

    @app.get("/perm-or")
    async def perm_or_route(user: User = Depends(PermissionChecker("read", "write", mode="OR"))):
        return {"status": "ok"}

    @app.get("/role-and")
    async def role_and_route(user: User = Depends(RoleChecker("admin", "editor", mode="AND"))):
        return {"status": "ok"}

    @app.get("/role-or")
    async def role_or_route(user: User = Depends(RoleChecker("admin", "editor", mode="OR"))):
        return {"status": "ok"}
    
    @app.get("/scoped/{org_id}")
    async def scoped_route(org_id: str, user: User = Depends(PermissionChecker("manage", scope_from_path="org_id"))):
        return {"status": "ok"}

    return app

@pytest.fixture
async def integration_client(integration_app):
    transport = ASGITransport(app=integration_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

# --- Tests ---

@pytest.mark.asyncio
async def test_get_current_user_cookie(integration_client, auth_tuna_async, authenticated_user):
    # Create a session
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookie_value = session.get_cookie_string()

    # Test valid cookie
    response = await integration_client.get("/protected", cookies={"session_token": cookie_value})
    assert response.status_code == 200
    assert response.json()["user_id"] == authenticated_user.id

    # Test invalid cookie
    response = await integration_client.get("/protected", cookies={"session_token": "invalid"})
    assert response.status_code == 401

    # Test missing cookie
    response = await integration_client.get("/protected")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_current_user_bearer(integration_client, auth_tuna_async, authenticated_user):
    # Create an API key
    api_key = await auth_tuna_async.api.create_key(authenticated_user.id, "Test Key", key_type="secret")
    api_key_str = api_key.plaintext
    
    # Test valid bearer
    response = await integration_client.get("/protected", headers={"Authorization": f"Bearer {api_key_str}"})
    assert response.status_code == 200
    assert response.json()["user_id"] == authenticated_user.id

    # Test invalid bearer
    response = await integration_client.get("/protected", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_current_user_optional(integration_client, auth_tuna_async, authenticated_user):
    # Authenticated
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    response = await integration_client.get("/optional", cookies={"session_token": session.get_cookie_string()})
    assert response.status_code == 200
    assert response.json()["user_id"] == authenticated_user.id

    # Unauthenticated
    response = await integration_client.get("/optional")
    assert response.status_code == 200
    assert response.json()["user_id"] is None

@pytest.mark.asyncio
async def test_permission_checker(integration_client, auth_tuna_async, authenticated_user):
    # Setup roles and permissions
    role, _ = await auth_tuna_async.roles.get_or_create("reader")
    perm_read, _ = await auth_tuna_async.permissions.get_or_create("read")
    perm_write, _ = await auth_tuna_async.permissions.get_or_create("write")
    
    await auth_tuna_async.roles.add_permission_to_role("reader", "read")
    
    # Assign role to user
    # We need a user to assign the role (admin), let's just use the same user for simplicity or create a system user
    # Ideally we should use `assign_to_user` but it requires an assigner. 
    # Let's bypass the manager for setup and use DB directly or use a system override if available.
    # Actually `assign_to_user` checks permissions. Let's use `create` on `UserRoleAssociation` directly or use a superadmin.
    # For simplicity, let's inject the association directly.
    
    from authtuna.core.database import user_roles_association
    import time
    async with auth_tuna_async.db_manager.get_db() as db:
        stmt = user_roles_association.insert().values(
            user_id=authenticated_user.id, role_id=role.id, scope="global",
            given_by_id="system", given_at=time.time()
        )
        await db.execute(stmt)
        await db.commit()

    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}

    # Test OR (has 'read', needs 'read' or 'write') -> Should Pass
    response = await integration_client.get("/perm-or", cookies=cookies)
    assert response.status_code == 200

    # Test AND (has 'read', needs 'read' and 'write') -> Should Fail
    response = await integration_client.get("/perm-and", cookies=cookies)
    assert response.status_code == 403

    # Add 'write' permission
    await auth_tuna_async.roles.add_permission_to_role("reader", "write")
    
    # Test AND (now has both) -> Should Pass
    response = await integration_client.get("/perm-and", cookies=cookies)
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_role_checker(integration_client, auth_tuna_async, authenticated_user):
    # Setup roles
    role_admin, _ = await auth_tuna_async.roles.get_or_create("admin")
    role_editor, _ = await auth_tuna_async.roles.get_or_create("editor")

    # Assign 'admin' role
    from authtuna.core.database import user_roles_association
    import time
    async with auth_tuna_async.db_manager.get_db() as db:
        stmt = user_roles_association.insert().values(
            user_id=authenticated_user.id, role_id=role_admin.id, scope="global",
            given_by_id="system", given_at=time.time()
        )
        await db.execute(stmt)
        await db.commit()

    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}

    # Test OR (has 'admin', needs 'admin' or 'editor') -> Should Pass
    response = await integration_client.get("/role-or", cookies=cookies)
    assert response.status_code == 200

    # Test AND (has 'admin', needs 'admin' and 'editor') -> Should Fail
    response = await integration_client.get("/role-and", cookies=cookies)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_scoped_permission(integration_client, auth_tuna_async, authenticated_user):
    # Setup scoped role
    role, _ = await auth_tuna_async.roles.get_or_create("manager")
    perm, _ = await auth_tuna_async.permissions.get_or_create("manage")
    await auth_tuna_async.roles.add_permission_to_role("manager", "manage")

    # Assign role with scope "org:123"
    from authtuna.core.database import user_roles_association
    import time
    async with auth_tuna_async.db_manager.get_db() as db:
        stmt = user_roles_association.insert().values(
            user_id=authenticated_user.id, role_id=role.id, scope="org:123",
            given_by_id="system", given_at=time.time()
        )
        await db.execute(stmt)
        await db.commit()

    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}

    # Access /scoped/123 -> Should Pass
    response = await integration_client.get("/scoped/123", cookies=cookies)
    assert response.status_code == 200

    # Access /scoped/456 -> Should Fail
    response = await integration_client.get("/scoped/456", cookies=cookies)
    assert response.status_code == 403
