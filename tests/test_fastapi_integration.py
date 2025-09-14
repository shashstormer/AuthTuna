import pytest
from authtuna.manager.asynchronous import AuthTunaAsync


@pytest.mark.asyncio
async def test_get_current_user_dependency_requires_user(setup_db):
    service = AuthTunaAsync()
    app = service.fastapi_app
    client = service.get_test_client()
    r = client.get("/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_role_checker_uses_user_roles(setup_db):
    service = AuthTunaAsync()
    user = await service.users.create(email="role@example.com", username="RoleUser", password="pass", ip_address="1.1.1.1")
    await service.roles.get_or_create("admin", {"description": "Admin role"})
    await service.roles.assign_to_user(user.id, "admin", assigner_id=user.id, scope="global")
    app = service.fastapi_app
    client = service.get_test_client()
    r = client.get("/admin", headers={"user_id": user.id})
    assert r.status_code == 200
