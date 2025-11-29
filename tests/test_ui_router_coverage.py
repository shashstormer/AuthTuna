import pytest
from unittest.mock import AsyncMock, patch
from fastapi import status
from httpx import AsyncClient
import uuid

@pytest.fixture
async def unique_org_name():
    return f"Test Org {uuid.uuid4().hex}"

@pytest.fixture
async def setup_user_role(auth_tuna_async, authenticated_user):
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

@pytest.mark.asyncio
async def test_create_organization_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Grant permission for org creation
    perm, _ = await auth_tuna_async.permissions.get_or_create("org:create")
    role, _ = await auth_tuna_async.roles.get_or_create("OrgCreator")
    await auth_tuna_async.roles.add_permission_to_role("OrgCreator", "org:create")
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "OrgCreator", assigner_id="system", scope="global")

    # Mock service to raise generic exception
    with patch("authtuna.routers.ui.auth_service.orgs.create_organization", side_effect=Exception("Generic DB Error")):
        response = await fastapi_client.post("/ui/organizations/create", data={"name": "Test Org Unique"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Generic DB Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_invite_to_org_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Role
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    
    # Mock service to raise generic exception
    with patch("authtuna.routers.ui.auth_service.orgs.invite_to_organization", side_effect=Exception("Invite Error")):
        response = await fastapi_client.post(f"/ui/organizations/{org.id}/invite", json={"email": "invitee@example.com"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invite Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_accept_org_invite_generic_error(fastapi_client):
    # Mock service to raise generic exception
    with patch("authtuna.routers.ui.auth_service.orgs.accept_organization_invite", side_effect=Exception("Accept Error")):
        response = await fastapi_client.get("/ui/organizations/join?token=invalid_token")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Accept Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_org_details_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")

    # Mock service to raise generic exception
    with patch("authtuna.routers.ui.auth_service.orgs.get_organization_by_id", side_effect=Exception("Details Error")):
        response = await fastapi_client.get(f"/ui/organizations/{org.id}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Details Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_delete_org_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    with patch("authtuna.routers.ui.auth_service.orgs.get_organization_by_id", side_effect=Exception("Delete Error")):
        response = await fastapi_client.delete(f"/ui/organizations/{org.id}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Delete Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_leave_org_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org (user is owner, so can't leave normally, but we mock error before that check or during get)
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")

    with patch("authtuna.routers.ui.auth_service.orgs.get_organization_by_id", side_effect=Exception("Leave Error")):
        response = await fastapi_client.post(f"/ui/organizations/{org.id}/leave")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Leave Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_remove_org_member_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    
    # Mock get_organization_by_id to raise exception
    with patch("authtuna.routers.ui.auth_service.orgs.get_organization_by_id", side_effect=Exception("Remove Member Error")):
        response = await fastapi_client.delete(f"/ui/organizations/{org.id}/members/some_id")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Remove Member Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_create_team_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    
    # Mock create_team to raise exception
    with patch("authtuna.routers.ui.auth_service.orgs.create_team", side_effect=Exception("Create Team Error")):
        response = await fastapi_client.post(f"/ui/organizations/{org.id}/teams", json={"name": "New Team"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Create Team Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_invite_to_team_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Team
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")
    
    # Mock invite_to_team to raise exception
    with patch("authtuna.routers.ui.auth_service.orgs.invite_to_team", side_effect=Exception("Invite Team Error")):
        response = await fastapi_client.post(f"/ui/teams/{team.id}/invite", json={"email": "invitee@example.com"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invite Team Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_accept_team_invite_generic_error(fastapi_client):
    with patch("authtuna.routers.ui.auth_service.orgs.accept_team_invite", side_effect=Exception("Accept Team Error")):
        response = await fastapi_client.get("/ui/teams/join?token=invalid")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Accept Team Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_team_details_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Team
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")
    
    with patch("authtuna.routers.ui.auth_service.orgs.get_team_by_id", side_effect=Exception("Team Details Error")):
        response = await fastapi_client.get(f"/ui/teams/{team.id}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Team Details Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_delete_team_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Team
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")
    
    with patch("authtuna.routers.ui.auth_service.orgs.get_team_by_id", side_effect=Exception("Delete Team Error")):
        response = await fastapi_client.delete(f"/ui/teams/{team.id}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Delete Team Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_leave_team_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Team
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")
    
    with patch("authtuna.routers.ui.auth_service.orgs.get_team_by_id", side_effect=Exception("Leave Team Error")):
        response = await fastapi_client.post(f"/ui/teams/{team.id}/leave")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Leave Team Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_remove_team_member_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role, unique_org_name):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Setup Org and Team
    org = await auth_tuna_async.orgs.create_organization(unique_org_name, authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")
    
    with patch("authtuna.routers.ui.auth_service.orgs.get_team_by_id", side_effect=Exception("Remove Team Member Error")):
        response = await fastapi_client.delete(f"/ui/teams/{team.id}/members/some_id")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Remove Team Member Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_update_profile_errors(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    # Integrity Error
    from sqlalchemy.exc import IntegrityError
    with patch("authtuna.routers.ui.auth_service.users.update", side_effect=IntegrityError(None, None, Exception("Duplicate"))):
        response = await fastapi_client.patch("/ui/profile", json={"username": "new_name"})
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "Username already exists" in response.json()["detail"]

    # Generic Error
    with patch("authtuna.routers.ui.auth_service.users.update", side_effect=Exception("Update Error")):
        response = await fastapi_client.patch("/ui/profile", json={"username": "new_name"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Update Error" in response.json()["detail"]

@pytest.mark.asyncio
async def test_create_api_key_generic_error(fastapi_client, auth_tuna_async, authenticated_user, setup_user_role):
    # Authenticate
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    fastapi_client.cookies = {"session_token": session.get_cookie_string()}
    
    with patch("authtuna.routers.ui.auth_service.api.create_key", side_effect=Exception("API Key Error")):
        response = await fastapi_client.post("/ui/settings/api-keys", json={"name": "Test Key", "key_type": "secret"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "API Key Error" in response.json()["detail"]
