import pytest
from fastapi import status
from authtuna.core.database import User, Organization, Team

@pytest.mark.asyncio
async def test_ui_dashboard_unauthenticated(fastapi_client):
    response = await fastapi_client.get("/ui/dashboard")
    # Should redirect to login or return 401/403?
    # Middleware handles it. If public_routes doesn't include it, it returns 401/403?
    # SessionMiddleware returns 401/403 if raise_errors is True, or handles it.
    # But RoleChecker dependency raises 401/403.
    assert response.status_code in [401, 403]

@pytest.mark.asyncio
async def test_ui_dashboard_authenticated(fastapi_client, auth_tuna_async, authenticated_user):
    # Create session
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    
    # Assign 'User' role if not already (signup usually does it)
    # authenticated_user fixture uses create() which DOES NOT assign 'User' role automatically unless signup() is used.
    # But RoleChecker("User") requires it.
    # Let's assign it.
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")
    
    fastapi_client.cookies = cookies
    response = await fastapi_client.get("/ui/dashboard")
    assert response.status_code == 200
    assert "Dashboard" in response.text or "user_dashboard" in response.text # Check for template content

@pytest.mark.asyncio
async def test_ui_profile(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    fastapi_client.cookies = cookies
    response = await fastapi_client.get("/ui/profile")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_ui_settings(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    fastapi_client.cookies = cookies
    response = await fastapi_client.get("/ui/settings")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_ui_organizations_flow(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")
    
    # Grant org:create permission
    perm, _ = await auth_tuna_async.permissions.get_or_create("org:create")
    await auth_tuna_async.roles.add_permission_to_role("User", "org:create")

    # 1. Dashboard
    fastapi_client.cookies = cookies
    response = await fastapi_client.get("/ui/organizations")
    assert response.status_code == 200

    # 2. Create Org
    response = await fastapi_client.post("/ui/organizations/create", data={"name": "Test Org"})
    assert response.status_code == 200
    org_data = response.json()
    org_id = org_data["id"]
    assert org_data["name"] == "Test Org"

    # 3. Get Org Details
    response = await fastapi_client.get(f"/ui/organizations/{org_id}")
    assert response.status_code == 200
    assert "Test Org" in response.text

    # 4. Create Team
    response = await fastapi_client.post(f"/ui/organizations/{org_id}/teams", json={"name": "Test Team"})
    assert response.status_code == 200
    team_data = response.json()
    team_id = team_data["team_id"]

    # 5. Get Team Details
    response = await fastapi_client.get(f"/ui/teams/{team_id}")
    assert response.status_code == 200
    assert "Test Team" in response.text

    # 6. Delete Team
    response = await fastapi_client.delete(f"/ui/teams/{team_id}")
    assert response.status_code == 200

    # 7. Delete Org
    response = await fastapi_client.delete(f"/ui/organizations/{org_id}")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_ui_api_keys(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # 1. Create Key
    key_data = {
        "name": "UI Test Key",
        "key_type": "secret",
        "scopes": [],
        "valid_seconds": 3600
    }
    fastapi_client.cookies = cookies
    response = await fastapi_client.post("/ui/settings/api-keys", json=key_data)
    assert response.status_code == 201
    created_key = response.json()["api_key"]
    key_id = created_key["id"]

    # 2. List Keys
    response = await fastapi_client.get("/ui/settings/api-keys")
    assert response.status_code == 200
    keys = response.json()
    assert any(k["id"] == key_id for k in keys)

    # 3. Delete Key
    response = await fastapi_client.delete(f"/ui/settings/api-keys/{key_id}")
    assert response.status_code == 200

    # 4. Verify Deleted
    response = await fastapi_client.get("/ui/settings/api-keys")
    keys = response.json()
    assert not any(k["id"] == key_id for k in keys)

@pytest.mark.asyncio
async def test_ui_org_member_management(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")
    
    # Create Org
    perm, _ = await auth_tuna_async.permissions.get_or_create("org:create")
    await auth_tuna_async.roles.add_permission_to_role("User", "org:create")
    fastapi_client.cookies = cookies
    response = await fastapi_client.post("/ui/organizations/create", data={"name": "Member Test Org"})
    org_id = response.json()["id"]

    # Create another user and add to org directly via DB
    other_user = await auth_tuna_async.users.create("other@example.com", "otheruser", "password", "127.0.0.1")
    
    from authtuna.core.database import organization_members
    async with auth_tuna_async.db_manager.get_db() as db:
        stmt = organization_members.insert().values(user_id=other_user.id, organization_id=org_id)
        await db.execute(stmt)
        # Assign role
        await auth_tuna_async.roles.assign_to_user(other_user.id, "OrgMember", assigner_id="system", scope=f"org:{org_id}", db=db)
        await db.commit()

    # Remove member
    response = await fastapi_client.delete(f"/ui/organizations/{org_id}/members/{other_user.id}")
    assert response.status_code == 200
    assert "removed" in response.json()["message"]

    # Verify removed
    members = await auth_tuna_async.orgs.get_org_members(org_id)
    assert not any(m["user_id"] == other_user.id for m in members)

    # Error: Remove non-existent member
    response = await fastapi_client.delete(f"/ui/organizations/{org_id}/members/{other_user.id}")
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_ui_leave_org(fastapi_client, auth_tuna_async, authenticated_user):
    # Create user who will leave
    leaver = await auth_tuna_async.users.create("leaver@example.com", "leaver", "password", "127.0.0.1")
    session = await auth_tuna_async.sessions.create(leaver.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(leaver.id, "User", assigner_id="system", scope="global")

    # Create Org by someone else
    owner = await auth_tuna_async.users.create("owner@example.com", "owner", "password", "127.0.0.1")
    org = await auth_tuna_async.orgs.create_organization("Leave Test Org", owner, "127.0.0.1")
    
    # Add leaver to org directly
    from authtuna.core.database import organization_members
    async with auth_tuna_async.db_manager.get_db() as db:
        stmt = organization_members.insert().values(user_id=leaver.id, organization_id=org.id)
        await db.execute(stmt)
        await auth_tuna_async.roles.assign_to_user(leaver.id, "OrgMember", assigner_id="system", scope=f"org:{org.id}", db=db)
        await db.commit()

    # Leave Org
    fastapi_client.cookies = cookies
    response = await fastapi_client.post(f"/ui/organizations/{org.id}/leave")
    if response.status_code != 200:
        import logging
        logging.warning(f"DEBUG: Leave Org failed: {response.text}")
    assert response.status_code == 200
    
    # Verify left
    members = await auth_tuna_async.orgs.get_org_members(org.id)
    assert not any(m["user_id"] == leaver.id for m in members)

@pytest.mark.asyncio
async def test_ui_team_management(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")
    
    # Create Org and Team
    perm, _ = await auth_tuna_async.permissions.get_or_create("org:create")
    await auth_tuna_async.roles.add_permission_to_role("User", "org:create")
    org = await auth_tuna_async.orgs.create_organization("Team Test Org", authenticated_user, "127.0.0.1")
    team = await auth_tuna_async.orgs.create_team("Test Team", org.id, authenticated_user, "127.0.0.1")

    # Create another user and add to team directly
    other_user = await auth_tuna_async.users.create("teammember@example.com", "teammember", "password", "127.0.0.1")
    
    from authtuna.core.database import organization_members, team_members
    async with auth_tuna_async.db_manager.get_db() as db:
        # Add to org first
        stmt = organization_members.insert().values(user_id=other_user.id, organization_id=org.id)
        await db.execute(stmt)
        await auth_tuna_async.roles.assign_to_user(other_user.id, "OrgMember", assigner_id="system", scope=f"org:{org.id}", db=db)
        
        # Add to team
        stmt = team_members.insert().values(user_id=other_user.id, team_id=team.id)
        await db.execute(stmt)
        await auth_tuna_async.roles.assign_to_user(other_user.id, "TeamMember", assigner_id="system", scope=f"team:{team.id}", db=db)
        await db.commit()

    # Remove member from team
    fastapi_client.cookies = cookies
    response = await fastapi_client.delete(f"/ui/teams/{team.id}/members/{other_user.id}")
    assert response.status_code == 200

    # Verify removed
    members = await auth_tuna_async.orgs.get_team_members(team.id)
    assert not any(m["user_id"] == other_user.id for m in members)

@pytest.mark.asyncio
async def test_ui_errors(fastapi_client, auth_tuna_async, authenticated_user):
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # To test 404, we need permission to access the resource (scope).
    # Assign OrgOwner for 'nonexistent' scope
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "OrgOwner", assigner_id="system", scope="org:nonexistent")
    
    # Delete non-existent org
    fastapi_client.cookies = cookies
    response = await fastapi_client.delete("/ui/organizations/nonexistent")
    assert response.status_code == 404

    # Assign TeamLead for 'nonexistent' scope
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "TeamLead", assigner_id="system", scope="team:nonexistent")

    # Delete non-existent team
    response = await fastapi_client.delete("/ui/teams/nonexistent")
    assert response.status_code == 404

    # Leave non-existent org (requires OrgMember/Admin/Owner)
    # We already have OrgOwner for org:nonexistent
    response = await fastapi_client.post("/ui/organizations/nonexistent/leave")
    assert response.status_code == 404

