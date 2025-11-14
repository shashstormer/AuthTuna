"""
This file gonna contain routes for ui (dashboards, user info and logins etc etc, gonna work on this soon)
"""
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Request, HTTPException, Form, BackgroundTasks
from fastapi import status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError

from authtuna.core.config import settings
from authtuna.core.database import User, Organization
from authtuna.helpers.theme import get_theme_css
from authtuna.integrations import PermissionChecker
from authtuna.integrations.fastapi_integration import auth_service, RoleChecker, get_user_ip

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory=settings.DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR)
templates.env.globals['get_theme_css'] = get_theme_css


class UserProfileUpdate(BaseModel):
    username: str


class SessionInfo(BaseModel):
    session_id: str
    region: str
    device: str
    last_ip: str
    mtime: float
    is_current: bool = False

    class Config:
        from_attributes = True


class OrgCreate(BaseModel):
    name: str


@router.get("/dashboard", name="ui_dashboard")
async def dashboard(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user dashboard page.
    """
    return templates.TemplateResponse("user_dashboard.html", {"request": request, "user": user})


@router.get("/profile", name="ui_profile")
async def profile(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user profile page.
    """
    return templates.TemplateResponse("user_profile.html", {"request": request, "user": user})


@router.get("/settings", name="ui_settings")
async def settings_page(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Renders the user settings page.
    """
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})


@router.get("/organizations", response_class=HTMLResponse, summary="Organizations dashboard UI", name="orgs_dashboard")
async def orgs_dashboard(request: Request, current_user: User = Depends(RoleChecker("User"))):
    user_orgs = await auth_service.orgs.get_user_orgs(current_user.id)
    owned_orgs = await auth_service.orgs.get_user_owned_orgs(current_user.id)
    can_create_org = await auth_service.roles.has_permission(current_user.id, 'org:create')
    return templates.TemplateResponse("organizations.html", {
        "request": request,
        "user": current_user,
        "orgs": user_orgs,
        "owned_orgs": owned_orgs,
        "can_create_org": can_create_org,
    })


@router.post("/organizations/create", name="create_org")
async def create_organization(org: OrgCreate = Form(...), user: User = Depends(PermissionChecker('org:create')),
                              ip: str = Depends(get_user_ip)):
    try:
        org = await auth_service.orgs.create_organization(org.name, owner=user, ip_address=ip)
        return org
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


org_checker = RoleChecker("OrgOwner", "OrgMember", "OrgAdmin", scope_from_path="org_id", mode="OR")




class OrgInvite(BaseModel):
    email: str
    role_name: str = "OrgMember"


@router.post("/organizations/{org_id}/invite", name="org_invite")
async def invite_to_org(
        org_id: str,
        invite: OrgInvite,
        request: Request,
        background_tasks: BackgroundTasks,
        user: User = Depends(RoleChecker("OrgAdmin", "OrgOwner", scope_from_path="org_id", mode="OR"))
):
    """Invite a user to an organization."""
    try:
        ip_address = request.state.user_ip_address
        result = await auth_service.orgs.invite_to_organization(
            org_id=org_id,
            invitee_email=invite.email,
            role_name=invite.role_name,
            inviter=user,
            ip_address=ip_address,
            background_tasks=background_tasks
        )

        if result is True:
            return {"message": f"Invitation sent to {invite.email}", "email_sent": True}
        elif result is None:
            return {"message": f"User {invite.email} automatically added to organization", "email_sent": False}
        else:
            return {"message": "Invitation processed", "email_sent": False}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/organizations/join", name="org_join_page")
async def accept_org_invite_page(request: Request, token: str):
    """Accept organization invite via token."""
    try:
        ip_address = request.state.user_ip_address
        org = await auth_service.orgs.accept_organization_invite(token_id=token, ip_address=ip_address)
        return templates.TemplateResponse("invite_accepted.html", {
            "request": request,
            "type": "organization",
            "name": org.name,
            "org_id": org.id
        })
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/organizations/{org_id}", response_class=HTMLResponse, name="org_details")
async def org_details_page(request: Request, org_id: str, user: User = Depends(org_checker)):
    """Organization details page showing teams, members, and settings."""
    try:
        org = await auth_service.orgs.get_organization_by_id(org_id)
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

        members = await auth_service.orgs.get_org_members(org_id)
        teams = await auth_service.orgs.get_org_teams(org_id)

        # Convert timestamps to human readable strings
        org_created_human = _format_ts(org.created_at)
        # Mutate member join timestamps to human readable
        for m in members:
            if isinstance(m, dict):
                m['joined_at'] = _format_ts(m.get('joined_at'))

        # Attach human-readable created_at to team objects (transient attribute)
        for t in teams:
            try:
                setattr(t, 'created_at_human', _format_ts(t.created_at))
            except Exception:
                setattr(t, 'created_at_human', None)

        # Check if user is owner or admin
        user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"org:{org_id}")
        is_owner = org.owner_id == user.id
        is_admin = any(role.name == "OrgAdmin" for role in user_roles)

        return templates.TemplateResponse("org_details.html", {
            "request": request,
            "user": user,
            "org": org,
            "org_created_at": org_created_human,
            "members": members,
            "teams": teams,
            "is_owner": is_owner,
            "is_admin": is_admin,
            "can_manage": is_owner or is_admin
        })
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/organizations/{org_id}", name="delete_org")
async def delete_organization(
        org_id: str,
        request: Request,
        user: User = Depends(RoleChecker("OrgOwner", scope_from_path="org_id"))
):
    """Delete an organization (owner only)."""
    try:
        org = await auth_service.orgs.get_organization_by_id(org_id)
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

        if org.owner_id != user.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Only the owner can delete the organization")

        # Delete the organization
        async with auth_service.db_manager.get_db() as db:
            org_to_delete = await db.get(Organization, org_id)
            if org_to_delete:
                await db.delete(org_to_delete)
                await auth_service.db_manager.log_audit_event(
                    user.id, "ORG_DELETED", request.state.user_ip_address,
                    {"org_id": org_id, "org_name": org.name}, db=db
                )
                await db.commit()

        return {"message": "Organization deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/organizations/{org_id}/leave", name="leave_org")
async def leave_organization(
        org_id: str,
        request: Request,
        user: User = Depends(org_checker)
):
    """Leave an organization."""
    try:
        org = await auth_service.orgs.get_organization_by_id(org_id)
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

        if org.owner_id == user.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Owner cannot leave organization. Transfer ownership or delete the organization.")

        # Remove user from org
        async with auth_service.db_manager.get_db() as db:
            from authtuna.core.database import organization_members
            stmt = delete(organization_members).where(
                organization_members.c.user_id == user.id,
                organization_members.c.organization_id == org_id
            )
            await db.execute(stmt)

            # Remove org-scoped roles
            org_scope = f"org:{org_id}"
            user_roles = await auth_service.roles.get_user_roles(user.id, scope=org_scope, db=db)
            for role in user_roles:
                await auth_service.roles.remove_from_user(user.id, role.name, remover_id=user.id, scope=org_scope,
                                                          db=db)

            await auth_service.db_manager.log_audit_event(
                user.id, "ORG_LEFT", request.state.user_ip_address,
                {"org_id": org_id, "org_name": org.name}, db=db
            )
            await db.commit()

        return {"message": f"You have left {org.name}"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/organizations/{org_id}/members/{member_id}", name="remove_org_member")
async def remove_org_member(
        org_id: str,
        member_id: str,
        request: Request,
        user: User = Depends(RoleChecker("OrgAdmin", "OrgOwner", scope_from_path="org_id", mode="OR"))
):
    """Remove a member from an organization."""
    try:
        org = await auth_service.orgs.get_organization_by_id(org_id)
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

        if org.owner_id == member_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove the owner")

        member = await auth_service.users.get_by_id(member_id)
        if not member:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

        # Remove user from org
        async with auth_service.db_manager.get_db() as db:
            from authtuna.core.database import organization_members
            stmt = delete(organization_members).where(
                organization_members.c.user_id == member_id,
                organization_members.c.organization_id == org_id
            )
            result = await db.execute(stmt)

            if result.rowcount == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not in organization")

            # Remove org-scoped roles
            org_scope = f"org:{org_id}"
            user_roles = await auth_service.roles.get_user_roles(member_id, scope=org_scope, db=db)
            for role in user_roles:
                await auth_service.roles.remove_from_user(member_id, role.name, remover_id=user.id, scope=org_scope,
                                                          db=db)

            await auth_service.db_manager.log_audit_event(
                user.id, "ORG_MEMBER_REMOVED", request.state.user_ip_address,
                {"org_id": org_id, "removed_user_id": member_id, "removed_user_email": member.email}, db=db
            )
            await db.commit()

        return {"message": f"Member {member.email} removed from organization"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# Team Management Routes

class TeamCreate(BaseModel):
    name: str


@router.post("/organizations/{org_id}/teams", name="create_team")
async def create_team(
        org_id: str,
        team: TeamCreate,
        request: Request,
        user: User = Depends(RoleChecker("OrgAdmin", "OrgOwner", scope_from_path="org_id", mode="OR"))
):
    """Create a new team in an organization."""
    try:
        ip_address = request.state.user_ip_address
        new_team = await auth_service.orgs.create_team(
            name=team.name,
            org_id=org_id,
            creator=user,
            ip_address=ip_address
        )
        return {"message": "Team created successfully", "team_id": new_team.id, "team_name": new_team.name}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


team_checker = RoleChecker("TeamLead", "TeamMember", scope_from_path="team_id", mode="OR")




class TeamInvite(BaseModel):
    email: str
    role_name: str = "TeamMember"


@router.post("/teams/{team_id}/invite", name="team_invite")
async def invite_to_team(
        team_id: str,
        invite: TeamInvite,
        request: Request,
        user: User = Depends(RoleChecker("TeamLead", scope_from_path="team_id"))
):
    """Invite a user to a team."""
    try:
        ip_address = request.state.user_ip_address
        result = await auth_service.orgs.invite_to_team(
            team_id=team_id,
            invitee_email=invite.email,
            role_name=invite.role_name,
            inviter=user,
            ip_address=ip_address
        )

        if result is True:
            return {"message": f"Invitation sent to {invite.email}", "email_sent": True}
        elif result is None:
            return {"message": f"User {invite.email} automatically added to team", "email_sent": False}
        else:
            return {"message": "Invitation processed", "email_sent": False}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/teams/join", name="team_join_page")
async def accept_team_invite_page(request: Request, token: str):
    """Accept team invite via token."""
    try:
        ip_address = request.state.user_ip_address
        team = await auth_service.orgs.accept_team_invite(token_id=token, ip_address=ip_address)
        return templates.TemplateResponse("invite_accepted.html", {
            "request": request,
            "type": "team",
            "name": team.name,
            "team_id": team.id
        })
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/teams/{team_id}", response_class=HTMLResponse, name="team_details")
async def team_details_page(request: Request, team_id: str, user: User = Depends(team_checker)):
    """Team details page showing members and settings."""
    try:
        team = await auth_service.orgs.get_team_by_id(team_id)
        if not team:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        org = await auth_service.orgs.get_organization_by_id(team.organization_id)
        members = await auth_service.orgs.get_team_members(team_id)

        # Convert timestamps
        team_created_human = _format_ts(team.created_at)
        for m in members:
            if isinstance(m, dict):
                m['joined_at'] = _format_ts(m.get('joined_at'))
        try:
            setattr(team, 'created_at_human', team_created_human)
        except Exception:
            setattr(team, 'created_at_human', None)

        # Check if user is team lead or org admin/owner
        user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"team:{team_id}")
        is_lead = any(role.name == "TeamLead" for role in user_roles)

        org_user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"org:{org.id}")
        is_org_admin = any(role.name in ["OrgAdmin", "OrgOwner"] for role in org_user_roles)

        return templates.TemplateResponse("team_details.html", {
            "request": request,
            "user": user,
            "team": team,
            "org": org,
            "members": members,
            "is_lead": is_lead,
            "is_org_admin": is_org_admin,
            "can_manage": is_lead or is_org_admin
        })
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/teams/{team_id}", name="delete_team")
async def delete_team(
        team_id: str,
        request: Request,
        user: User = Depends(RoleChecker("TeamLead", scope_from_path="team_id"))
):
    """Delete a team."""
    try:
        team = await auth_service.orgs.get_team_by_id(team_id)
        if not team:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        # Check if user is team lead or org admin/owner
        user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"team:{team_id}")
        is_lead = any(role.name == "TeamLead" for role in user_roles)

        org = await auth_service.orgs.get_organization_by_id(team.organization_id)
        is_org_owner = org.owner_id == user.id
        org_user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"org:{org.id}")
        is_org_admin = any(role.name == "OrgAdmin" for role in org_user_roles)

        if not (is_lead or is_org_admin or is_org_owner):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to delete team")

        # Delete the team
        async with auth_service.db_manager.get_db() as db:
            from authtuna.core.database import Team
            team_to_delete = await db.get(Team, team_id)
            if team_to_delete:
                await db.delete(team_to_delete)
                await auth_service.db_manager.log_audit_event(
                    user.id, "TEAM_DELETED", request.state.user_ip_address,
                    {"team_id": team_id, "team_name": team.name, "org_id": team.organization_id}, db=db
                )
                await db.commit()

        return {"message": "Team deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/teams/{team_id}/leave", name="leave_team")
async def leave_team(
        team_id: str,
        request: Request,
        user: User = Depends(team_checker)
):
    """Leave a team."""
    try:
        team = await auth_service.orgs.get_team_by_id(team_id)
        if not team:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        # Check if user is the only team lead
        members = await auth_service.orgs.get_team_members(team_id)
        user_roles = await auth_service.roles.get_user_roles(user.id, scope=f"team:{team_id}")
        is_lead = any(role.name == "TeamLead" for role in user_roles)

        if is_lead and len(members) > 1:
            # Check if there are other leads
            other_leads = False
            for member in members:
                if member["user_id"] != user.id:
                    member_roles = await auth_service.roles.get_user_roles(member["user_id"], scope=f"team:{team_id}")
                    if any(role.name == "TeamLead" for role in member_roles):
                        other_leads = True
                        break

            if not other_leads:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="Cannot leave team as the only lead. Promote another member or delete the team.")

        # Remove user from team
        async with auth_service.db_manager.get_db() as db:
            from authtuna.core.database import team_members
            stmt = delete(team_members).where(
                team_members.c.user_id == user.id,
                team_members.c.team_id == team_id
            )
            await db.execute(stmt)

            # Remove team-scoped roles
            team_scope = f"team:{team_id}"
            for role in user_roles:
                await auth_service.roles.remove_from_user(user.id, role.name, remover_id=user.id, scope=team_scope,
                                                          db=db)

            await auth_service.db_manager.log_audit_event(
                user.id, "TEAM_LEFT", request.state.user_ip_address,
                {"team_id": team_id, "team_name": team.name}, db=db
            )
            await db.commit()

        return {"message": f"You have left {team.name}"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/teams/{team_id}/members/{member_id}", name="remove_team_member")
async def remove_team_member(
        team_id: str,
        member_id: str,
        request: Request,
        user: User = Depends(RoleChecker("TeamLead", scope_from_path="team_id"))
):
    """Remove a member from a team."""
    try:
        team = await auth_service.orgs.get_team_by_id(team_id)
        if not team:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")

        member = await auth_service.users.get_by_id(member_id)
        if not member:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

        # Remove user from team
        async with auth_service.db_manager.get_db() as db:
            from authtuna.core.database import team_members
            stmt = delete(team_members).where(
                team_members.c.user_id == member_id,
                team_members.c.team_id == team_id
            )
            result = await db.execute(stmt)

            if result.rowcount == 0:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not in team")

            # Remove team-scoped roles
            team_scope = f"team:{team_id}"
            user_roles = await auth_service.roles.get_user_roles(member_id, scope=team_scope, db=db)
            for role in user_roles:
                await auth_service.roles.remove_from_user(member_id, role.name, remover_id=user.id, scope=team_scope,
                                                          db=db)

            await auth_service.db_manager.log_audit_event(
                user.id, "TEAM_MEMBER_REMOVED", request.state.user_ip_address,
                {"team_id": team_id, "removed_user_id": member_id, "removed_user_email": member.email}, db=db
            )
            await db.commit()

        return {"message": f"Member {member.email} removed from team"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/profile", status_code=status.HTTP_200_OK)
async def update_profile(
        update_data: UserProfileUpdate,
        request: Request,
        user: User = Depends(RoleChecker("User"))
):
    """
    Update the current user's profile.
    """
    try:
        ip_address = request.state.user_ip_address
        updated_user = await auth_service.users.update(
            user_id=user.id,
            update_data={"username": update_data.username},
            ip_address=ip_address
        )
        return {"message": "Profile updated successfully!", "user": {"username": updated_user.username}}
    except IntegrityError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"An error occurred: {e}")


@router.get("/settings/sessions", response_model=List[SessionInfo])
async def get_user_sessions(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Fetches all active sessions for the current user.
    """
    current_session_id = request.state.session_id
    sessions = await auth_service.sessions.get_all_for_user(user.id, current_session_id)
    return sessions


@router.post("/settings/sessions/{session_id}/terminate", status_code=status.HTTP_200_OK)
async def terminate_session(session_id: str, request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Terminates a specific session for the current user.
    """
    session_to_terminate = await auth_service.sessions.get_by_id(session_id)
    if not session_to_terminate or session_to_terminate.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Session not found or does not belong to user.")

    if session_to_terminate.session_id == request.state.session_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot terminate the current session.")

    ip_address = request.state.user_ip_address
    await auth_service.sessions.terminate(session_id, ip_address)
    return {"message": "Session terminated successfully."}


@router.post("/settings/sessions/terminate-all", status_code=status.HTTP_200_OK)
async def terminate_all_other_sessions(request: Request, user: User = Depends(RoleChecker("User"))):
    """
    Terminates all active sessions for the current user, except the current one.
    """
    current_session_id = request.state.session_id
    ip_address = request.state.user_ip_address
    await auth_service.sessions.terminate_all_for_user(user.id, ip_address, except_session_id=current_session_id)
    return {"message": "All other sessions have been terminated."}


# API Key Management Routes

class ApiKeyCreate(BaseModel):
    name: str
    key_type: str  # "secret", "master", "public", "test"
    scopes: List[str] = []
    valid_seconds: int = 31536000  # 1 year default


class ApiKeyInfo(BaseModel):
    id: str
    name: str
    key_type: str
    created_at: float
    expires_at: float
    last_used_at: Optional[float] = None

    class Config:
        from_attributes = True


@router.get("/settings/api-keys", response_model=List[ApiKeyInfo])
async def get_user_api_keys(user: User = Depends(RoleChecker("User"))):
    """
    Fetches all API keys for the current user.
    """
    keys = await auth_service.api.get_all_keys_for_user(user.id)
    return keys


@router.get("/settings/available-scopes")
async def get_available_scopes(user: User = Depends(RoleChecker("User"))):
    """
    Returns the user's available roles and scopes for creating API keys.
    """
    user_with_roles = await auth_service.users.get_by_id(user.id, with_relations=True)

    scopes_info = []
    for role in user_with_roles.roles:
        role_scopes = user_with_roles.get_role_scope(role.id)
        scopes_info.append({
            "role_name": role.name,
            "scope": role_scopes,
            "display": ", ".join([f"{role.name}:{role_scope}" for role_scope in role_scopes]),
        })

    return {"scopes": scopes_info}


@router.post("/settings/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
        key_data: ApiKeyCreate,
        user: User = Depends(RoleChecker("User"))
):
    """
    Creates a new API key for the current user.
    """
    try:
        api_key = await auth_service.api.create_key(
            user_id=user.id,
            name=key_data.name,
            key_type=key_data.key_type,
            scopes=key_data.scopes if key_data.scopes else None,
            valid_seconds=key_data.valid_seconds
        )
        return {
            "message": "API key created successfully",
            "api_key": {
                "id": api_key.id,
                "name": api_key.name,
                "key_type": api_key.key_type,
                "plaintext": api_key.plaintext,  # Only shown once!
                "created_at": api_key.created_at,
                "expires_at": api_key.expires_at
            }
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/settings/api-keys/{key_id}", status_code=status.HTTP_200_OK)
async def delete_api_key(
        key_id: str,
        user: User = Depends(RoleChecker("User"))
):
    """
    Deletes a specific API key for the current user.
    """
    # Verify the key belongs to the user
    keys = await auth_service.api.get_all_keys_for_user(user.id)
    if not any(k.id == key_id for k in keys):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="API key not found or does not belong to user.")

    success = await auth_service.api.delete_key(key_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    return {"message": "API key deleted successfully."}


def _format_ts(ts: Optional[float]) -> str:
    """Return a human-readable timestamp string or a placeholder if None."""
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

