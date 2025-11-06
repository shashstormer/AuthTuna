from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from starlette.templating import Jinja2Templates

from authtuna import settings
from authtuna.core.database import User
from authtuna.core.exceptions import RoleNotFoundError, PermissionNotFoundError, UserNotFoundError, \
    OperationForbiddenError
from authtuna.integrations.fastapi_integration import get_current_user, auth_service, PermissionChecker
from authtuna.routers.auth import RoleInfo

# --- Router Setup ---
# A router-level dependency ensures that users have basic admin panel access.
# Specific, more powerful permissions are checked on each endpoint individually.
router = APIRouter(
    prefix="/admin", tags=["Administration"], dependencies=[Depends(PermissionChecker("admin:access:panel"))],
)

templates = Jinja2Templates(directory=settings.HTML_TEMPLATE_DIR)
templates.env.globals['get_theme_css'] = __import__('authtuna.helpers.theme', fromlist=['get_theme_css']).get_theme_css


# --- Pydantic Models (Unchanged) ---

class RoleCreate(BaseModel):
    name: str = Field(..., description="The unique name for the new role.")
    description: Optional[str] = Field(None, description="A brief description of the role's purpose.")
    level: Optional[int] = Field(None, description="An optional integer hierarchy level for the role.")


class PermissionCreate(BaseModel):
    name: str = Field(..., description="The unique name for the new permission (e.g., 'timeline:edit:content').")
    description: Optional[str] = Field(None, description="A brief description of what the permission allows.")


class AssignPermissionToRole(BaseModel):
    permission_name: str


class AssignRoleToUser(BaseModel):
    user_id: str
    role_name: str
    scope: str = Field("global", description="The scope in which the role is granted (e.g., 'global', 'timeline:123').")


class UserSearchResult(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True


class UserSuspend(BaseModel):
    reason: str = Field("No reason provided.", description="The reason for suspending the user.")


class AuditEventResponse(BaseModel):
    event_type: str
    timestamp: float
    ip_address: Optional[str]
    details: Optional[dict]

    class Config:
        from_attributes = True


class GrantRoleAssignPermission(BaseModel):
    assigner_role_name: str
    assignable_role_name: str


class GrantPermissionGrantPermission(BaseModel):
    granter_role_name: str
    grantable_permission_name: str

class PermissionInfo(BaseModel):
    name: str

    class Config:
        from_attributes = True


class UserInRole(BaseModel):
    username: str
    scope: str


class RoleDetail(RoleInfo):
    permissions: List[PermissionInfo]
    users: List[UserInRole]

@router.get(
    "/users/search", response_model=List[UserSearchResult], summary="Search and Filter Users",
    dependencies=[Depends(PermissionChecker("admin:manage:users"))]  # ADDED: Specific permission
)
async def search_users_endpoint(
        identity: Optional[str] = Query(None, description="Search by email or username."),
        role: Optional[str] = Query(None, description="Filter by a role the user has."),
        scope: Optional[str] = Query(None, description="Filter by a scope the user has a role in."),
        is_active: Optional[bool] = Query(None, description="Filter by user's active status."), skip: int = 0,
        limit: int = 50
):
    """Provides advanced, flexible filtering for users."""
    users = await auth_service.users.search_users(
        identity=identity, role=role, scope=scope, is_active=is_active, skip=skip, limit=limit
    )
    return users

@router.get(
    "/users/{user_id}", response_class=HTMLResponse, summary="Serve the User Detail Page"
)
async def serve_user_detail_page(request: Request):
    """Serves the HTML page for viewing a single user's details."""
    return templates.TemplateResponse("admin_user_detail.html", {"request": request})

@router.get("/assignable-roles", dependencies=[Depends(PermissionChecker("admin:manage:roles"))])
async def get_my_assignable_roles(current_user: User = Depends(get_current_user), ):
    """
    Returns a list of roles the current user can assign to themselves.
    """
    assignable_roles = await auth_service.roles.get_self_assignable_roles(current_user.id)
    return assignable_roles

@router.get(
    "/users/{user_id}/assignable-roles", summary="Get Roles Assignable by Current Admin",
    dependencies=[Depends(PermissionChecker("admin:manage:roles"))]
)
async def get_assignable_roles_for_user(user_id: str, admin_user: User = Depends(get_current_user)):
    """
    Retrieves a list of roles that the currently authenticated admin
    is permitted to assign to the specified user.
    """
    try:
        assignable_roles = await auth_service.roles.get_assignable_roles_for_user(
            target_user_id=user_id, assigning_user=admin_user
        )
        return assignable_roles
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/users/{user_id}/details-data", summary="Get Detailed User Information",
    dependencies=[Depends(PermissionChecker("admin:manage:users"))]
)
async def get_user_details_data(user_id: str):
    """Retrieves detailed information about a single user, including their roles."""
    user = await auth_service.users.get_by_id(user_id, with_relations=True)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    roles = await auth_service.roles.get_user_roles_with_scope(user.id)
    can_assign = await auth_service.roles.get_self_assignable_roles(user.id)
    return {
        "id": user.id,
        "email": user.email,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "username": user.username,
        "roles": roles,
        "can_assign": can_assign,
    }


@router.get(
    "/roles/{role_name}", response_class=HTMLResponse, summary="Serve the Role Detail Page"
)
async def serve_role_detail_page(request: Request):
    """Serves the HTML page for viewing a single role's details."""
    return templates.TemplateResponse("admin_role_detail.html", {"request": request})


@router.get(
    "/roles/{role_name}/details-data", summary="Get Detailed Role Information",
    dependencies=[Depends(PermissionChecker("admin:manage:roles"))]
)
async def get_role_details_data(role_name: str):
    """Retrieves detailed information about a single role, including permissions and users."""
    role = await auth_service.roles.get_by_name(role_name)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    users = await auth_service.roles.get_users_for_role(role_name)

    return {
        "name": role.name, "description": role.description, "level": role.level, "permissions": role.permissions,
        "users": users
    }


@router.get(
    "/dashboard", response_class=HTMLResponse, summary="Serve the Admin Dashboard HTML Page"
)
async def serve_admin_dashboard(request: Request):
    """Serves the main admin dashboard HTML page."""
    return templates.TemplateResponse("admin_dashboard.html", {"request": request})


@router.get(
    "/roles", summary="List All Roles", dependencies=[Depends(PermissionChecker("admin:manage:roles"))]
)
async def list_roles():
    """Retrieves a list of all roles in the system."""
    roles = await auth_service.roles.get_all_roles()
    return roles


# --- Admin Endpoints ---


@router.post(
    "/users/{user_id}/suspend", response_model=UserSearchResult, summary="Suspend a User Account",
    dependencies=[Depends(PermissionChecker("admin:manage:users"))]  # ADDED: Specific permission
)
async def suspend_user(user_id: str, payload: UserSuspend, admin_user: User = Depends(get_current_user)):
    """Suspends a user, preventing them from logging in."""
    try:
        user = await auth_service.users.suspend_user(user_id, admin_id=admin_user.id, reason=payload.reason)
        return user
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/users/{user_id}/unsuspend", response_model=UserSearchResult, summary="Unsuspend a User Account",
    dependencies=[Depends(PermissionChecker("admin:manage:users"))]  # ADDED: Specific permission
)
async def unsuspend_user(user_id: str, payload: UserSuspend, admin_user: User = Depends(get_current_user)):
    """Reactivates a previously suspended user."""
    try:
        user = await auth_service.users.unsuspend_user(user_id, admin_id=admin_user.id, reason=payload.reason)
        return user
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/users/{user_id}/audit-log", response_model=List[AuditEventResponse], summary="Get User Audit Log",
    dependencies=[Depends(PermissionChecker("admin:manage:users"))]  # ADDED: Specific permission
)
async def get_user_audit_log(user_id: str, skip: int = 0, limit: int = 25):
    """Retrieves the security audit trail for a specific user."""
    events = await auth_service.audit.get_events_for_user(user_id, skip=skip, limit=limit)
    return events


@router.post(
    "/roles", status_code=status.HTTP_201_CREATED, dependencies=[Depends(PermissionChecker("admin:manage:roles"))]
    # ADDED: Specific permission
)
async def create_role(role_data: RoleCreate):
    """Creates a new role in the system with an optional level."""
    try:
        await auth_service.roles.create(
            name=role_data.name, description=role_data.description, level=role_data.level
        )
        return {"message": f"Role '{role_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post(
    "/permissions", status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(PermissionChecker("admin:manage:permissions"))]  # ADDED: Specific permission
)
async def create_permission(permission_data: PermissionCreate):
    """Creates a new permission in the system."""
    try:
        await auth_service.permissions.get_or_create(permission_data.name,
                                                     defaults={"description": permission_data.description})
        return {"message": f"Permission '{permission_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post(
    "/roles/{role_name}/permissions", dependencies=[Depends(PermissionChecker("admin:manage:roles"))]
    # ADDED: Specific permission
)
async def add_permission_to_role(role_name: str, payload: AssignPermissionToRole,
                                 admin_user: User = Depends(get_current_user)):
    """Assigns an existing permission to an existing role."""
    try:
        await auth_service.roles.add_permission_to_role(role_name, payload.permission_name, admin_user.id)
        return {"message": f"Permission '{payload.permission_name}' added to role '{role_name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/users/roles/assign", dependencies=[Depends(PermissionChecker("admin:manage:roles"))]  # ADDED: Specific permission
)
async def assign_role_to_user(payload: AssignRoleToUser, admin_user: User = Depends(get_current_user)):
    """Assigns a role to a user."""
    try:
        await auth_service.roles.assign_to_user(
            user_id=payload.user_id, role_name=payload.role_name, scope=payload.scope, assigner_id=admin_user.id
        )
        return {"message": f"Role '{payload.role_name}' assigned to user {payload.user_id} in scope '{payload.scope}'."}
    except (UserNotFoundError, RoleNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/users/roles/revoke", dependencies=[Depends(PermissionChecker("admin:manage:roles"))]  # ADDED: Specific permission
)
async def revoke_role_from_user(payload: AssignRoleToUser, admin_user: User = Depends(get_current_user)):
    """Revokes a role from a user within a specific scope."""
    try:
        success = await auth_service.roles.revoke_user_role_by_scope(
            user_id=payload.user_id, role_name=payload.role_name, scope=payload.scope, revoker_id=admin_user.id, )
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found.")
        return {"message": f"Role '{payload.role_name}' revoked from user {payload.user_id}."}
    except (RoleNotFoundError, UserNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.delete(
    "/roles/{role_name}", dependencies=[Depends(PermissionChecker("admin:manage:roles"))]  # ADDED: Specific permission
)
async def delete_role(role_name: str, admin_user: User = Depends(get_current_user)):
    """Deletes a role from the system."""
    try:
        await auth_service.roles.delete_role(role_name=role_name, deleter_id=admin_user.id)
        return {"message": f"Role '{role_name}' has been deleted."}
    except RoleNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/roles/grants/assign-role", status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(PermissionChecker("admin:manage:roles"))]  # ADDED: Specific permission
)
async def grant_role_assignment_permission(payload: GrantRoleAssignPermission):
    """Authorizes a role to be able to assign another role."""
    try:
        granter_role, assignable_role = await auth_service.roles.grant_relationship(
            granter_role_name=payload.assigner_role_name, grantable_name=payload.assignable_role_name,
            grantable_manager=auth_service.roles, relationship_attr="can_assign_roles"
        )
        return {"message": f"Role '{granter_role.name}' can now assign role '{assignable_role.name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post(
    "/roles/grants/grant-permission", status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(PermissionChecker("admin:manage:permissions"))]  # ADDED: Specific permission
)
async def grant_permission_granting_permission(payload: GrantPermissionGrantPermission):
    """Authorizes a role to grant a specific permission to other roles."""
    try:
        granter_role, permission = await auth_service.roles.grant_relationship(
            granter_role_name=payload.granter_role_name, grantable_name=payload.grantable_permission_name,
            grantable_manager=auth_service.permissions, relationship_attr="can_grant_permissions"
        )
        return {"message": f"Role '{granter_role.name}' can now grant permission '{permission.name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))
