# authtuna/routers/admin.py
# NEW: A dedicated, secure router for administrative tasks.

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field

from authtuna.core.database import User, db_manager
from authtuna.core.exceptions import RoleNotFoundError, PermissionNotFoundError, UserNotFoundError, \
    OperationForbiddenError
from authtuna.integrations.fastapi_integration import get_current_user, auth_service, PermissionChecker

# --- Router Setup ---
# All routes in this file will be prefixed with /admin and tagged for documentation.
# A router-level dependency ensures that ONLY users with the 'admin:manage:system'
# permission can access any of these endpoints.
router = APIRouter(
    prefix="/admin",
    tags=["Administration"],
    dependencies=[Depends(PermissionChecker("admin:manage:system"))],
)


# --- Pydantic Models for Admin Operations ---

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


# --- Admin Endpoints ---
@router.get("/users/search", response_model=List[UserSearchResult], summary="Search and Filter Users")
async def search_users_endpoint(
        identity: Optional[str] = Query(None,
                                        description="Search by email or username (case-insensitive, partial match)."),
        role: Optional[str] = Query(None, description="Filter by a role the user has."),
        scope: Optional[str] = Query(None, description="Filter by a scope the user has a role in."),
        is_active: Optional[bool] = Query(None, description="Filter by user's active status."),
        skip: int = 0,
        limit: int = 50
):
    """Provides advanced, flexible filtering for users."""
    users = await auth_service.users.search_users(
        identity=identity, role=role, scope=scope,
        is_active=is_active, skip=skip, limit=limit
    )
    return users


@router.post("/users/{user_id}/suspend", response_model=UserSearchResult, summary="Suspend a User Account")
async def suspend_user(user_id: str, payload: UserSuspend, admin_user: User = Depends(get_current_user)):
    """Suspends a user, preventing them from logging in."""
    try:
        user = await auth_service.users.suspend_user(user_id, admin_id=admin_user.id, reason=payload.reason)
        return user
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/users/{user_id}/unsuspend", response_model=UserSearchResult, summary="Unsuspend a User Account")
async def unsuspend_user(user_id: str, payload: UserSuspend, admin_user: User = Depends(get_current_user)):
    """Reactivates a previously suspended user."""
    try:
        user = await auth_service.users.unsuspend_user(user_id, admin_id=admin_user.id, reason=payload.reason)
        return user
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/users/{user_id}/audit-log", response_model=List[AuditEventResponse], summary="Get User Audit Log")
async def get_user_audit_log(user_id: str, skip: int = 0, limit: int = 25):
    """Retrieves the security audit trail for a specific user."""
    events = await auth_service.audit.get_events_for_user(user_id, skip=skip, limit=limit)
    return events


@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(role_data: RoleCreate):
    """Creates a new role in the system with an optional level."""
    try:
        await auth_service.roles.create(
            name=role_data.name,
            description=role_data.description,
            level=role_data.level
        )
        return {"message": f"Role '{role_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))



@router.post("/permissions", status_code=status.HTTP_201_CREATED)
async def create_permission(permission_data: PermissionCreate):
    """Creates a new permission in the system."""
    try:
        await auth_service.permissions.get_or_create(permission_data.name,
                                                     defaults={"description": permission_data.description})
        return {"message": f"Permission '{permission_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/roles/{role_name}/permissions")
async def add_permission_to_role(role_name: str, payload: AssignPermissionToRole,
                                 admin_user: User = Depends(get_current_user)):
    """Assigns an existing permission to an existing role."""
    try:
        await auth_service.roles.add_permission_to_role(role_name, payload.permission_name, admin_user.id)
        return {"message": f"Permission '{payload.permission_name}' added to role '{role_name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/users/roles/assign")
async def assign_role_to_user(payload: AssignRoleToUser, admin_user: User = Depends(get_current_user)):
    """
    Assigns a role to a user. The core manager now handles all complex authorization checks
    (level, direct grant, or permission override) internally.
    """
    try:
        await auth_service.roles.assign_to_user(
            user_id=payload.user_id,
            role_name=payload.role_name,
            scope=payload.scope,
            assigner_id=admin_user.id
        )
        return {"message": f"Role '{payload.role_name}' assigned to user {payload.user_id} in scope '{payload.scope}'."}
    except (UserNotFoundError, RoleNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))



@router.post("/users/roles/revoke")
async def revoke_role_from_user(payload: AssignRoleToUser, admin_user: User = Depends(get_current_user)):
    """Revokes a role from a user within a specific scope, now with authorization."""
    try:
        success = await auth_service.roles.revoke_user_role_by_scope(
            user_id=payload.user_id,
            role_name=payload.role_name,
            scope=payload.scope,
            revoker_id=admin_user.id,
        )
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found for the given user, role, and scope.")
        return {"message": f"Role '{payload.role_name}' revoked from user {payload.user_id} in scope '{payload.scope}'."}
    except (RoleNotFoundError, UserNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.delete("/roles/{role_name}")
async def delete_role(role_name: str, admin_user: User = Depends(get_current_user)):
    """Deletes a role from the system, now with authorization."""
    try:
        await auth_service.roles.delete_role(
            role_name=role_name,
            deleter_id=admin_user.id
        )
        return {"message": f"Role '{role_name}' has been deleted."}
    except RoleNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except OperationForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))



@router.post("/roles/grants/assign-role", status_code=status.HTTP_201_CREATED)
async def grant_role_assignment_permission(payload: GrantRoleAssignPermission,
                                           admin_user: User = Depends(get_current_user)):
    """
    Authorizes a role to be able to assign another role.
    Requires 'admin:manage:roles' permission.
    """
    if not await auth_service.roles.has_permission(admin_user.id, "admin:manage:roles"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Missing required permission: 'admin:manage:roles'")

    try:
        granter_role, assignable_role = await auth_service.roles.grant_relationship(
                granter_role_name=payload.assigner_role_name,
                grantable_name=payload.assignable_role_name,
                grantable_manager=auth_service.roles,
                relationship_attr="can_assign_roles"
            )
        return {"message": f"Role '{granter_role.name}' can now assign role '{assignable_role.name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/roles/grants/grant-permission", status_code=status.HTTP_201_CREATED)
async def grant_permission_granting_permission(payload: GrantPermissionGrantPermission,
                                               admin_user: User = Depends(get_current_user)):
    """
    Authorizes a role to be able to add a specific permission to other roles.
    Requires 'admin:manage:permissions' permission.
    """
    if not await auth_service.roles.has_permission(admin_user.id, "admin:manage:permissions"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Missing required permission: 'admin:manage:permissions'")

    try:
        granter_role, permission = await auth_service.roles.grant_relationship(
                granter_role_name=payload.granter_role_name,
                grantable_name=payload.grantable_permission_name,
                grantable_manager=auth_service.permissions,
                relationship_attr="can_grant_permissions"
            )
        return {"message": f"Role '{granter_role.name}' can now grant permission '{permission.name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))