# authtuna/routers/admin.py
# NEW: A dedicated, secure router for administrative tasks.

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from authtuna.core.database import User
from authtuna.core.exceptions import RoleNotFoundError, PermissionNotFoundError, UserNotFoundError
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


class PermissionCreate(BaseModel):
    name: str = Field(..., description="The unique name for the new permission (e.g., 'timeline:edit:content').")
    description: Optional[str] = Field(None, description="A brief description of what the permission allows.")


class AssignPermissionToRole(BaseModel):
    permission_name: str


class AssignRoleToUser(BaseModel):
    user_id: str
    role_name: str
    scope: str = Field("global", description="The scope in which the role is granted (e.g., 'global', 'timeline:123').")


# --- Admin Endpoints ---

@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(role_data: RoleCreate):
    """Creates a new role in the system."""
    try:
        await auth_service.roles.get_or_create(role_data.name, defaults={"description": role_data.description})
        return {"message": f"Role '{role_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/permissions", status_code=status.HTTP_201_CREATED)
async def create_permission(permission_data: PermissionCreate):
    """Creates a new permission in the system."""
    try:
        await auth_service.permissions.get_or_create(permission_data.name, defaults={"description": permission_data.description})
        return {"message": f"Permission '{permission_data.name}' created successfully."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/roles/{role_name}/permissions")
async def add_permission_to_role(role_name: str, payload: AssignPermissionToRole, admin_user: User = Depends(get_current_user)):
    """Assigns an existing permission to an existing role."""
    try:
        await auth_service.roles.add_permission_to_role(role_name, payload.permission_name, admin_user.id)
        return {"message": f"Permission '{payload.permission_name}' added to role '{role_name}'."}
    except (RoleNotFoundError, PermissionNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/users/roles/assign")
async def assign_role_to_user(payload: AssignRoleToUser, admin_user: User = Depends(get_current_user)):
    """Assigns a role to a user within a specific scope."""
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


@router.post("/users/roles/revoke")
async def revoke_role_from_user(payload: AssignRoleToUser):
    """Revokes a role from a user within a specific scope."""
    try:
        success = await auth_service.roles.revoke_user_role_by_scope(
            user_id=payload.user_id,
            role_name=payload.role_name,
            scope=payload.scope
        )
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found for the given user, role, and scope.")
        return {"message": f"Role '{payload.role_name}' revoked from user {payload.user_id} in scope '{payload.scope}'."}
    except RoleNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
