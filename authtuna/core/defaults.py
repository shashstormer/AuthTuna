import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from authtuna.core.database import User, Role, Permission, user_roles_association
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings
import logging
logger = logging.getLogger(__name__)

DEFAULT_PERMISSIONS = {
    "admin:access:panel": "Access the main admin dashboard.",
    "admin:manage:users": "Create, edit, suspend, and delete users.",
    "admin:manage:roles": "Create roles and manage role assignment grants.",
    "admin:manage:permissions": "Create permissions and manage permission grant relationships.",
    "roles:assign:SuperAdmin": "Permission to assign the SuperAdmin role.",
    "roles:assign:Admin": "Permission to assign the Admin role.",
    "roles:assign:Moderator": "Permission to assign the Moderator role.",
    "roles:assign:User": "Permission to assign the User role.",

    "org:create": "Permission to create a new organization.",
    "org:manage": "Permission to edit and delete an organization.",
    "org:invite_member": "Permission to invite new members to an organization.",
    "org:remove_member": "Permission to remove members from an organization.",
    "team:create": "Permission to create a new team within an organization.",
    "team:manage": "Permission to edit and delete a team.",
    "team:invite_member": "Permission to invite new members to a team.",
    "team:remove_member": "Permission to remove members from a team.",
    "team:delete": "Permission to delete a team.",
}
DEFAULT_ROLES = {
    "User": {"level": 0, "description": "Standard user with basic permissions will be assigned to all users by default (from v0.1.11), allows configuring if all users can create orgs or only specific users so based on requirement you will be able to update and build further."},

    # These are addedd for organization management. These will be using the role based grant system instead of hierarchical
    "OrgMember": {"description": "Default member of an organization."},
    "TeamMember": {"description": "Default member of a team."},
    "TeamLead": {"description": "Can manage a specific team and its members."},
    "OrgAdmin": {"description": "Can manage an organization's members and teams."},
    "OrgOwner": {"description": "Full control over an organization."},

    # the following roles meant purely for administrative purposes for the auth service owners and use hierarchical grant system.
    "Moderator": {"level": 50, "description": "Can manage users and content."},
    "Admin": {"level": 90, "description": "Full administrative access to most features."},
    "SuperAdmin": {"level": 100, "description": "Highest level of administrative access."},
    "System": {"level": 999, "system": True, "description": "For automated, internal system processes."},
}
ROLE_PERMISSIONS = {
    "Moderator": ["admin:access:panel", "admin:manage:users", "roles:assign:User"],
    "Admin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "roles:assign:Moderator",
              "roles:assign:User"],
    "SuperAdmin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "admin:manage:permissions",
                   "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"],
    "System": ["roles:assign:SuperAdmin", "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"],

    "OrgMember": ["org:create"],
    "TeamLead": ["team:invite_member", "team:remove_member", "team:manage"],
    "OrgAdmin": ["org:invite_member", "org:remove_member", "team:create", "team:delete", "team:manage"],
    "OrgOwner": ["org:manage", "org:invite_member", "org:remove_member", "team:create", "team:delete", "team:manage"],
}

DEFAULT_ROLE_GRANTS = {
    # System Admin Roles
    "System": ["SuperAdmin", "Admin", "Moderator", "OrgOwner", "OrgAdmin", "TeamLead", "OrgMember", "User", "TeamMember"],
    "SuperAdmin": ["Admin", "Moderator", "OrgOwner", "OrgAdmin", "TeamLead", "OrgMember", "User", "TeamMember"], # anyway hierarchical system exists so this and the next line dont actually matter.
    "Admin": ["Moderator", "OrgOwner", "OrgAdmin", "TeamLead", "OrgMember", "User"],

    # Organization Roles
    "OrgOwner": ["OrgAdmin", "TeamLead", "OrgMember", "TeamMember"],
    "OrgAdmin": ["TeamLead", "OrgMember", "TeamMember"],
    "TeamLead": ["TeamMember"],
}

async def provision_defaults(db: AsyncSession):
    """
    Idempotently creates default permissions, roles, and users.
    """
    if not settings.TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN:
        system_user_exists = (await db.execute(select(User).where(
            User.id == "system"))).unique().scalar_one_or_none()  # this is to reduce database queries. If the system user exists, there is no need to provision defaults, if you want to re initialize a specific user then delete that user and system and they will be reprovisioned on next start.
        if system_user_exists:
            return
    logger.debug("Provisioning default permissions, roles, and users.")
    DEFAULT_USERS = {
        "system": {
            "id": "system", "username": "system", "email": "system@local.host", "password": None, "roles": ["System"]
        },
        "superadmin": {
            "id": "default-super-admin", "username": "superadmin", "email": settings.DEFAULT_SUPERADMIN_EMAIL,
            "password": settings.DEFAULT_SUPERADMIN_PASSWORD.get_secret_value() if settings.DEFAULT_SUPERADMIN_PASSWORD else None,
            "roles": ["SuperAdmin", "User"]
        },
        "admin": {
            "id": "default-admin", "username": "admin", "email": settings.DEFAULT_ADMIN_EMAIL,
            "password": settings.DEFAULT_ADMIN_PASSWORD.get_secret_value() if settings.DEFAULT_ADMIN_PASSWORD else None,
            "roles": ["Admin", "User"]
        }
    }

    for name, desc in DEFAULT_PERMISSIONS.items():
        if not (await db.execute(select(Permission).where(Permission.name == name))).scalar_one_or_none():
            db.add(Permission(name=name, description=desc))
    await db.flush()

    for name, attrs in DEFAULT_ROLES.items():
        if not (await db.execute(select(Role).where(Role.name == name))).unique().scalar_one_or_none():
            db.add(Role(name=name, **attrs))
    await db.flush()

    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = (await db.execute(select(Role).where(Role.name == role_name))).unique().scalar_one_or_none()
        for perm_name in perm_names:
            permission = (await db.execute(select(Permission).where(Permission.name == perm_name))).scalar_one_or_none()
            if permission not in role.permissions:
                role.permissions.append(permission)
    await db.flush()

    for user_key, user_data in DEFAULT_USERS.items():
        if not (await db.execute(select(User).where(User.id == user_data["id"]))).unique().scalar_one_or_none():
            new_user = User(
                id=user_data["id"],
                username=user_data["username"],
                email=user_data["email"],
                email_verified=True,
                is_active=True,
            )

            if user_data.get("password"):
                new_user.password_hash = encryption_utils.hash_password(user_data["password"])

            db.add(new_user)
            await db.flush()

            for role_name in user_data["roles"]:
                role = (await db.execute(select(Role).where(Role.name == role_name))).unique().scalar_one()
                stmt = user_roles_association.insert().values(
                    user_id=new_user.id,
                    role_id=role.id,
                    scope='global',
                    given_by_id='system',
                    given_at=time.time()
                )
                await db.execute(stmt)
    await db.flush()
    for assigner_name, assignable_names in DEFAULT_ROLE_GRANTS.items():
        assigner_role_query = select(Role).options(
            selectinload(Role.can_assign_roles)
        ).where(Role.name == assigner_name)
        assigner_role_result = await db.execute(assigner_role_query)
        assigner_role = assigner_role_result.unique().scalar_one_or_none()
        if not assigner_role:
            logger.warning(f"Warning: Assigner role '{assigner_name}' not found, skipping grants.")
            continue
        for assignable_name in assignable_names:
            assignable_role_result = await db.execute(select(Role).options(selectinload(Role.can_assign_roles)).where(Role.name == assignable_name))
            assignable_role = assignable_role_result.unique().scalar_one_or_none()
            if not assignable_role:
                logger.warning(
                    f"Warning: Assignable role '{assignable_name}' for assigner '{assigner_name}' not found, skipping.")
                continue
            if assignable_role not in assigner_role.can_assign_roles:
                assigner_role.can_assign_roles.append(assignable_role)
                logger.debug(f"Granting: '{assigner_name}' -> can assign -> '{assignable_name}'")
    await db.commit()
