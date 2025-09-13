from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from authtuna.core.database import User, Role, Permission
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings


DEFAULT_PERMISSIONS = {
    # General Admin Access
    "admin:access:panel": "Access the main admin dashboard.",

    # User Management
    "admin:manage:users": "Create, edit, suspend, and delete users.",

    # Role & Permission Management
    "admin:manage:roles": "Create roles and manage role assignment grants.",
    "admin:manage:permissions": "Create permissions and manage permission grant relationships.",

    # System-level permissions for assigning any role
    "roles:assign:SuperAdmin": "Permission to assign the SuperAdmin role.",
    "roles:assign:Admin": "Permission to assign the Admin role.",
    "roles:assign:Moderator": "Permission to assign the Moderator role.",
    "roles:assign:User": "Permission to assign the User role.",
}

# --- Default Roles and their Hierarchy ---
DEFAULT_ROLES = {
    "User": {"level": 10, "description": "Standard user with basic permissions."},
    "Moderator": {"level": 50, "description": "Can manage users and content."},
    "Admin": {"level": 90, "description": "Full administrative access to most features."},
    "SuperAdmin": {"level": 100, "description": "Highest level of administrative access."},
    "System": {"level": 999, "system": True, "description": "For automated, internal system processes."},
}

# --- Mapping Permissions to Roles ---
ROLE_PERMISSIONS = {
    "Moderator": ["admin:access:panel", "admin:manage:users"],
    "Admin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "roles:assign:Moderator",
              "roles:assign:User"],
    "SuperAdmin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "admin:manage:permissions",
                   "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"],
    "System": ["roles:assign:SuperAdmin", "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"]
}

# --- Default Users with Fixed IDs ---
DEFAULT_USERS = {
    "system": {
        "id": "system",
        "username": "system",
        "email": "system@local.host",
        "password": None, # Explicitly no password
        "roles": ["System"]
    },
    "superadmin": {
        "id": "default-super-admin",
        "username": "superadmin",
        "email": settings.DEFAULT_SUPERADMIN_EMAIL,
        "password": None if not settings.DEFAULT_SUPERADMIN_PASSWORD else settings.DEFAULT_SUPERADMIN_PASSWORD.get_secret_value(),
        "roles": ["SuperAdmin", "User"]
    },
    "admin": {
        "id": "default-admin",
        "username": "admin",
        "email": settings.DEFAULT_ADMIN_EMAIL,
        "password": None if not settings.DEFAULT_ADMIN_PASSWORD else settings.DEFAULT_ADMIN_PASSWORD.get_secret_value(),
        "roles": ["Admin", "User"]
    }
}


async def provision_defaults(db: AsyncSession):
    """
    Idempotently creates default permissions, roles, and users.
    This function checks for the existence of the 'system' user and exits if found,
    preventing re-provisioning on subsequent startups.
    """
    # Check if provisioning has already been done by looking for the system user.
    system_user_exists = (await db.execute(select(User).where(User.id == "system"))).scalar_one_or_none()
    if system_user_exists:
        return # Defaults are already provisioned.

    # 1. Provision all default permissions
    for name, desc in DEFAULT_PERMISSIONS.items():
        if not (await db.execute(select(Permission).where(Permission.name == name))).scalar_one_or_none():
            db.add(Permission(name=name, description=desc))
    await db.flush()

    # 2. Provision all default roles
    for name, attrs in DEFAULT_ROLES.items():
        if not (await db.execute(select(Role).where(Role.name == name))).scalar_one_or_none():
            db.add(Role(name=name, **attrs))
    await db.flush()

    # 3. Map permissions to roles
    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
        for perm_name in perm_names:
            permission = (await db.execute(select(Permission).where(Permission.name == perm_name))).scalar_one()
            if permission not in role.permissions:
                role.permissions.append(permission)

    # 4. Create default users if they don't exist
    for user_key, user_data in DEFAULT_USERS.items():
        user_id = user_data["id"]
        if not (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none():
            new_user = User(
                id=user_id,
                username=user_data["username"],
                email=user_data["email"],
                email_verified=True,
                is_active=True
            )

            if user_data.get("password"):
                new_user.password_hash = encryption_utils.hash_password(user_data["password"])

            db.add(new_user)
            await db.flush()

            # Assign roles to the new user
            for role_name in user_data["roles"]:
                role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
                new_user.roles.append(role)
            db.add(new_user)

    await db.commit()