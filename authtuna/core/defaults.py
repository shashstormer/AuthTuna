import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from authtuna.core.database import User, Role, Permission, user_roles_association
from authtuna.core.encryption import encryption_utils
from authtuna.core.config import settings

DEFAULT_PERMISSIONS = {
    "admin:access:panel": "Access the main admin dashboard.",
    "admin:manage:users": "Create, edit, suspend, and delete users.",
    "admin:manage:roles": "Create roles and manage role assignment grants.",
    "admin:manage:permissions": "Create permissions and manage permission grant relationships.",
    "roles:assign:SuperAdmin": "Permission to assign the SuperAdmin role.",
    "roles:assign:Admin": "Permission to assign the Admin role.",
    "roles:assign:Moderator": "Permission to assign the Moderator role.",
    "roles:assign:User": "Permission to assign the User role.",
}
DEFAULT_ROLES = {
    "User": {"level": 10, "description": "Standard user with basic permissions."},
    "Moderator": {"level": 50, "description": "Can manage users and content."},
    "Admin": {"level": 90, "description": "Full administrative access to most features."},
    "SuperAdmin": {"level": 100, "description": "Highest level of administrative access."},
    "System": {"level": 999, "system": True, "description": "For automated, internal system processes."},
}
ROLE_PERMISSIONS = {
    "Moderator": ["admin:access:panel", "admin:manage:users"],
    "Admin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "roles:assign:Moderator",
              "roles:assign:User"],
    "SuperAdmin": ["admin:access:panel", "admin:manage:users", "admin:manage:roles", "admin:manage:permissions",
                   "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"],
    "System": ["roles:assign:SuperAdmin", "roles:assign:Admin", "roles:assign:Moderator", "roles:assign:User"]
}


async def provision_defaults(db: AsyncSession):
    """
    Idempotently creates default permissions, roles, and users.
    """
    system_user_exists = (await db.execute(select(User).where(User.id == "system"))).unique().scalar_one_or_none()
    if system_user_exists:
        return

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
        if not (await db.execute(select(Role).where(Role.name == name))).scalar_one_or_none():
            db.add(Role(name=name, **attrs))
    await db.flush()

    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = (await db.execute(select(Role).where(Role.name == role_name))).unique().scalar_one()
        for perm_name in perm_names:
            permission = (await db.execute(select(Permission).where(Permission.name == perm_name))).scalar_one()
            if permission not in role.permissions:
                role.permissions.append(permission)

    for user_key, user_data in DEFAULT_USERS.items():
        if not (await db.execute(select(User).where(User.id == user_data["id"]))).scalar_one_or_none():
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

    await db.commit()