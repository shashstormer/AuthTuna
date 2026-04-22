import asyncio
from authtuna.integrations import auth_service
from authtuna.core.config import init_settings

async def setup_rbac():
    # 1. Initialize settings if not using .env
    # init_settings(DEFAULT_DATABASE_URI="sqlite+aiosqlite:///./authtuna.db", ...)

    # 2. Create Permissions
    # permissions are unique and idempotent via get_or_create
    await auth_service.permissions.get_or_create("posts:write", {"description": "Can create/edit posts"})
    await auth_service.permissions.get_or_create("posts:delete", {"description": "Can delete posts"})
    
    # 3. Create Roles
    # higher level = more power
    editor_role, _ = await auth_service.roles.get_or_create("editor", {"level": 100})
    admin_role, _ = await auth_service.roles.get_or_create("admin", {"level": 500})
    
    # 4. Bind Permissions to Roles
    await auth_service.roles.add_permission_to_role("editor", "posts:write")
    await auth_service.roles.add_permission_to_role("admin", "posts:write")
    await auth_service.roles.add_permission_to_role("admin", "posts:delete")
    
    # 5. Assign Role to User with Scope
    # Scope can be 'global', or a specific resource identifier
    await auth_service.roles.assign_to_user(
        user_id="target_user_id",
        role_name="editor",
        assigner_id="system",  # Using system as assigner bypasses level checks
        scope="blog:tech"
    )
    
    print("RBAC setup complete!")

if __name__ == "__main__":
    asyncio.run(setup_rbac())
