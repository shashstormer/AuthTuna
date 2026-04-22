# Pattern: Context-Aware (Scoped) Permissions

Scoped permissions allow a single role (e.g., "Editor") to grant different access levels depending on the resource context (e.g., "Project A" vs "Project B").

## Concept
- **Scope Path**: A string using `/` as a delimiter (e.g., `company/marketing/social`).
- **Hierarchical Resolution**: Permissions granted at a parent scope (e.g., `company`) automatically apply to all child scopes (e.g., `company/marketing`).
- **Global Scope**: The special scope `global` applies to the entire system.

## Implementation

### 1. Assigning a Scoped Role
Assign the role with a specific scope string.

```python
# User is an 'Editor' only for 'Project-X'
await auth_service.roles.assign_to_user(
    user_id="user123",
    role_name="Editor",
    scope="project/x"
)
```

### 2. Protecting FastAPI Routes
Use `PermissionChecker` with `scope_from_path` to dynamically resolve the scope from the URL.

```python
from authtuna.integrations.fastapi_integration import PermissionChecker

@app.get("/projects/{project_id}/edit")
async def edit_project(
    project_id: str,
    user = Depends(PermissionChecker("project:edit", scope_from_path="project_id"))
):
    # If project_id="x", the checker validates permission in scope "project:x"
    # Note: Automatic path-based resolution uses ':' as the default separator.
    return {"status": "success"}
```

### 3. Manual Permission Checking
You can manually check permissions in a specific scope using `has_permission`.

```python
has_access = await auth_service.roles.has_permission(
    user_id="user123",
    permission_name="project:view",
    scope_prefix="project/x/sub-task"
)
# Returns True if user has 'project:view' in:
# - 'project/x/sub-task'
# - 'project/x'
# - 'project'
# - 'global'
```

## Advanced: Scope Prefixing
In `PermissionChecker`, use `scope_prefix` to add a static prefix to the path-derived scope.

```python
# If path is /orgs/123/settings
# Resulting scope: "org/123"
checker = PermissionChecker("org:manage", scope_from_path="org_id", scope_prefix="org")
```

## Best Practices
- **Consistent Delimiters**: Always use `/` for nested paths.
- **Normalize IDs**: Ensure IDs used in scopes are URL-safe and consistent.
- **Avoid Depth**: Keep scope depth reasonable (usually 2-4 levels) for performance and readability.
