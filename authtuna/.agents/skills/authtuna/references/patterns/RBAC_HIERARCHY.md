# Pattern: Hierarchical RBAC

Hierarchical RBAC (Role-Based Access Control) allows you to define roles with numeric levels to prevent privilege escalation and simplify permission management.

## Concept
- **Levels**: Each role has an optional `level`.
- **Escalation Prevention**: A user cannot assign or revoke a role that has a level higher than or equal to their own highest role level.
- **Inheritance**: (Implicit) In management logic, a higher level role is often assumed to have the capabilities of lower level roles.

## Implementation

### 1. Define Roles with Levels
Create your role hierarchy during system initialization.

```python
# SuperAdmin (Level 100) > Admin (Level 90) > Moderator (Level 50) > User (Level 0)
await auth_service.roles.create("SuperAdmin", level=100, description="Full control")
await auth_service.roles.create("Admin", level=90, description="Most admin tasks")
await auth_service.roles.create("Moderator", level=50, description="User management")
await auth_service.roles.create("User", level=0, description="Standard access")
```

### 2. Assignment with Authorization
When assigning roles, provide the `assigner_id`. AuthTuna will automatically validate that the assigner has a higher level than the role being assigned.

```python
try:
    await auth_service.roles.assign_to_user(
        user_id="target_user_id",
        role_name="Admin",
        assigner_id="current_admin_id", # Level checked here
        scope="global"
    )
except OperationForbiddenError:
    print("Assigner level too low to grant 'Admin' role.")
```

### 3. Revocation
Similarly, revoking a role requires the revoker to have a higher level than the role being revoked.

```python
await auth_service.roles.revoke_user_role_by_scope(
    user_id="target_user_id",
    role_name="Moderator",
    scope="global",
    revoker_id="current_admin_id"
)
```

## Best Practices
- **System Roles**: Use `system=True` for roles that should never be deleted.
- **Gap Levels**: Leave gaps between levels (e.g., 10, 20, 30) to allow for future intermediate roles.
- **Permission Mapping**: Level-based checks are for *management* (assigning/revoking). Use `PermissionChecker` for *access* to features.
