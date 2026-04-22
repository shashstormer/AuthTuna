# Pattern: Delegated Administration (Grant Relationships)

Delegate the power to manage specific roles without relying on a global numeric hierarchy.

## Concept
- **Grantor Role**: The role that has the power to assign another.
- **Grantable Role**: The role being assigned.
- **Independence**: This bypasses the `level` check, allowing lateral or even upward assignment if explicitly granted.

## Implementation

### 1. Granting Assignment Rights
Configure your system roles to allow delegation.

```python
# Allow 'HR_Manager' to assign the 'Employee' role
await auth_service.roles.grant_relationship(
    granter_role_name="HR_Manager",
    grantable_name="Employee",
    grantable_manager=auth_service.roles,
    relationship_attr="can_assign_roles"
)
```

### 2. Granting Permission Rights
Similarly, allow a role to grant specific permissions to other roles.

```python
# Allow 'Security_Lead' to grant 'network:access' to any role
await auth_service.roles.grant_relationship(
    granter_role_name="Security_Lead",
    grantable_name="network:access",
    grantable_manager=auth_service.permissions,
    relationship_attr="can_grant_permissions"
)
```

### 3. Usage
When a user with the `HR_Manager` role calls `assign_to_user`, the system checks:
1.  Is the level high enough? (Normal check)
2.  **OR** Does the user have a role that `can_assign_roles` for this specific role? (Delegation check)

```python
await auth_service.roles.assign_to_user(
    user_id="new_employee_id",
    role_name="Employee",
    assigner_id="hr_manager_id"
)
```

## Use Cases
- **Departmental Admins**: Let the Marketing Lead manage Marketing roles without giving them global Admin powers.
- **Temporary Access**: Grant a "Service Account" the ability to assign a specific "Worker" role.

## Best Practices
- **Explicit Grants**: Only use delegation for specific, well-defined relationships.
- **Audit**: Monitor who is granting what roles to ensure no circular or unintended power loops.
- **Limit Depth**: Don't create long chains of delegation (A can grant B, B can grant C, etc.) as it becomes hard to audit.
