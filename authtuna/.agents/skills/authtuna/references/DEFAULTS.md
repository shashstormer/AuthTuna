# Default System Configuration

AuthTuna comes with a pre-provisioned set of roles and permissions to enable immediate administrative control.

## Default Roles

| Role | Level | Description |
|------|-------|-------------|
| `SuperAdmin` | `100` | Full system control. |
| `Admin` | `90` | Most administrative tasks. |
| `Moderator` | `50` | User management and moderation. |
| `OrgOwner` | `None` | Full control over an organization. |
| `OrgAdmin` | `None` | Manage org members and teams. |
| `TeamLead` | `None` | Manage a specific team. |
| `User` | `0` | Standard basic access. |
| `System` | `999` | Internal automated processes. |

## Default Permissions (Partial List)

- `admin:access:panel`: Access the admin UI.
- `admin:manage:users`: CRUD operations on users.
- `admin:manage:roles`: Create and grant roles.
- `org:create`: Create organizations.
- `org:manage`: Edit/Delete organizations.
- `team:manage`: Edit/Delete teams.

## Default Users

If configured in settings, the following users are created on first start:
- `superadmin`: Assigned `SuperAdmin` and `User` roles.
- `admin`: Assigned `Admin` and `User` roles.
- `system`: Internal process user.
