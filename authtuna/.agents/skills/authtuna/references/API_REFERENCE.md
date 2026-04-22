# AuthTuna API Reference

This document provides a detailed reference for the core classes and methods in the AuthTuna library.

## Core Facade: `AuthTunaAsync` (via `auth_service`)

The main entry point for all operations.

| Manager | Property | Description |
|---------|----------|-------------|
| `UserManager` | `.users` | User CRUD and account management. |
| `RoleManager` | `.roles` | Role definitions and assignments. |
| `PermissionManager` | `.permissions` | Fine-grained permission management. |
| `SessionManager` | `.sessions` | Active session tracking and termination. |
| `TokenManager` | `.tokens` | Lifecycle for magic links and invite tokens. |
| `MFAManager` | `.mfa` | Multi-factor authentication logic. |
| `PasskeyManager` | `.passkeys` | WebAuthn/Passkey operations. |
| `APIKEYManager` | `.api` | API key generation and validation. |
| `OrganizationManager` | `.orgs` | Multi-tenant organization and team management. |
| `AuditManager` | `.audit` | Security trail querying. |

---

## UserManager (`auth_service.users`)

- **`get_by_id(user_id, with_relations=True)`**: Retrieves a user by ID.
- **`get_by_email(email)`**: Retrieves a user by email (handles encryption hash).
- **`get_by_username(username)`**: Retrieves a user by username.
- **`list(skip=0, limit=100)`**: Lists users.
- **`create(email, username, password=None, ip_address='system', **kwargs)`**: Registers a new user.
- **`update(user_id, update_data, ip_address='system')`**: Updates user fields.
- **`delete(user_id, ip_address='system')`**: Archives a user (soft delete).
- **`erase_user(user_id, ip_address='system')`**: **GDPR Crypto-Shredding**. Irreversibly destroys the user's encryption key.
- **`suspend_user(user_id, admin_id, reason)`**: Sets `is_active=False`.
- **`unsuspend_user(user_id, admin_id, reason)`**: Sets `is_active=True`.
- **`search_users(identity=None, role=None, scope=None, is_active=None, skip=0, limit=100)`**: Advanced lookup.

---

## RoleManager (`auth_service.roles`)

- **`create(name, description, system=False, level=None)`**: Creates a new role.
- **`assign_to_user(user_id, role_name, assigner_id, scope='global')`**: Assigns a role in a context.
- **`remove_from_user(user_id, role_name, remover_id, scope='global')`**: Revokes a role assignment.
- **`grant_relationship(granter_role_name, grantable_name, grantable_manager, relationship_attr)`**:
    - `relationship_attr`: `can_assign_roles` or `can_grant_permissions`.
- **`has_permission(user_id, permission_name, scope_prefix=None)`**: Checks permissions (hierarchical `/` support).
- **`delete_role(role_name, deleter_id)`**: Deletes a role definition.

---

## SessionManager (`auth_service.sessions`)

- **`get_by_id(session_id)`**: Retrieves active session.
- **`create(user_id, ip_address, region, device)`**: Creates a new DB session.
- **`terminate(session_id, ip_address)`**: Invalidates a specific session.
- **`terminate_all_for_user(user_id, ip_address, except_session_id=None)`**: Global logout/security reset.

---

## TokenManager (`auth_service.tokens`)

- **`create(user_id, purpose, expiry_seconds=3600)`**: Generates a one-time token.
- **`verify(token_id, purpose)`**: Validates and marks token as used.
- **`revoke(token_id)`**: Manually invalidates a token.

---

## OrganizationManager (`auth_service.orgs`)

- **`create_organization(name, owner, ip_address)`**: Creates org and sets owner.
- **`get_org_members(org_id)`**: Returns members with join timestamps.
- **`get_user_orgs(user_id)`**: Lists orgs the user belongs to.
- **`invite_to_organization(org_id, invitee_email, role_name, inviter, ip_address)`**: Sends invite token.
- **`accept_organization_invite(token_id, ip_address)`**: Joins user to org.
- **`create_team(name, org_id, creator, ip_address)`**: Creates a team.
- **`get_org_teams(org_id)`**: Lists teams in an organization.
- **`get_user_teams(user_id, org_id=None)`**: Lists teams the user belongs to.

---

## APIKEYManager (`auth_service.api`)

- **`create_key(user_id, name, key_type='SECRET', scopes=None, valid_seconds=31536000)`**: Generates key.
    - `key_type`: `SECRET`, `MASTER`, `PUBLIC`, `TEST`.
- **`validate_key(token)`**: Returns `ApiKey` if secret and hash match.
- **`delete_key(key_id)`**: Revokes an API key.

---

## AuditManager (`auth_service.audit`)

- **`get_events_for_user(user_id, skip=0, limit=25)`**: User security trail.
- **`get_events_by_type(event_type, skip=0, limit=100)`**: Global event filtering.
