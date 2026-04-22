---
name: authtuna
description: Instructions and guidelines for building high-security, distributed-ready IAM systems using the AuthTuna library. Use this skill whenever setting up authentication, RBAC, multi-tenancy, or GDPR-compliant data erasure.
license: LGPL-3.0
compatibility: Requires python >= 3.8 and authtuna installed.
metadata:
  version: "1.0"
  target: "authtuna"
---

# AuthTuna Skill

AuthTuna is a high-security, distributed-ready identity and access management (IAM) system for Python (FastAPI). It provides a "Batteries Included" suite of tools for authentication, authorization, and privacy compliance.

When building applications using `authtuna`, strictly follow the patterns and architectural guidelines outlined in this document.

## System Philosophy & Security

AuthTuna is built on a "Zero-Trust" and "Privacy-First" foundation:
1.  **Replay Protection**: Uses **Random String Rotation** in sessions. Every request generates a new token; using an old one immediately invalidates the entire session.
2.  **Granular Rate Limiting**: The `AuthTunaAsync` facade tracks failed attempts by both **User ID** and **IP Address** to mitigate brute-force and credential stuffing.
3.  **Envelope Encryption**: PII (emails) are stored using **Fernet-wrapped AES-256 keys**. Each user has a unique wrapper; destroying it (Crypto-Shredding) makes data permanently unrecoverable.
4.  **Scope Integrity**: Stricly prevents "Scope Escalation" by verifying that a manager's authority encompasses the target scope hierarchicaly.

## System Architecture

1.  **The Facade (`AuthTunaAsync`)**: All core logic is orchestrated by a central facade (usually named `auth_service`). It acts as the gateway to all subsystems.
2.  **Subsystem Managers**: Functionality is divided into specialized managers:
    *   `UserManager`: Core user account and profile operations.
    *   `RoleManager`: Hierarchical RBAC and role assignment logic.
    *   `OrganizationManager`: Multi-tenant tenant and team isolation.
    *   `MFAManager`: TOTP and recovery code security.
    *   `PasskeyManager`: WebAuthn/Passkey lifecycle.
    *   `APIKEYManager`: Scoped machine-to-machine authentication.
    *   `AuditManager`: Forensic trail querying (AuditEvent model).
3.  **Privacy Layer**: Implements envelope encryption and crypto-shredding at the data layer.

## Step-by-Step Instructions

### 1. Initial Setup and Configuration
Before any features can be used, AuthTuna must be initialized with its database and settings.
- Ensure `init_app(app)` is called in your main FastAPI entry point.
- Refer to [`CONFIGURATION.md`](references/CONFIGURATION.md) and [`DEFAULTS.md`](references/DEFAULTS.md) for required environment variables.

### 2. Implementing Authorization (RBAC)
AuthTuna supports two powerful authorization models that can be used simultaneously.
- **Hierarchical Levels**: Use numeric levels to prevent lower-privileged users from managing higher-privileged ones. Refer to [RBAC Hierarchy Pattern](references/patterns/RBAC_HIERARCHY.md).
- **Grant Relationships**: Use explicit delegation to let specific roles manage others independently of level. Refer to [Delegated Administration Pattern](references/patterns/DELEGATED_ADMIN.md).

### 3. Contextual Isolation (Scopes)
Protect resources within specific contexts (Organizations, Projects, Teams) using hierarchical scopes.
- Always use `/` as the delimiter (e.g., `company/department/team`).
- Permissions resolve upwards (Global -> Parent -> Child).
- Refer to [Scoped Permissions Pattern](references/patterns/SCOPED_PERMISSIONS.md).

### 4. Securing FastAPI Endpoints
Use the provided dependency factories to protect your routes.
- Use `Depends(get_current_user)` for basic authentication.
- Use `Depends(PermissionChecker(...))` for granular access control.
- Refer to [`MIDDLEWARE.md`](references/MIDDLEWARE.md).

### 5. Managing Multi-Tenancy
AuthTuna simplifies building SaaS platforms with its `OrganizationManager`.
- Flow: Create Org -> Create Teams -> Invite Members -> Assign Scoped Roles.
- Refer to [Organizations & Teams Pattern](references/patterns/ORGANIZATIONS_TEAMS.md) and [Invitation Workflow Pattern](references/patterns/INVITATION_WORKFLOW.md).

### 6. Modern Auth (SSO, MFA, Magic Links)
- **Social SSO**: Mount the pre-built router from `authtuna.routers.social`. Refer to [Social SSO Pattern](references/patterns/SOCIAL_SSO.md).
- **MFA**: Enforce TOTP and recovery codes for sensitive roles. Refer to [MFA Pattern](references/patterns/MFA_TOTP_RECOVERY.md).
- **Magic Links**: Use token-based login for frictionless onboarding. Refer to [Magic Links Pattern](references/patterns/PASSWORDLESS_MAGIC_LINKS.md).

### 7. Privacy and Compliance (GDPR)
Automatically handle GDPR requests using cryptographic erasure.
- Use `auth_service.users.erase_user(uid)` to trigger crypto-shredding.
- Refer to [GDPR & Crypto-Shredding Pattern](references/patterns/GDPR_PRIVACY.md).

## Technical Reference Library

| Document | Purpose |
|----------|---------|
| [**API Reference**](references/API_REFERENCE.md) | Exhaustive signatures for all core managers. |
| [**Implementation Patterns**](references/PATTERNS.md) | Detailed guides for SSO, MFA, Magic Links, and zero-trust. |
| [**Architecture & Models**](references/ARCHITECTURE.md) | Visualizations of the data model and auth flows. |
| [**FastAPI Integration**](references/MIDDLEWARE.md) | Deep dive into session hijacking and state management. |
| [**System Events**](references/EVENTS.md) | Lifecycle hooks inventory for system extensibility. |
| [**Routes Inventory**](references/ROUTES.md) | Catalog of all pre-built auth and admin UI routes. |

## Common Edge Cases & Best Practices

- **Always use the Facade**: Interact with `auth_service`, not individual manager classes, to ensure hooks are triggered correctly.
- **Check Permissions, not Roles**: Check for specific permissions (e.g., `user:edit`) rather than role names (e.g., `Admin`) to maintain system flexibility.
- **Leverage Hooks**: Use `auth_service.hooks.on(Events.USER_CREATED)` instead of modifying core logic for side-effects like sending emails.
- **IP Awareness**: Most manager methods require an `ip_address`. Always pass the client IP for accurate audit logging.
- **Feature Status**: 
    - **Fully Supported**: RBAC, Orgs, MFA, Social SSO, API Keys, GDPR Erasure.
    - **Supported But Disabled by default as additional configuration needed**: Passkeys (WebAuthn) - *Disabled by default in settings*.
    - **Not Supported**: RPC (Parts removed), Refresh Tokens (Planned/Placeholder).
