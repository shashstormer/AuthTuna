# AuthTuna Implementation Patterns

This document serves as an index for detailed architectural and security patterns using AuthTuna. Each pattern includes a conceptual overview, step-by-step implementation, and best practices.

## Core Authorization
- [**Hierarchical RBAC**](patterns/RBAC_HIERARCHY.md): Using numeric levels to prevent privilege escalation.
- [**Context-Aware (Scoped) Permissions**](patterns/SCOPED_PERMISSIONS.md): Fine-grained access using hierarchical `/` paths.
- [**Delegated Administration**](patterns/DELEGATED_ADMIN.md): Explicitly granting role assignment rights between roles.

## Multi-Tenancy & Teams
- [**Organizations & Teams**](patterns/ORGANIZATIONS_TEAMS.md): Structuring multi-tenant applications and memberships.
- [**Invitation Workflow**](patterns/INVITATION_WORKFLOW.md): Securely onboarding members via email tokens.

## Modern Authentication
- [**Social SSO**](patterns/SOCIAL_SSO.md): Integrating Google and Github with auto-registration.
- [**Passwordless Magic Links**](patterns/PASSWORDLESS_MAGIC_LINKS.md): Token-based login via email.
- [**MFA (TOTP) & Recovery**](patterns/MFA_TOTP_RECOVERY.md): Second-factor security and emergency backup codes.
- [**Zero-Trust API Keys**](patterns/API_KEY_SECURITY.md): Secure, scoped machine-to-machine authentication.

## Privacy & Extensibility
- [**GDPR & Crypto-Shredding**](patterns/GDPR_PRIVACY.md): Cryptographically erasing user data to comply with "Right to be Forgotten".
- [**Event-Driven Hooks**](patterns/HOOKS_EXTENSIBILITY.md): Extending system behavior using asynchronous lifecycle hooks.

---

### Pattern Selection Guide

| If you want to... | Use this pattern |
|-------------------|------------------|
| Prevent an admin from creating other admins | [Hierarchical RBAC](patterns/RBAC_HIERARCHY.md) |
| Limit access to a specific project or folder | [Scoped Permissions](patterns/SCOPED_PERMISSIONS.md) |
| Let a team lead manage their own team only | [Delegated Administration](patterns/DELEGATED_ADMIN.md) |
| Remove all traces of a user instantly | [GDPR Crypto-Shredding](patterns/GDPR_PRIVACY.md) |
| Send a Slack notification on signup | [Event-Driven Hooks](patterns/HOOKS_EXTENSIBILITY.md) |
