# AuthTuna 🐟

AuthTuna is currently focused on FastAPI. While parts of the core remain framework-agnostic and the design allows future adapters, the officially supported and actively maintained integration is FastAPI.

A high-performance authorization, session, and user management library for Python with first-class FastAPI support.

AuthTuna provides a robust, multi-layered security foundation for modern web applications. It is designed for developers who need to build complex, multi-tenant systems without compromising on security or performance. The library combines a powerful hierarchical permission model with an advanced, stateful session management system to actively defend against a wide range of modern threats.

This project is built on the philosophy that robust security should be accessible, not an afterthought. It provides the tools to manage complex authorization logic in a way that is both intuitive and highly secure.

## Core Concepts

AuthTuna is built on a few key architectural principles:

- **Hierarchical RBAC (Role-Based Access Control)**: Permissions are not global. They are structured in a logical, multi-level hierarchy perfect for SaaS and collaborative platforms: Organization ➡️ Project ➡️ Team ➡️ Resource. A user's abilities can change depending on their context.

- **Object-Level Security**: Go beyond simple roles with fine-grained permissions based on a resource's specific attributes, such as ownership. This allows for intuitive rules like "a user can always edit their own posts."

- **Advanced Session Management**: A high-security, dual-state session model that actively detects and prevents session hijacking. It uses a server-side session store as the source of truth, providing full control over session validity.

- **Framework-Agnostic Design**: A clean core engine written in pure Python, with dedicated adapters for seamless integration with modern web frameworks like FastAPI.

## Features

- FastAPI-first integration: ready-to-use dependencies (get_current_user, PermissionChecker, RoleChecker) and session middleware.
- Async SQLAlchemy models and manager for Users, Roles, Permissions, Sessions, Tokens, MFA, Social Accounts.
- Dual-state session model: server-side sessions + JWT cookie with rotating random_string and periodic DB verification.
- Session hijack detection: region/device fingerprint checks, IP tracking, automatic invalidation.
- Email flows: verification, password reset, MFA notifications (Jinja templates included).
- Extensible RBAC with scoped permissions (e.g., "project:read" with scope_from_path).
- SQL-first design with PostgreSQL and SQLite support.

## Installation

Install from PyPI.

```bash
pip install authtuna
```

## Configuration

Key environment variables in authtuna.core.config.Settings (can also be overridden via .env):
- DATABASE_URL: Async database URL (e.g., postgresql+asyncpg://user:pass@host/db or sqlite+aiosqlite:///./authtuna.db)
- SESSION_TOKEN_NAME: Cookie name for session (default: authtuna_session)
- SESSION_LIFETIME_SECONDS / SESSION_ABSOLUTE_LIFETIME_SECONDS
- SESSION_DB_VERIFICATION_INTERVAL: Seconds between DB checks for session validity
- EMAIL_ENABLED / SMTP settings for email flows

See authtuna/core/config.py for full list and defaults.

## Quick Start

FastAPI setup with session middleware and simple permission/role checks.

```python
from fastapi import FastAPI, Depends
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.integrations.fastapi_integration import get_current_user, PermissionChecker, RoleChecker
from authtuna.core.database import User

app = FastAPI()

# Attach the session middleware
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/me")
async def whoami(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email}

# Require a specific permission (AND by default)
@app.get("/projects/{project_id}")
async def read_project(
    project_id: str,
    user: User = Depends(PermissionChecker("project:read", scope_from_path="project_id"))
):
    return {"project_id": project_id, "user": user.id}

# Require one of multiple roles
@app.get("/admin")
async def admin_area(user: User = Depends(RoleChecker("admin", "moderator"))):
    return {"message": f"Welcome, {user.username}"}
```

## Built-in Routers and Templates

AuthTuna ships optional routers for auth and social login and a set of Jinja templates you can mount quickly.

```python
from fastapi import FastAPI
from authtuna.routers import auth as auth_router, social as social_router
from authtuna.middlewares.session import DatabaseSessionMiddleware

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(social_router.router, prefix="/auth", tags=["social"])
```

Email templates are in authtuna/templates/email and page templates in authtuna/templates/pages. You can override them in your app by providing your own templates.

## Architectural Diagram

This diagram shows the complete data structure for the authorization and session management system, designed for optimal performance and clarity.

```mermaid
erDiagram
    Users { 
        int user_id PK
        string name
    }
    Organizations { 
        int org_id PK
        string name
    }
    Projects { 
        int project_id PK
        int org_id FK
    }
    Teams { 
        int team_id PK
        int project_id FK
    }
    Resources { 
        int resource_id PK
        string name
        int team_id FK
        int owner_id FK
    }
    Roles { 
        int role_id PK
        string name
        enum scope
    }
    Permissions { 
        int permission_id PK
        string codename
    }
    Tools { 
        int tool_id PK
        string name
    }
    UserSession { 
        string session_id PK
        int user_id FK
        string rotating_token
        string ip_address
        string user_agent
    }

    Tools ||--|{ Permissions : "defines"
    Roles }o--o{ RolePermissions : "grants"
    Permissions }o--o{ RolePermissions : "is granted by"
    
    Users ||--o{ OrganizationMemberships : "member of"
    Organizations ||--o{ OrganizationMemberships : "has member"
    Roles ||--o{ OrganizationMemberships : "with role"
    
    Users ||--o{ ProjectMemberships : "member of"
    Projects ||--o{ ProjectMemberships : "has member"
    Roles ||--o{ ProjectMemberships : "with role"
    
    Users ||--o{ TeamMemberships : "is member of"
    Teams ||--o{ TeamMemberships : "has member"
    Roles ||--o{ TeamMemberships : "with role"

    Organizations ||--|{ Projects : "contains"
    Projects ||--|{ Teams : "contains"
    Teams ||--|{ Resources : "contains"
    Users ||--|{ Resources : "owns"
    Users ||--o{ UserSession : "has"
```

## Security Overview 🛡️

AuthTuna is designed with a defense-in-depth strategy. Security is not a single feature but a result of the entire architecture working together.

| Attack Vector | Defense Strategy & Implementation |
|---------------|-----------------------------------|
| **Session Hijacking** | IP/User-Agent fingerprinting is performed on every request, comparing against the secure server-side record. The rotating token provides immediate, real-time breach detection if a stolen cookie is used. |
| **Replay Attacks** | The core session model is built on one-time-use rotating tokens. An intercepted request is useless because the token becomes invalid after its first use. |
| **CSRF** | The primary defense is the SameSite=Lax cookie attribute, which prevents browsers from sending the session cookie on unauthorized cross-site POST, PUT, etc., requests. |
| **XSS** | The core session_id is stored in an HttpOnly cookie, preventing direct access from JavaScript. This is combined with a strong Content Security Policy (CSP) and proper output encoding in the application. |
| **Timing Attacks** | All comparisons of secret values (like the rotating_token) are performed using a constant-time comparison function (e.g., Python's hmac.compare_digest). |
| **Credential Stuffing** | While outside the library's direct scope, we strongly recommend rate limiting, CAPTCHA, and Multi-Factor Authentication (MFA) on the application's login form. |
| **Insecure Direct Object Ref.** | The core authorizer.can(user, permission, resource) check is the fundamental defense against IDOR, ensuring a user is authorized for the specific resource they are requesting. |
| **Session Fixation** | A new, cryptographically secure session_id is generated in the database after every successful login, ensuring a user cannot be forced into a pre-existing session. |

## Project Status

This library is under active development with FastAPI as the primary target. APIs may change; pin a version in production and review changelogs before upgrading.

## Contributing

We welcome contributions of all kinds! Whether it's reporting a bug, proposing a new feature, or submitting a pull request, your help is valued. Please feel free to open an issue to start a discussion.

## License

This project is licensed under the MIT License. See the LICENSE file for details.