# AuthTuna 🐟

AuthTuna is an async-first, high-performance authorization, session, and user management library for Python, with first-class FastAPI support.

> **Note:** While the core is designed to be framework-agnostic, the officially supported and actively maintained integration is FastAPI. Other adapters may be added in the future.

AuthTuna provides a robust, multi-layered security foundation for modern web applications. It is designed for developers who need to build complex, multi-tenant systems without compromising on security or performance. The library combines a powerful hierarchical permission model with an advanced, stateful session management system to actively defend against a wide range of modern threats.

## Core Concepts

- **Hierarchical RBAC (Role-Based Access Control):** Permissions are structured in a logical, multi-level hierarchy perfect for SaaS and collaborative platforms: Organization → Project → Team → Resource. A user's abilities can change depending on their context.
- **Object-Level Security:** Go beyond simple roles with fine-grained permissions based on a resource's specific attributes, such as ownership. This allows for intuitive rules like "a user can always edit their own posts."
- **Advanced Session Management:** A high-security, dual-state session model that actively detects and prevents session hijacking. It uses a server-side session store as the source of truth, providing full control over session validity.
- **Async SQLAlchemy:** All database operations are async, using SQLAlchemy 2.x with async drivers (PostgreSQL via asyncpg, SQLite via aiosqlite).
- **Framework-Agnostic Core:** The core engine is pure Python, with adapters for seamless integration with FastAPI.

## Features

- FastAPI-first integration: ready-to-use dependencies (get_current_user, PermissionChecker, RoleChecker) and session middleware.
- Async SQLAlchemy models and manager for Users, Roles, Permissions, Sessions, Tokens, MFA, Social Accounts.
- Dual-state session model: server-side sessions + JWT cookie with rotating random_string and periodic DB verification.
- Session hijack detection: region/device fingerprint checks, IP tracking, automatic invalidation.
- Email flows: verification, password reset, MFA notifications (Jinja templates included).
- Extensible RBAC with scoped permissions (e.g., "project:read" with scope_from_path).
- SQL-first design with PostgreSQL and SQLite support only.

## Installation

Install from PyPI:

```bash
pip install authtuna
```

## Configuration

Key environment variables in `authtuna.core.config.Settings` (can also be overridden via .env):
- `DEFAULT_DATABASE_URI`: Async database URL (e.g., postgresql+asyncpg://user:pass@host/db or sqlite+aiosqlite:///./authtuna.db)
- `SESSION_TOKEN_NAME`: Cookie name for session (default: session_token)
- `SESSION_LIFETIME_SECONDS` / `SESSION_ABSOLUTE_LIFETIME_SECONDS`
- `SESSION_DB_VERIFICATION_INTERVAL`: Seconds between DB checks for session validity
- `EMAIL_ENABLED` / SMTP settings for email flows

See `authtuna/core/config.py` for full list and defaults.

## Quick Start

FastAPI setup with session middleware and simple permission/role checks:

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

## Philosophy

Robust security should be accessible, not an afterthought. AuthTuna provides the tools to manage complex authorization logic in a way that is both intuitive and highly secure.

---

For more details, see the code and inline documentation.
