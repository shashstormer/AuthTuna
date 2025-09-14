# AuthTuna 🐟

AuthTuna is an async-first, high-performance authorization, session, and user management library for Python, with first-class FastAPI support.

> **Note:** While the core is framework-agnostic, FastAPI is the officially supported and actively maintained integration. Other adapters may be added in the future.

AuthTuna provides a robust, multi-layered security foundation for modern web applications. It is designed for developers who need to build complex, multi-tenant systems without compromising on security or performance. The library combines a powerful hierarchical permission model with advanced, stateful session management to actively defend against a wide range of modern threats.

---

## 🚦 Core Concepts

- **Hierarchical RBAC:** Multi-level, context-aware permissions (Organization → Project → Team → Resource).
- **Object-Level Security:** Fine-grained, resource-based permissions (e.g., "users can edit their own posts").
- **Advanced Session Management:** Dual-state, server-side sessions with hijack detection and full control.
- **Async SQLAlchemy:** All DB operations are async (PostgreSQL/asyncpg, SQLite/aiosqlite).
- **Framework-Agnostic Core:** Pure Python engine, with adapters for FastAPI.

---

## ✨ Features

- **FastAPI-first integration:** Ready-to-use dependencies (`get_current_user`, `PermissionChecker`, `RoleChecker`) and session middleware.
- **Async SQLAlchemy models:** Users, Roles, Permissions, Sessions, Tokens, MFA, Social Accounts.
- **Dual-state session model:** Server-side sessions + JWT cookie with rotating random_string and periodic DB verification.
- **Session hijack detection:** Region/device fingerprint checks, IP tracking, automatic invalidation.
- **Email flows:** Verification, password reset, MFA notifications (Jinja templates included).
- **Extensible RBAC:** Scoped permissions (e.g., `project:read` with `scope_from_path`).
- **SQL-first design:** PostgreSQL and SQLite support only.

---

## 📦 Installation

```bash
pip install authtuna
```

---

## ⚙️ Configuration

AuthTuna is configured through environment variables. You can set these in your environment or in a `.env` file. Key variables include:

- `DEFAULT_DATABASE_URI`: Async DB URL (e.g., `postgresql+asyncpg://user:pass@host/db` or `sqlite+aiosqlite:///./authtuna.db`)
- `SESSION_TOKEN_NAME`: Cookie name for session (default: `session_token`)
- `SESSION_LIFETIME_SECONDS` / `SESSION_ABSOLUTE_LIFETIME_SECONDS`: Session lifetimes
- `SESSION_DB_VERIFICATION_INTERVAL`: Seconds between DB checks for session validity
- `EMAIL_ENABLED` / SMTP settings for email flows

For a full list of options and defaults, see [`authtuna/core/config.py`](authtuna/core/config.py).

---

## 🚀 Quick Start

Here's how to set up AuthTuna with FastAPI:

```python
from fastapi import FastAPI, Depends
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.integrations.fastapi_integration import get_current_user, PermissionChecker, RoleChecker
from authtuna.core.database import User

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/me")
async def whoami(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email}

@app.get("/projects/{project_id}")
async def read_project(
    project_id: str,
    user: User = Depends(PermissionChecker("project:read", scope_from_path="project_id"))
):
    return {"project_id": project_id, "user": user.id}

@app.get("/admin")
async def admin_area(user: User = Depends(RoleChecker("admin", "moderator"))):
    return {"message": f"Welcome, {user.username}"}
```

---

## 🛠️ Built-in Routers & Templates

AuthTuna ships with optional routers for authentication, social login, and administration, as well as a set of Jinja templates to get started quickly.

```python
from fastapi import FastAPI
from authtuna.routers import auth as auth_router, social as social_router, admin as admin_router
from authtuna.middlewares.session import DatabaseSessionMiddleware

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(social_router.router, prefix="/auth", tags=["social"])
app.include_router(admin_router.router, prefix="/admin", tags=["admin"])
```

---

## 💡 Philosophy

Robust security should be accessible, not an afterthought. AuthTuna provides the tools to manage complex authorization logic in a way that is both intuitive and highly secure.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 🛡️ Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for our security policy and how to report it.
