[![PyPI version](https://img.shields.io/pypi/v/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![Python Versions](https://img.shields.io/pypi/pyversions/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![License](https://img.shields.io/github/license/shashstormer/authtuna?style=flat-square)](LICENSE.txt)
[![CI](https://github.com/shashstormer/authtuna/actions/workflows/ci.yml/badge.svg)](https://github.com/shashstormer/authtuna/actions)
[![codecov](https://codecov.io/github/shashstormer/AuthTuna/graph/badge.svg?token=8AV8FB3ZGQ)](https://codecov.io/github/shashstormer/AuthTuna)
[![Downloads](https://static.pepy.tech/badge/authtuna)](https://pepy.tech/project/authtuna)

# AuthTuna 🐟

**The Modern Async Security Framework for FastAPI**

AuthTuna is a battle-tested, async-first security framework for Python that provides a complete, production-ready foundation for authentication, authorization, and session management. Stop reinventing the wheel and start shipping secure applications faster.

Designed for developers who need to build complex, multi-tenant systems with zero compromise on security or performance, AuthTuna combines a powerful hierarchical permission model with advanced, stateful session management to actively defend against a wide range of modern threats.

---

## Why AuthTuna?

🛡️ **Production-Grade Security, Out of the Box:** From hijack detection to granular, object-level permissions, get the features of an enterprise-grade auth system without the complexity.

🚀 **Blazing-Fast & Async-First:** Built on asyncio and SQLAlchemy 2.0, AuthTuna is designed for high-concurrency environments and won't block your event loop.

🧩 **Batteries-Included, But Pluggable:** Use our pre-built routers and templates to get started in minutes, or integrate the core engine into your existing architecture.

👨‍💻 **Unbeatable Developer Experience:** With first-class FastAPI support, ready-to-use dependencies, and clear, Pydantic-based models, securing your API has never been easier.

---

## Features & Philosophy

Robust security should be accessible, not an afterthought. AuthTuna provides the tools to manage complex authorization logic in a way that is both intuitive and highly secure.

- ⚔️ **Granular, Hierarchical RBAC:** Go beyond simple roles. Implement multi-level, context-aware permissions (e.g., Organization → Project → Resource) and resource-based rules (e.g., "users can only edit their own posts").
- 🔒 **Advanced Session Management:** Our unique dual-state, server-side session model provides the security of server-side validation with the performance of JWTs. Features full programmatic control, hijack detection, and automatic invalidation.
- ⚡ **High-Performance Async Core:** All database operations are fully asynchronous using the latest SQLAlchemy features with asyncpg for PostgreSQL and aiosqlite for SQLite.
- 📧 **Built-in Email Flows:** Ready-to-use and customizable flows for email verification, password resets, and MFA notifications with included Jinja templates.
- 🌐 **Social & Passwordless Login:** Optional, pre-built routers for common social providers (Google, GitHub, etc.) and passwordless authentication.

---

## 📦 Installation

```bash
pip install authtuna
```

---

## ⚙️ Configuration

AuthTuna is configured through environment variables, making it perfect for containerized deployments. Key variables include:

- `DEFAULT_DATABASE_URI`: Your async database URL (e.g., `postgresql+asyncpg://user:pass@host/db`)
- `SESSION_TOKEN_NAME`: The cookie name for your session (default: `session_token`)
- `SESSION_LIFETIME_SECONDS`: The duration of an active session.
- `EMAIL_ENABLED` / SMTP settings for email flows.

For a full list of options, see the documentation or [`authtuna/core/config.py`](authtuna/core/config.py).

---

## 🚀 Quick Start

Secure your FastAPI application in under 20 lines of code.

```python
from fastapi import FastAPI, Depends
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.integrations.fastapi_integration import get_current_user, PermissionChecker, RoleChecker
from authtuna.core.database import User

# Initialize the FastAPI app and add the session middleware
app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

# A simple protected route that requires a valid session
@app.get("/me")
async def whoami(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email}

# Protect a route with a specific, scoped permission
@app.get("/projects/{project_id}")
async def read_project(
    project_id: str,
    user: User = Depends(PermissionChecker("project:read", scope_from_path="project_id"))
):
    return {"project_id": project_id, "user": user.id}

# Protect a route with a simple role check
@app.get("/admin")
async def admin_area(user: User = Depends(RoleChecker("admin", "moderator"))):
    return {"message": f"Welcome, {user.username}"}
```

---

## 🛠️ Batteries-Included: Pre-built Routers

AuthTuna ships with optional, pre-built routers for common authentication, social login, and administration tasks to get you started even faster.

```python
from fastapi import FastAPI
from authtuna.routers import auth as auth_router, social as social_router, admin as admin_router
from authtuna.middlewares.session import DatabaseSessionMiddleware

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

# Mount the pre-built routers
app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"])
app.include_router(social_router.router, prefix="/auth", tags=["Social Login"])
app.include_router(admin_router.router, prefix="/admin", tags=["Administration"])
```

---

## 🤝 Community & Support

- 🤝 **Contributing:** Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.
- 🛡️ **Security:** If you discover a security vulnerability, please see our [security policy](SECURITY.md) for how to report it.

---

## 🐟 AuthTuna: Secure, Fast, and Actually Fun to Use

AuthTuna is built by developers who care about security, performance, and developer happiness. We believe you shouldn't have to choose between robust security and a great developer experience. Try AuthTuna and see how easy secure can be.

*No hype, no snake oil—just a modern, async security framework that works. (And yes, we eat our own dogfood!)*
