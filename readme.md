[![PyPI version](https://img.shields.io/pypi/v/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![Python Versions](https://img.shields.io/pypi/pyversions/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![License](https://img.shields.io/github/license/shashstormer/authtuna?style=flat-square)](LICENSE.txt)
[![CI](https://github.com/shashstormer/authtuna/actions/workflows/ci.yml/badge.svg)](https://github.com/shashstormer/authtuna/actions)
[![codecov](https://codecov.io/github/shashstormer/AuthTuna/graph/badge.svg?token=8AV8FB3ZGQ)](https://codecov.io/github/shashstormer/AuthTuna)
[![Downloads](https://static.pepy.tech/badge/authtuna)](https://pepy.tech/project/authtuna)


# AuthTuna 🐟

A modern async security framework for Python (FastAPI-first, framework-agnostic core).  
Battle-tested, batteries-included authentication, session management, RBAC, SSO, MFA, and much more.

---

## Table of Contents

1. [Getting Started (Basic Auth & Login)](#getting-started-basic-auth--login)
2. [Configuring AuthTuna (Environment, Secrets Manager, etc.)](#configuring-authtuna-environment-secrets-manager-etc)
   - [Required Config Keys (`FERNET_KEYS`, `API_BASE_URL`)](#required-config-keys-fernet_keys-api_base_url)
   - [All Config Options](#all-config-options)
   - [Using .env or Environment Variables](#using-env-or-environment-variables)
   - [Using a Secrets Manager or Custom `init_settings`](#using-a-secrets-manager-or-custom-init_settings)
3. [SSO (Social Login)](#sso-social-login)
4. [MFA (Multi-Factor Authentication)](#mfa-multi-factor-authentication)
5. [Permission Checker](#permission-checker)
6. [Role Checker](#role-checker)
7. [Sample Backend Code](#sample-backend-code)
8. [Advanced Guide & Patterns](#advanced-guide--patterns)
9. [Proof of Endless Possibility](#proof-of-endless-possibility)

---

## Getting Started (Basic Auth & Login)

**1. Install dependencies:**
```bash
pip install authtuna fastapi uvicorn[standard] asyncpg aiosqlite python-dotenv
```

**2. Create a `.env` file with minimum configs:**
```
API_BASE_URL=http://localhost:8000
FERNET_KEYS=["YOUR_GENERATED_FERNET_KEY","OPTIONAL_OLDER_KEYS_FOR_COMPATIBILITY_DURING_ROTATION"]
DEFAULT_DATABASE_URI=sqlite+aiosqlite:///./authtuna.db
SECRET_KEY=your-very-secret-key
```
*(See below for how to generate FERNET_KEYS)*

**3. Minimal FastAPI app:**
```python
from fastapi import FastAPI, Depends
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.integrations.fastapi_integration import get_current_user

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/me")
async def me(user=Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email}
```

**4. Run it:**
```bash
uvicorn main:app --reload
```
---

## Configuring AuthTuna (Environment, Secrets Manager, etc.)

### Required Config Keys (`FERNET_KEYS`, `API_BASE_URL`)

- **`FERNET_KEYS`**: Comma-separated base64-encoded keys for encrypting sensitive data (sessions, cookies, etc).
  - To generate:  
    ```python
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
    ```
  - Or you can also
    ```bash
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ```
     *(Repeat to rotate keys, separate by commas. Oldest last in list.)*


- **`API_BASE_URL`**: The base URL of your API. Used for generating links in emails and security validation.

### All Config Options

| Variable                      | Description                                                | Required | Example                                |
|-------------------------------|------------------------------------------------------------|----------|----------------------------------------|
| API_BASE_URL                  | Your app's public base URL                                 | Yes      | http://localhost:8000                  |
| FERNET_KEYS                   | Comma-separated list of Fernet keys (base64)               | Yes      | `key1,key2,...`                        |
| DEFAULT_DATABASE_URI          | SQLAlchemy DB URI (async supported)                        | Yes      | `sqlite+aiosqlite:///./authtuna.db`    |
| SECRET_KEY                    | Secret for signing tokens                                  | Yes      | `your-super-secret-key`                |
| JWT_SECRET_KEY                | JWT encryption secret                                      |          | (defaults, override for prod)          |
| ENCRYPTION_PRIMARY_KEY        | Encryption key for sensitive fields                        |          | (defaults, override for prod)          |
| ENCRYPTION_SECONDARY_KEYS     | For key rotation                                           |          |                                        |
| APP_NAME                      | Application name                                           | No       | AuthTuna                               |
| DATABASE_USE_ASYNC_ENGINE     | Use async SQLAlchemy drivers                               | No       | True                                   |
| SESSION_LIFETIME_SECONDS      | Session duration (seconds)                                 | No       | 604800                                 |
| SESSION_TOKEN_NAME            | Cookie name for session                                    | No       | session_token                          |
| EMAIL_ENABLED                 | Enable/disable email features                              | No       | False                                  |
| SMTP_HOST, SMTP_PORT, ...     | SMTP config for sending emails                             | If email | smtp.example.com, 587, ...             |
| EMAIL_DOMAINS                 | Allowed email domains (list)                               | No       | gmail.com,example.com                  |
| ...                           | See source for full list and default values                |          |                                        |

**See [core/config.py](authtuna/core/config.py) for ALL options.**

### Using `.env` or Environment Variables

- Place your config in a `.env` file (see above).
- Or export them in your shell:  
  `export API_BASE_URL="https://api.mysite.com"`, etc.
- If you want to use a custom file:  
  `ENV_FILE_NAME=".myenv"`

### Using a Secrets Manager or Custom `init_settings`

- For ultimate flexibility (Docker, cloud, Vault, AWS, etc), call `init_settings()` at app startup:

```python
from authtuna.core.config import init_settings

def fetch_secrets():
    # Example: fetch from AWS, Vault, or any source
    import os
    return {
        "API_BASE_URL": os.environ.get("API_BASE_URL"),
        "FERNET_KEYS": os.environ.get("FERNET_KEYS"),
        # ...add your secrets here...
    }

init_settings(**fetch_secrets())
```
- If you set `AUTHTUNA_NO_ENV=true`, AuthTuna will **not** auto-load from env and will require explicit `init_settings()`.

---

## SSO (Social Login)

- Enable and configure Google, GitHub, or other OAuth providers in your config:
  ```
  GOOGLE_CLIENT_ID=...
  GOOGLE_CLIENT_SECRET=...
  GITHUB_CLIENT_ID=...
  GITHUB_CLIENT_SECRET=...
  ```
- Mount the built-in routers:
  ```python
  from authtuna.routers import social as social_router
  app.include_router(social_router.router, prefix="/social", tags=["Social Login"])
  ```

---

## MFA (Multi-Factor Authentication)

- AuthTuna supports TOTP, email MFA, and backup codes.
- Enable MFA in your app settings and use the built-in flows:
  ```python
  # Flows available in templates/pages and routers
  ```

---

## Permission Checker

- Protect any route with fine-grained, context-aware permissions:
  ```python
  from authtuna.integrations.fastapi_integration import PermissionChecker

  @app.get("/resource/{resource_id}")
  async def get_resource(
      resource_id: str,
      user = Depends(PermissionChecker("resource:read", scope_from_path="resource_id"))
  ):
      ...
  ```

---

## Role Checker

- Require a role for access (supports multiple roles, hierarchical RBAC):
  ```python
  from authtuna.integrations.fastapi_integration import RoleChecker

  @app.get("/admin")
  async def admin_panel(user=Depends(RoleChecker("admin", "superuser"))):
      ...
  ```

---

## Sample Backend Code

```python
from fastapi import FastAPI, Depends, HTTPException
from authtuna.middlewares.session import DatabaseSessionMiddleware
from authtuna.integrations.fastapi_integration import (
    get_current_user, PermissionChecker, RoleChecker
)
from authtuna.core.database import User

app = FastAPI()
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username}

@app.get("/project/{project_id}/edit")
async def edit_project(
    project_id: str,
    user: User = Depends(PermissionChecker("project:edit", scope_from_path="project_id"))
):
    # Only users with 'edit' permission in this project
    return {"msg": "Project edit granted"}

@app.get("/superadmin")
async def superadmin(user: User = Depends(RoleChecker("superadmin"))):
    return {"msg": f"Welcome, {user.username}!"}
```

---

## Advanced Guide & Patterns

- **Multi-Tenancy:** Use scoped permissions to isolate orgs/customers.
- **Device/IP/Region Security:** Use session hooks to enforce device or location controls.
- **Key Rotation:** Rotate `FERNET_KEYS`, `ENCRYPTION_PRIMARY_KEY` as needed. Old keys are accepted for decryption.
- **Event Hooks:** Run logic on login, registration, session validation, etc.
- **Custom User Models:** Extend or swap out models as needed.
- **Pluggable Routers:** Use only pieces you want, or replace with your own.

---

## Proof of Endless Possibility

- **SaaS Platforms:** Isolated orgs, user impersonation, custom admin flows.
- **FinTech:** Device fingerprinting, session hijack protection, audit logging.
- **Education/Community:** Nested hierarchy permissions, moderation, bulk actions.
- **Enterprise:** SSO, approval workflows, compliance and auditing.

> If you can describe the business logic, you can implement it in AuthTuna.

## Community & Support
- Found a bug or need a feature? [Open an issue](https://github.com/shashstormer/AuthTuna/issues)
- Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---
*No hype, no snake oil—just a modern, async security framework that works. PRs, questions, and feedback always welcome!*
