[![PyPI version](https://img.shields.io/pypi/v/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![Python Versions](https://img.shields.io/pypi/pyversions/authtuna.svg?style=flat-square)](https://pypi.org/project/authtuna/)
[![License](https://img.shields.io/github/license/shashstormer/authtuna?style=flat-square)](LICENSE.txt)
[![CI](https://github.com/shashstormer/authtuna/actions/workflows/ci.yml/badge.svg)](https://github.com/shashstormer/authtuna/actions)
[![codecov](https://codecov.io/github/shashstormer/AuthTuna/graph/badge.svg?token=8AV8FB3ZGQ)](https://codecov.io/github/shashstormer/AuthTuna)
[![Downloads](https://static.pepy.tech/badge/authtuna)](https://pepy.tech/project/authtuna)


# AuthTuna 🐟

A modern async security framework for Python (FastAPI-first, framework-agnostic core).
Battle-tested, batteries-included authentication, session management, RBAC, SSO, MFA, and much more.

## Check Documentation at [authtuna.shashstorm.in](https://authtuna.shashstorm.in)

### Below is some documentation on getting started.

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

## Upgrading To v0.2.0
You may need to run [upgrade script](https://github.com/shashstormer/stormauth/blob/28c50aef8a8b80f563bbaf7e548f1deeb162b2aa/test.py) if you are not able to access the dashboard as the user dashboard now check the User role instead of get_current_user which was not present some versions ago and also set `TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN=True` in .env.

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

| Variable                      | Description                                                | Required | Default                                |
|-------------------------------|------------------------------------------------------------|----------|----------------------------------------|
| `APP_NAME` | Name of the application. | No | `AuthTuna` |
| `ALGORITHM` | JWT encryption algorithm. | No | `HS256` |
| `API_BASE_URL` | Your app's public base URL. | Yes | |
| `TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN`| Attempt to re-initialize the system user if it already exists. | No | `False` |
| `JWT_SECRET_KEY` | Secret key for JWT encryption. | No | `dev-secret-key-change-in-production` |
| `ENCRYPTION_PRIMARY_KEY` | Primary key for encrypting sensitive fields. | No | `dev-encryption-key-change-in-production` |
| `ENCRYPTION_SECONDARY_KEYS` | Secondary keys for key rotation. | No | `[]` |
| `FERNET_KEYS` | Comma-separated list of Fernet keys for session encryption. | Yes | |
| `DEFAULT_SUPERADMIN_PASSWORD` | Default password for the superadmin user. | No | |
| `DEFAULT_ADMIN_PASSWORD` | Default password for the admin user. | No | |
| `DEFAULT_SUPERADMIN_EMAIL` | Default email for the superadmin user. | No | `superadmin@example.com` |
| `DEFAULT_ADMIN_EMAIL` | Default email for the admin user. | No | `admin@example.com` |
| `DEFAULT_DATABASE_URI` | SQLAlchemy database URI. | Yes | `sqlite+aiosqlite:///./authtuna_dev.db` |
| `DATABASE_USE_ASYNC_ENGINE` | Use async SQLAlchemy drivers. | No | `True` |
| `AUTO_CREATE_DATABASE` | Automatically create database tables if they don't exist. | No | `True` |
| `DATABASE_POOL_SIZE` | Database connection pool size. | No | `20` |
| `DATABASE_MAX_OVERFLOW` | Database connection pool max overflow. | No | `40` |
| `DATABASE_POOL_TIMEOUT` | Database connection pool timeout in seconds. | No | `30` |
| `DATABASE_POOL_RECYCLE` | Database connection pool recycle time in seconds. | No | `1800` |
| `DATABASE_POOL_PRE_PING` | Ping the database before each connection. | No | `True` |
| `FINGERPRINT_HEADERS` | List of headers to use for device fingerprinting. | No | `["User-Agent", "Accept-Language"]` |
| `SESSION_DB_VERIFICATION_INTERVAL` | Time in seconds before rechecking if a session token is still active in the database. | No | `10` |
| `SESSION_LIFETIME_SECONDS` | Session duration in seconds. | No | `604800` |
| `SESSION_ABSOLUTE_LIFETIME_SECONDS` | Absolute session lifetime in seconds. | No | `31536000` |
| `SESSION_LIFETIME_FROM` | Session lifetime calculation method (`last_activity` or `creation`). | No | `last_activity` |
| `SESSION_SAME_SITE` | SameSite policy for session cookies. | No | `LAX` |
| `SESSION_SECURE` | Use secure cookies for sessions. | No | `True` |
| `SESSION_TOKEN_NAME` | Cookie name for the session token. | No | `session_token` |
| `SESSION_COOKIE_DOMAIN` | Domain for the session cookie. | No | |
| `LOCK_SESSION_REGION` | Lock sessions to a region based on IP geolocation. | No | `True` |
| `DISABLE_RANDOM_STRING` | Disable random string mismatch checks to prevent logouts in high-concurrency environments. | No | `False` |
| `RANDOM_STRING_GRACE` | Grace period in seconds for accepting stored random strings. | No | `300` |
| `EMAIL_ENABLED` | Enable or disable email features. | No | `False` |
| `SMTP_HOST` | SMTP server host. | If email | |
| `SMTP_PORT` | SMTP server port. | If email | `587` |
| `SMTP_USERNAME` | SMTP server username. | If email | |
| `SMTP_PASSWORD` | SMTP server password. | If email | |
| `DKIM_PRIVATE_KEY_PATH` | Path to the DKIM private key. | If email | |
| `DKIM_DOMAIN` | DKIM domain. | If email | |
| `DKIM_SELECTOR` | DKIM selector. | If email | |
| `DEFAULT_SENDER_EMAIL` | Default email address for sending emails. | No | `noreply@example.com` |
| `EMAIL_DOMAINS` | Allowed email domains for user registration. | No | `["gmail.com"]` |
| `TOKENS_EXPIRY_SECONDS` | Expiry time in seconds for email tokens. | No | `3600` |
| `TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION` | Maximum number of tokens per day per user per action. | No | `5` |
| `MAIL_STARTTLS` | Use STARTTLS for SMTP connections. | No | `True` |
| `MAIL_SSL_TLS` | Use SSL/TLS for SMTP connections. | No | `False` |
| `USE_CREDENTIALS` | Use credentials for SMTP authentication. | No | `True` |
| `VALIDATE_CERTS` | Validate SSL/TLS certificates. | No | `True` |
| `EMAIL_TEMPLATE_DIR` | Directory for email templates. | No | `authtuna/templates/email` |
| `HTML_TEMPLATE_DIR` | Directory for HTML page templates. | No | `authtuna/templates/pages` |
| `DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR` | Directory for dashboard and user info page templates. | No | `authtuna/templates/dashboard` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID. | If Google SSO | |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret. | If Google SSO | |
| `GOOGLE_REDIRECT_URI` | Google OAuth redirect URI. | If Google SSO | |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID. | If GitHub SSO | |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret. | If GitHub SSO | |
| `GITHUB_REDIRECT_URI` | GitHub OAuth redirect URI. | If GitHub SSO | |
| `RPC_ENABLED` | Enable or disable RPC. | No | `False` |
| `RPC_AUTOSTART` | Automatically start the RPC server. | No | `True` |
| `RPC_TOKEN` | RPC authentication token. | No | `changeme-secure-token` |
| `RPC_TLS_CERT_FILE` | Path to the RPC TLS certificate file. | If RPC TLS | |
| `RPC_TLS_KEY_FILE` | Path to the RPC TLS key file. | If RPC TLS | |
| `RPC_ADDRESS` | RPC server address. | No | `[::]:50051` |
| `WEBAUTHN_ENABLED` | Enable or disable WebAuthn. | No | `False` |
| `WEBAUTHN_RP_ID` | WebAuthn relying party ID. | No | `localhost` |
| `WEBAUTHN_RP_NAME` | WebAuthn relying party name. | No | `AuthTuna` |
| `WEBAUTHN_ORIGIN` | WebAuthn origin URL. | No | `http://localhost:8000` |
| `STRATEGY` | Authentication strategy (`COOKIE` or `BEARER`). | No | `COOKIE` |

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

> If you can describe the business logic, you can implement it in AuthTuna.

## Community & Support
- Found a bug or need a feature? [Open an issue](https://github.com/shashstormer/AuthTuna/issues)
- Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---
*No hype, no snake oil—just a modern, async security framework that works. PRs, questions, and feedback always welcome!*


