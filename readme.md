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

This readme.md is so that LLM's can understand how to use the library instead of hallucinating, but it contains a decent level of docs but the docs site better.

### Below is some documentation on getting started.

---

## Table of Contents

1. [Getting Started (Basic Auth & Login)](#getting-started-basic-auth--login)
2. [Configuration Options](#configuration-options)
   - [Required Config Keys](#required-config-keys)
   - [All Config Options](#all-config-options)
   - [Setting Configuration](#setting-configuration)
3. [FastAPI Integration](#fastapi-integration)
   - [Dependencies](#dependencies)
   - [Permission Checker](#permission-checker)
   - [Role Checker](#role-checker)
4. [Managing Permissions](#managing-permissions)
   - [Creating Permissions](#creating-permissions)
   - [Permission Naming](#permission-naming)
5. [Managing Users](#managing-users)
6. [Creating Roles](#creating-roles)
7. [Batteries Included](#batteries-included)
8. [RBAC Example](#rbac-example)
9. [Advanced Features](#advanced-features)
   - [SSO (Social Login)](#sso-social-login)
   - [MFA (Multi-Factor Authentication)](#mfa-multi-factor-authentication)
   - [Passkeys](#passkeys)
   - [API Keys](#api-keys)
10. [Sample Backend Code](#sample-backend-code)
11. [Advanced Guide & Patterns](#advanced-guide--patterns)
12. [Community & Support](#community--support)

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

## Configuration Options

### Required Config Keys

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

### Setting Configuration

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

## FastAPI Integration

### Dependencies

- Install AuthTuna and FastAPI:
  ```bash
  pip install authtuna fastapi uvicorn[standard]
  ```
- Add middleware to your FastAPI app:
  ```python
  from authtuna.middlewares.session import DatabaseSessionMiddleware

  app.add_middleware(DatabaseSessionMiddleware)
  ```
- Use dependency injection for getting the current user:
  ```python
  from authtuna.integrations.fastapi_integration import get_current_user

  @app.get("/me")
  async def me(user=Depends(get_current_user)):
      return {"id": user.id, "username": user.username}
  ```

### Permission Checker

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

### Role Checker

- Require a role for access (supports multiple roles, hierarchical RBAC):
  ```python
  from authtuna.integrations.fastapi_integration import RoleChecker

  @app.get("/admin")
  async def admin_panel(user=Depends(RoleChecker("admin", "superuser"))):
      ...
  ```

---

## Managing Permissions

Permissions are the granular capabilities that define what actions users can perform in your system. They are the atomic units of authorization, representing specific operations like "create a post", "delete a user", or "view analytics". Unlike roles, permissions are never assigned directly to users — they are always bundled into roles for better management.

### Creating Permissions

Creating permissions involves defining their name and description. AuthTuna validates permissions to prevent duplicates and ensures proper naming conventions.

**Permission Properties:**
- `name`: string (required) - The unique identifier for the permission
- `description`: string (optional) - Human-readable description

**Creating a Permission:**
```python
from authtuna.integrations import auth_service

permission_manager = auth_service.permissions

# Create a new permission
new_permission = await permission_manager.create(
    name="posts:create",
    description="Allows users to create new blog posts"
)

# Or use get_or_create for idempotent operations
permission, created = await permission_manager.get_or_create(
    name="posts:publish",
    defaults={"description": "Allows publishing posts to make them public"}
)

if created:
    print("Permission was created")
else:
    print("Permission already exists")
```

### Permission Naming Conventions

Well-structured permission names make your authorization system maintainable and understandable. AuthTuna follows a hierarchical naming pattern that's both readable and scalable.

**The Pattern: resource:action**
Use colon-separated hierarchies to organize permissions by resource and action. This creates a natural taxonomy that's easy to understand and query.

**Examples:**
- `posts:create` - Create blog posts
- `users:manage` - Manage user accounts
- `reports:view` - View analytics reports
- `org:teams:invite` - Invite members to organization teams

**Good Practices:**
- Use lowercase: `posts:create` not `Posts:Create`
- Be specific: `posts:publish` not `posts:edit`
- Use hierarchies: `org:teams:manage` for nested resources
- Be consistent: Follow patterns across your application
- Use verbs: create, read, update, delete, manage, view, etc.

**Anti-Patterns:**
- Too generic: `admin` - what does it allow?
- Mixed case: `Posts:Create` - inconsistent
- Too specific: `posts:create:with:image` - over-complicated

---

## Managing Users

AuthTuna provides comprehensive user management capabilities through the `auth_service.users` manager.

Read docs at (user docs)[https://authtuna.shashstorm.in/managing-user]

### Creating Users

```python
from authtuna.integrations import auth_service

user_manager = auth_service.users

# Create a new user
new_user = await user_manager.create(
    email="john@example.com",
    username="johndoe",
    password="secure_password_123"
)

# Create user with additional metadata
user_with_meta = await user_manager.create(
    email="jane@example.com",
    username="janedoe",
    password="secure_password_123",
    first_name="Jane",
    last_name="Doe",
    is_active=True
)
```

### User Operations

```python
# Get user by ID
user = await user_manager.get_by_id(user_id)

# Get user by email
user = await user_manager.get_by_email("john@example.com")

# Update user
updated_user = await user_manager.update(
    user_id,
    {"first_name": "John", "last_name": "Smith"}
)

# Suspend user
await user_manager.suspend_user(user_id, admin_id, "Violation of terms")

# Unsuspend user
await user_manager.unsuspend_user(user_id, admin_id, "Appeal approved")

# Delete user (soft delete)
await user_manager.delete(user_id)

# List users with pagination
users = await user_manager.list(skip=0, limit=50)
```

### User Authentication

User authentication is handled through the main AuthTuna service:

```python
from authtuna.integrations import auth_service

# Login user
user, session_or_token = await auth_service.login(
    username_or_email="johndoe",
    password="secure_password_123",
    ip_address="192.168.1.1",
    region="US",
    device="Chrome on Windows"
)

# Change password
await auth_service.change_password(
    user=user,
    current_password="old_password",
    new_password="new_secure_password",
    ip_address="192.168.1.1",
    current_session_id=session_id
)

# Request password reset
token = await auth_service.request_password_reset(
    email="john@example.com",
    ip_address="192.168.1.1"
)

# Reset password with token
user = await auth_service.reset_password(
    token_id=token.id,
    new_password="new_password",
    ip_address="192.168.1.1"
)
```
---

## Creating Roles

Roles are groups of permissions that can be assigned to users. They provide a way to manage permissions at scale.

### Role Management

just read on (authtuna role management docs)[https://authtuna.shashstorm.in/creating-roles]

```python
from authtuna.integrations import auth_service

role_manager = auth_service.roles

# Create a new role
new_role = await role_manager.create(
    name="editor",
    description="Content editor with publishing rights"
)

# Add permissions to role
await role_manager.add_permission_to_role(
    role_name="editor",
    permission_name="posts:create"
)

await role_manager.add_permission_to_role(
    role_name="editor",
    permission_name="posts:edit",
    adder_id="system" # this is for audit logging.
)

# Assign role to user
await role_manager.assign_to_user(
    user_id=user.id,
    role_name="editor",
    assigner_id=admin_id, # This checks if the assigner can assign or not, you need to correctly setup the role with either hierarchy or using grantable allow.
    scope="org:project1", # either set this or set global, default = none to prevent misconfiguration
)

# Remove role from user
await role_manager.remove_from_user(
    user_id=user.id,
    role_name="editor",
    remover_id=admin_id
)
```

### Built-in Roles

AuthTuna comes with several built-in roles:

- **Superadmin**: Has all permissions in the system
- **Admin**: Has administrative permissions for user and system management
- **User**: Basic authenticated user permissions

### Role Hierarchy

Roles can be hierarchical. For example:
- Superadmin > Admin > User
- Admin can manage users, but User cannot

---

## Batteries Included

AuthTuna includes sensible defaults and built-in roles/permissions to get you started quickly.

### Default Roles

1. **Superadmin**
   - All permissions
   - System administration
   - User management
   - Role management

2. **Admin**
   - User management (create, update, deactivate)
   - Role assignment
   - System monitoring

3. **User**
   - Basic authentication
   - Profile management
   - Access to user-specific resources

### Default Permissions

AuthTuna automatically creates common permissions:
- `users:read` - View user profiles
- `users:manage` - Create/update/delete users
- `roles:read` - View roles
- `roles:manage` - Create/update/delete roles
- `permissions:read` - View permissions
- `permissions:manage` - Create/update permissions

### Auto-initialization

On first startup, AuthTuna will:
1. Create default roles
2. Create default permissions
3. Assign permissions to roles
4. Create system users (superadmin, admin)

---

## RBAC Example

Here's a complete example of setting up RBAC for a blog application.

### 1. Define Permissions

```python
from authtuna.integrations import auth_service

# Create permissions
await auth_service.permissions.get_or_create("posts:create", {"description": "Create blog posts"})
await auth_service.permissions.get_or_create("posts:read", {"description": "Read blog posts"})
await auth_service.permissions.get_or_create("posts:update", {"description": "Update blog posts"})
await auth_service.permissions.get_or_create("posts:delete", {"description": "Delete blog posts"})
await auth_service.permissions.get_or_create("posts:publish", {"description": "Publish blog posts"})
await auth_service.permissions.get_or_create("comments:moderate", {"description": "Moderate comments"})
```

### 2. Create Roles

```python
# Create Editor role
editor_role = await auth_service.roles.create("editor", "Content editor")
await auth_service.roles.add_permission_to_role("editor", "posts:create")
await auth_service.roles.add_permission_to_role("editor", "posts:read")
await auth_service.roles.add_permission_to_role("editor", "posts:update")
await auth_service.roles.add_permission_to_role("editor", "posts:publish")

# Create Moderator role
moderator_role = await auth_service.roles.create("moderator", "Comment moderator")
await auth_service.roles.add_permission_to_role("moderator", "posts:read")
await auth_service.roles.add_permission_to_role("moderator", "comments:moderate")

# Create Viewer role
viewer_role = await auth_service.roles.create("viewer", "Content viewer")
await auth_service.roles.add_permission_to_role("viewer", "posts:read")
```

### 3. Assign Roles to Users

```python
# Assign roles to users
await auth_service.roles.assign_to_user(user_id=editor_user.id, role_name="editor", assigner_id=admin_id)
await auth_service.roles.assign_to_user(user_id=moderator_user.id, role_name="moderator", assigner_id=admin_id)
await auth_service.roles.assign_to_user(user_id=viewer_user.id, role_name="viewer", assigner_id=admin_id)
```
---

## Advanced Features

### SSO (Social Login)

AuthTuna supports OAuth-based social login with Google, GitHub, and other providers.

#### Configuration

Add to your `.env` file:
```
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=https://yourapp.com/auth/social/google/callback

GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=https://yourapp.com/auth/social/github/callback
```

#### Setup

```python
from fastapi import FastAPI
from authtuna.routers import social
from authtuna import init_app

app = FastAPI()
init_app(app)

# Mount social login routes
app.include_router(social.router, prefix="/auth/social", tags=["Social Login"])
```

#### Usage

Users can now login via:
- `/auth/social/google/login`
- `/auth/social/github/login`

The social login will create user accounts automatically on first login.

### MFA (Multi-Factor Authentication)

AuthTuna supports MFA methods: TOTP and backup codes.

#### Enabling MFA

```python
# In your .env
MFA_ENABLED=True
```

#### MFA Setup Flow

```python
from authtuna.integrations import auth_service

# Start MFA setup for user
secret, url = await auth_service.mfa.setup_totp(user_id, "Just put ur app nm here it will give appname:email as credential id on scanning on phone")

# Returns QR code URL for TOTP apps like Google Authenticator
print(url)

# Complete setup with verification code
await auth_service.mfa.verify_and_enable_totp(user_id, verification_code="123456")
```

#### MFA Verification

```python
# Verify MFA code during login
is_valid = await auth_service.mfa.verify_code(user_id, code="123456")
```

### Passkeys

Passkeys provide passwordless authentication using WebAuthn.

#### Configuration

```python
# In your .env
WEBAUTHN_ENABLED=True
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_ORIGIN=https://yourdomain.com
```

### API Keys

API keys allow programmatic access to your application.

#### Creating API Keys

```python
from authtuna.integrations import auth_service

# Create API key for user
api_key = await auth_service.api_keys.create_key(
    user_id=user.id,
    name="My API Key",
    key_type="secret",
    scopes=["Admin:global", "Projects:{sm_org_ig}"], 
    valid_seconds=31536000  # 1 year
)

print(api_key.plaintext)  # The actual API key to use (only shown once)
```

#### Using API Keys

API keys can be used in two ways:

1. **Bearer Token**: `Authorization: Bearer sk-...`
2. **Query Parameter**: `?api_key=sk-...`

#### API Key Management

```python
# List user's API keys
keys = await auth_service.api_keys.get_all_keys_for_user(user.id)

# Revoke API key
await auth_service.api_keys.delete_key(key_id)
```

---

## Sample Backend Code

```python
from fastapi import FastAPI, Depends, HTTPException
from authtuna import init_app
from authtuna.integrations.fastapi_integration import (
    get_current_user,
    PermissionChecker,
    RoleChecker
)

app = FastAPI(title="AuthTuna Example API")

# Initialize AuthTuna (adds all routes, middleware, etc.)
init_app(app)

# Public endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to AuthTuna API"}

# Protected endpoint - requires authentication
@app.get("/me")
async def get_current_user_info(user=Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [role.name for role in user.roles]
    }

# Permission-based protection
@app.get("/admin/users")
async def list_users(user=Depends(PermissionChecker("users:manage"))):
    # Only users with users:manage permission
    users = await get_all_users()
    return {"users": users}

# Role-based protection
@app.post("/admin/roles")
async def create_role(role_data: dict, user=Depends(RoleChecker("admin"))):
    # Only admin role
    new_role = await create_role_in_db(role_data)
    return {"role": new_role}

# Scoped permissions
@app.get("/projects/{project_id}")
async def get_project(
    project_id: str,
    user=Depends(PermissionChecker("projects:read", scope_from_path="project_id"))
):
    # Check if user can read this specific project
    project = await get_project_by_id(project_id)
    return {"project": project}

# API key support
@app.get("/api/data")
async def get_data(user=Depends(get_current_user)):
    # Works with both session cookies and API keys
    data = await fetch_data_for_user(user.id)
    return {"data": data}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## Advanced Guide & Patterns

### Multi-Tenant Applications

For applications serving multiple organizations:

```python
# Organization-scoped permissions
@app.get("/orgs/{org_id}/projects")
async def list_org_projects(
    org_id: str,
    user=Depends(PermissionChecker("projects:read", scope_from_path="org_id"))
):
    # User must have projects:read permission in this org
    projects = await get_projects_for_org(org_id, user.id)
    return {"projects": projects}
```

### Database Integration

AuthTuna works with any async SQLAlchemy-supported database:

```python
# PostgreSQL
DEFAULT_DATABASE_URI=postgresql+asyncpg://user:pass@localhost/dbname

# SQLite (default)
DEFAULT_DATABASE_URI=sqlite+aiosqlite:///./authtuna.db
```
