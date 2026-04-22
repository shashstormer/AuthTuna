# AuthTuna HTTP Routes

When you call `init_app(app)`, AuthTuna mounts a series of APIRouters. Below is a comprehensive list of the out-of-the-box endpoints.

## Authentication Routes (`/auth`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/signup` | Registers a new user. |
| POST | `/auth/login` | Authenticates and starts a session. |
| ANY | `/auth/logout` | Terminates the current session. |
| POST | `/auth/forgot-password` | Requests a password reset link. |
| POST | `/auth/reset-password` | Resets password using a token. |
| POST | `/auth/change-password` | Updates password for logged-in user. |
| ANY | `/auth/user-info` | Returns detailed JSON about the current user. |
| GET | `/auth/signup` | HTML Signup page. |
| GET | `/auth/login` | HTML Login page. |
| GET | `/auth/forgot-password` | HTML Forgot Password page. |
| GET | `/auth/verify` | HTML Email Verification handler. |
| GET | `/auth/reset-password` | HTML Password Reset page. |

## UI & Dashboard Routes (`/ui`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ui/dashboard` | User's main landing page. |
| GET | `/ui/profile` | User profile management page. |
| GET | `/ui/settings` | General settings and MFA setup. |
| GET | `/ui/organizations` | List and manage organizations. |
| POST | `/ui/organizations/create` | Create a new organization. |
| GET | `/ui/organizations/{id}` | Detailed org view (members, teams). |
| GET | `/ui/settings/sessions` | List all active sessions. |
| POST | `/ui/settings/sessions/{id}/terminate` | Revoke a specific session. |
| GET | `/ui/settings/api-keys` | Manage user API keys. |

## MFA & Passkey Routes (`/mfa`, `/passkey`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mfa/setup` | Initiates TOTP setup. |
| POST | `/mfa/verify` | Finalizes TOTP setup. |
| POST | `/passkey/register/options` | WebAuthn registration options. |
| POST | `/passkey/register/verify` | Finalizes Passkey registration. |
| POST | `/passkey/login/options` | WebAuthn login options. |
| POST | `/passkey/login/verify` | Finalizes Passkey login. |

## Admin Routes (`/admin`)

*Note: These require administrative roles by default.*

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List all system users. |
| GET | `/admin/roles` | List and manage system roles. |
| GET | `/admin/audit` | View system-wide audit logs. |

## Social Auth Routes (`/auth/social`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/social/google/login` | Initiates Google OAuth flow. |
| GET | `/auth/social/google/callback` | Google OAuth callback handler. |
| GET | `/auth/social/github/login` | Initiates GitHub OAuth flow. |
| GET | `/auth/social/github/callback` | GitHub OAuth callback handler. |
