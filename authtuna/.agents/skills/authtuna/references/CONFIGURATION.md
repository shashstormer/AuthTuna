# AuthTuna Configuration Guide

AuthTuna uses Pydantic-based settings for maximum flexibility. You can configure it via environment variables, a `.env` file, or programmatically.

## Core Feature Toggles

Everything in AuthTuna is optional. You can disable entire subsystems to keep your application lightweight.

| Variable | Default | Description |
|----------|---------|-------------|
| `UI_ENABLED` | `True` | Mounts HTML pages and dashboards. |
| `MFA_ENABLED` | `True` | Enables TOTP support. |
| `PASSKEYS_ENABLED` | `True` | Enables WebAuthn support. |
| `ADMIN_ROUTES_ENABLED` | `True` | Mounts the `/admin` routers. |
| `PASSWORDLESS_LOGIN_ENABLED` | `True` | Enables email-link login. |
| `ONLY_MIDDLEWARE` | `False` | Disables all routes; only keeps session validation. |
| `EMAIL_ENABLED` | `False` | Required for password resets and verification. |

## Essential Security Settings

| Variable | Required | Description |
|----------|----------|-------------|
| `PRODUCTION` | No | Set to `True` in production. Enables strict checks to ensure dev defaults (like `JWT_SECRET_KEY`) are changed. |
| `API_BASE_URL` | Yes | Public URL of your API (e.g., `https://api.myapp.com`). |
| `FERNET_KEYS` | Yes | List of base64 keys for session encryption. |
| `DEFAULT_DATABASE_URI` | Yes | SQLAlchemy async URI (e.g., `postgresql+asyncpg://...`). |
| `JWT_SECRET_KEY` | No | Secret for JWT-based tokens. |

## Theme Customization

AuthTuna supports a comprehensive theme system for its prebuilt UI. You can customize colors for both light and dark modes.

```python
from authtuna.core.config import init_settings, Theme, ThemeMode

my_theme = Theme(
    light=ThemeMode(
        primary="#007AFF",  # iOS Blue
        background_start="#FFFFFF",
        # ... other colors
    ),
    dark=ThemeMode(
        primary="#0A84FF",
        background_start="#000000",
        # ... other colors
    )
)

init_settings(THEME=my_theme, API_BASE_URL="...", ...)
```

## Advanced Session Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `STRATEGY` | `"AUTO"` | `"COOKIE"`, `"BEARER"`, or `"AUTO"`. |
| `LOCK_SESSION_REGION` | `True` | Ties sessions to IP geolocation. |
| `SESSION_LIFETIME_SECONDS` | `604800` | (1 week) Rolling session expiry. |
| `SESSION_ABSOLUTE_LIFETIME` | `31536000` | (1 year) Max total session age. |
| `FINGERPRINT_HEADERS` | `["User-Agent"]`| Headers used for device tracking. |

## Database Connection Pool

- **Supported Databases**: 
  - **PostgreSQL** (via `asyncpg`)
  - **SQLite** (via `aiosqlite`)
  - *Other databases (MySQL, Oracle, etc.) are NOT supported.*
- **Async Only**: The entire library is built on `SQLAlchemy`'s async extension.
AuthTuna uses SQLAlchemy's async engine. You can tune the pool size and overflow for high-concurrency environments:
- `DATABASE_POOL_SIZE` (Default: 20)
- `DATABASE_MAX_OVERFLOW` (Default: 40)
- `DATABASE_POOL_TIMEOUT` (Default: 30)
- `DATABASE_POOL_RECYCLE` (Default: 1800)

## Rate Limiting

AuthTuna provides built-in rate limiting for authentication attempts to protect against brute-force attacks.

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_LOGIN_ATTEMPTS_PER_IP` | `10` | Total attempts allowed from one IP. |
| `MAX_LOGIN_ATTEMPTS_PER_USER` | `5` | Attempts allowed for a specific user. |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS`| `900` | Window (15m) for attempt counting. |
| `LOGIN_LOCKOUT_DURATION_SECONDS` | `1800` | Duration (30m) of account lockout. |

## PII Encryption & Privacy

For high-security environments, AuthTuna can encrypt Personal Identifiable Information (PII) at rest.

| Variable | Default | Description |
|----------|---------|-------------|
| `PII_ENCRYPTION_ENABLED` | `False` | Toggles encryption for emails and PII fields. |
| `PII_HMAC_KEY` | `None` | Key for hashing PII for exact-match lookup. |
| `ENCRYPT_AUDIT_IP` | `True` | Encrypts IP addresses in the audit trail. |

**Important**: When PII encryption is enabled, AuthTuna uses **crypto-shredding** for GDPR compliance. Deleting a user destroys their unique encryption key, rendering their stored data unreadable.
