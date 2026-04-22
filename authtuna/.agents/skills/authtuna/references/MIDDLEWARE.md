# FastAPI Middleware Reference

AuthTuna provides a high-security, database-backed session middleware for FastAPI.

## `DatabaseSessionMiddleware`

Located in `authtuna.middlewares.session`.

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `public_routes` | `Set[str]` \| `Callable` | Routes that don't require authentication. |
| `public_docs` | `bool` | If `True`, `/docs` and `/openapi.json` are public by default. |
| `region_kwargs` | `dict` | Custom arguments for device fingerprinting. |
| `raise_errors` | `bool` | Whether to propagate internal middleware errors. |

### Security Features

1.  **Session Hijack Detection**:
    *   **Region Locking**: Detects if a session moves to a different geographical region.
    *   **Device Fingerprinting**: Validates the User-Agent and device characteristics.
    *   **Random String Rotation**: Mitigates replay attacks by rotating a secret part of the JWT on every request (or interval).
2.  **State Injection**:
    *   Injects `request.state.user_id` and `request.state.session_id`.
    *   Injects `request.state.token_method` (`COOKIE` or `BEARER`).
3.  **Automatic Cookie Management**:
    *   Refreshes the session cookie on valid requests.
    *   Deletes the cookie automatically on invalid/expired/hijacked sessions.

### Usage

```python
from authtuna.middlewares.session import DatabaseSessionMiddleware

app.add_middleware(
    DatabaseSessionMiddleware,
    public_routes={"/health", "/about"},
    public_docs=True
)
```
