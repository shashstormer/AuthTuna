# Hook Events Reference

AuthTuna uses an event-driven architecture. You can register asynchronous hooks to execute custom logic when specific events occur.

## Available Events

| Event Constant (`Events.`) | Name | Triggered When... |
|---------------------------|------|-------------------|
| `USER_CREATED` | `user_created` | A new user account is successfully created. |
| `USER_UPDATED` | `user_updated` | User profile data is modified. |
| `USER_DELETED` | `user_deleted` | A user is archived/deleted (standard delete). |
| `USER_LOGGED_IN` | `user_logged_in` | A user successfully authenticates. |
| `SOCIAL_ACCOUNT_CONNECTED`| `social_account_connected` | A third-party provider is linked to a user. |
| `ORG_CREATED` | `org_created` | A new organization is created. |
| `TEAM_CREATED` | `team_created` | A new team is created within an org. |

## Registration Pattern

```python
from authtuna.core.hooks import Events
from authtuna.integrations.fastapi_integration import auth_service

@auth_service.hooks.on(Events.USER_LOGGED_IN)
async def track_login(user, **kwargs):
    print(f"User {user.username} logged in!")
```

### Hook Execution
- Hooks are executed **sequentially** for database consistency.
- All hooks receive the relevant objects as keyword arguments (e.g., `user`, `org`, `team`).
- Errors in hooks are logged but do not block the main transaction.
