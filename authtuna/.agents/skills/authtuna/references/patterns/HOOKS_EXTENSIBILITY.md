# Pattern: Event-Driven Extensibility (Hooks)

Extend AuthTuna's core behavior without modifying its source code using the asynchronous hook system.

## Concept
- **Events**: Predefined points in the lifecycle (e.g., `USER_CREATED`).
- **Hooks**: Asynchronous functions registered to an event.
- **Side-Effects**: Typical uses include sending emails, notifying Slack, or sync'ing with a CRM.

## Implementation

### 1. Registering a Hook
Use the `@auth_service.hooks.on` decorator or `register()` method.

```python
from authtuna.core.hooks import Events

@auth_service.hooks.on(Events.USER_CREATED)
async def welcome_new_user(user, **kwargs):
    # This runs after the user is committed to the DB
    await email_service.send_welcome(user.email)
```

### 2. Manual Triggering
You can trigger custom events in your own code.

```python
await auth_service.hooks.trigger("custom_payment_received", user_id=uid, amount=50)
```

## Available System Events
| Constant | Description |
|----------|-------------|
| `USER_CREATED` | After registration. |
| `USER_LOGGED_IN` | After successful authentication. |
| `SOCIAL_ACCOUNT_CONNECTED` | After OAuth callback. |
| `ORG_CREATED` | After organization creation. |
| `TEAM_CREATED` | After team creation. |

## Important Considerations
1.  **Sequential Execution**: Hooks run one after another. A slow hook will delay subsequent hooks (but not the main response if run in a background task).
2.  **Error Handling**: If a hook fails, AuthTuna logs the error but continues to the next hook.
3.  **Database Sessions**: Hooks should ideally use their own DB sessions or be careful with the shared session provided in `kwargs`.

## Best Practices
- **Background Tasks**: If a hook performs a heavy operation (e.g., calling an external API), wrap it in a FastAPI `BackgroundTasks` if possible.
- **Idempotency**: Ensure hooks can be safely re-run if the event is triggered multiple times.
- **Logging**: Always log important side-effects triggered by hooks.
