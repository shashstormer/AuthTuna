# Pattern: Social SSO with Auto-Registration

Integrate third-party identity providers (Google, Github) for seamless user onboarding.

## Concept
- **OAuth2/OIDC**: Uses industry-standard flows via `authlib`.
- **Auto-Registration**: If a social user doesn't exist, AuthTuna creates a local account automatically.
- **Linkage**: Maps a `SocialAccount` to a primary `User`.

## Implementation

### 1. Configure Settings
Add your provider credentials to `.env` or settings.

```env
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
API_BASE_URL=https://myapp.com
```

### 2. Mount the Router
Mount the pre-built social router in your FastAPI app.

```python
from authtuna.routers import social

app.include_router(social.router, tags=["auth"])
```

### 3. Custom Post-Login Logic
Use hooks to perform actions after a social user is registered or logged in.

```python
from authtuna.core.hooks import Events

@auth_service.hooks.on(Events.SOCIAL_ACCOUNT_CONNECTED)
async def on_social_connect(user, provider, **kwargs):
    print(f"User {user.email} connected via {provider}")
```

## How the Flow Works
1.  User visits `/auth/{provider}/login`.
2.  Redirected to Google/Github.
3.  Callback to `/auth/{provider}/callback`.
4.  AuthTuna validates the token, retrieves the email, and finds/creates the local user.
5.  Sets the session cookie and redirects to the `return_url` (default: `/ui/dashboard`).

## Best Practices
- **HTTPS**: OAuth2 callbacks usually require HTTPS in production.
- **Email Verification**: Social providers often provide "email verified" status; AuthTuna trusts this by default.
- **Return URL**: Set a `return_url` cookie before redirecting to login to control the final destination.
