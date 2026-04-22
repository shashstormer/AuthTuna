# Pattern: Passwordless "Magic Link" Authentication

Improve user conversion and security by allowing logins via temporary email-based tokens.

## Concept
- **Token Generation**: Create a short-lived token linked to a user and a specific purpose (`passwordless_login`).
- **Email Delivery**: Send a link containing the token to the user's email.
- **Verification**: On clicking the link, the token is validated, and a session is created.

## Implementation

### 1. Enable Configuration
Ensure tokens are enabled in settings.

```python
# settings.py
PASSWORDLESS_LOGIN_ENABLED = True
TOKENS_EXPIRY_SECONDS = 600 # 10 minutes
```

### 2. Requesting the Link
Create an endpoint to generate and send the token.

```python
@app.post("/auth/magic-link/request")
async def request_magic_link(email: str):
    user = await auth_service.users.get_by_email(email)
    if user:
        token = await auth_service.tokens.create(
            user_id=user.id, 
            purpose="passwordless_login"
        )
        # Send email with link: /auth/magic-link/verify?token=<token.id>
        await send_magic_link_email(user.email, token.id)
    return {"message": "If the account exists, a link has been sent."}
```

### 3. Verifying the Token
Create the landing endpoint that converts the token into a session.

```python
@app.get("/auth/magic-link/verify")
async def verify_magic_link(token: str, request: Request):
    try:
        # 1. Validate token
        token_obj = await auth_service.tokens.verify(
            token_id=token, 
            purpose="passwordless_login"
        )
        
        # 2. Get User
        user = await auth_service.users.get_by_id(token_obj.user_id)
        
        # 3. Create Session (Cookie-based)
        response = RedirectResponse(url="/ui/dashboard")
        await create_session_and_set_cookie(user, request, response)
        return response
        
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid or expired link.")
```

## Security Considerations
- **Single Use**: `auth_service.tokens.verify` marks the token as `used` automatically.
- **Expiration**: Keep the TTL short (e.g., 10-15 minutes).
- **Rate Limiting**: Apply strict rate limits to the "request" endpoint to prevent email spamming.

## Best Practices
- **UX**: Use a clean, clear email template.
- **Fallbacks**: Always allow users to fall back to password or MFA if the magic link fails.
- **Device Continuity**: Magic links work best when the user clicks the link on the same device where they requested it.
