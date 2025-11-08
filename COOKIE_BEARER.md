# Quick Reference: Cookie vs Bearer Authentication

## Request Flow Comparison

### COOKIE Authentication Flow
```
Client Request
    ↓
[Middleware: DatabaseSessionMiddleware]
    ↓ Reads cookie: "session=jwt_token..."
    ↓ Calls: _cookie_helper()
    ↓ Decodes JWT
    ↓ Validates against database (periodically)
    ↓ Sets: request.state.user_id
    ↓ Sets: request.state.session_id
    ↓ Sets: request.state.token_method = "COOKIE"
    ↓
[Endpoint Dependency: get_current_user]
    ↓ Checks: request.state.token_method == "COOKIE"
    ↓ Loads user from database using user_id
    ↓ Caches: request.state.user_object
    ↓ Returns: User object
    ↓
[Permission/Role Checker]
    ↓ Calls: _cookie_helper()
    ↓ Checks user's roles/permissions from database
    ↓ Returns: User if authorized
    ↓
[Your Endpoint Handler]
    ↓ Receives: User object
    ↓ Returns: Response
```

### BEARER Authentication Flow
```
Client Request
    ↓ Header: "Authorization: Bearer sk_xxx..."
[Middleware: DatabaseSessionMiddleware]
    ↓ Reads header
    ↓ Calls: _bearer_helper()
    ↓ Validates API key against database
    ↓ Sets: request.state.user_id
    ↓ Sets: request.state.api_key (cached)
    ↓ Sets: request.state.token_method = "BEARER"
    ↓
[Endpoint Dependency: get_current_user]
    ↓ Checks: request.state.token_method == "BEARER"
    ↓ Loads user from database using api_key.user_id
    ↓ Caches: request.state.user_object
    ↓ Returns: User object
    ↓
[Permission/Role Checker]
    ↓ Calls: _api_helper()
    ↓ Checks API key's scopes
    ↓ Validates permissions within those scopes
    ↓ Returns: User if authorized (scope-restricted)
    ↓
[Your Endpoint Handler]
    ↓ Receives: User object
    ↓ Returns: Response
```

## Key Differences

| Aspect | COOKIE | BEARER |
|--------|--------|--------|
| **Authentication** | Session ID + JWT | API Key |
| **Storage** | Browser cookie | App/Client storage |
| **Validation** | Periodic DB check | Every request |
| **Security** | Hijack detection (IP/device) | Scope restrictions |
| **User Context** | request.state.session_id | request.state.api_key |
| **Permission Model** | User's full roles | API key's scopes only* |
| **Refresh** | Token refreshed in middleware | No refresh (key expiry) |
| **Use Case** | Web applications | APIs, integrations |

\* Exception: MASTER keys use user's full roles dynamically

## Code Patterns

### Pattern 1: Accept Both Auth Types
```python
@router.get("/data")
async def get_data(user: User = Depends(get_current_user)):
    # Works with both cookie and bearer!
    return {"data": "...", "user": user.username}
```

### Pattern 2: Permission with Both Auth Types
```python
@router.post("/admin/action")
async def admin_action(
    user: User = Depends(PermissionChecker("admin:write"))
):
    # Cookie users: Checks full permissions
    # Bearer users: Checks if API key has this scope
    return {"status": "success"}
```

### Pattern 3: Different Logic per Auth Type
```python
from authtuna.integrations.fastapi_integration import resolve_token_method

@router.get("/mixed")
async def mixed_endpoint(
    request: Request,
    user: User = Depends(get_current_user)
):
    token_method = resolve_token_method(request)
    
    if token_method == "COOKIE":
        # User is logged in via browser
        return {"view": "full_ui", "user": user.username}
    elif token_method == "BEARER":
        # API client
        return {"data": {"user_id": user.id}}
    else:
        # Shouldn't happen if get_current_user succeeded
        raise HTTPException(401)
```

### Pattern 4: Check API Key Details (Bearer Only)
```python
@router.get("/key-info")
async def key_info(request: Request, user: User = Depends(get_current_user)):
    token_method = resolve_token_method(request)
    
    if token_method == "BEARER":
        api_key = request.state.api_key
        return {
            "key_id": api_key.id,
            "key_type": api_key.key_type,
            "expires_at": api_key.expires_at,
            "last_used": api_key.last_used_at
        }
    else:
        return {"error": "This endpoint requires API key authentication"}
```

## Troubleshooting

### Issue: "Not authenticated" error

**Cookie:**
- Check if session cookie is being sent
- Verify cookie hasn't expired
- Check if session is active in database
- Look for hijack detection (IP/device changed)

**Bearer:**
- Verify API key format: "Bearer sk_xxx..."
- Check if API key exists and isn't expired
- Ensure API key belongs to the user
- Check if key has required scopes

### Issue: Permission denied

**Cookie:**
- User might not have the required role
- Check user's roles in database
- Verify permission is assigned to role

**Bearer:**
- API key might not have required scope
- Check API key's scopes in database
- For SECRET keys: Scope must be explicitly granted
- For MASTER keys: Should have all user's permissions
- For PUBLIC keys: No permissions (identity only)

### Issue: Token method is None

- Middleware might not be installed
- Check if route is in public_routes
- Verify STRATEGY setting ("COOKIE", "BEARER", or "AUTO")

## Best Practices

1. **Use COOKIE for web applications** - Better UX, automatic refresh
2. **Use BEARER for APIs** - Better for integrations, machine-to-machine
3. **Use AUTO strategy for hybrid apps** - Supports both seamlessly
4. **Always validate scopes for SECRET keys** - Least privilege principle
5. **Use MASTER keys sparingly** - High privilege, suitable for admin tools
6. **Log API key usage** - Track last_used_at for security monitoring
7. **Set appropriate expiry times** - Balance security vs convenience
8. **Test both auth types** - Ensure endpoints work with both
9. **Document which auth types your endpoints support** - Help API consumers
10. **Use scope-based permissions** - More granular control with API keys

## Summary

- Both authentication types are fully implemented and integrated
- Middleware handles validation for both
- FastAPI dependencies work seamlessly with both
- Permission/Role checkers respect the differences
- Developers can use both types interchangeably or specifically

The system is production-ready! 🚀
