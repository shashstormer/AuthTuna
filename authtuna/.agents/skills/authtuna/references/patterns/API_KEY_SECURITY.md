# Pattern: Zero-Trust API Key Security

Securely expose your API to microservices or third-party integrations using scoped API keys.

## Concept
- **Key Types**:
    - `SECRET`: Standard scoped key.
    - `MASTER`: Dynamically inherits all permissions of the owner.
    - `PUBLIC`: Identity only, no permissions.
- **Prefixing**: Secret keys are prefixed with `sk_` (configurable).
- **Validation**: Keys are hashed using `bcrypt` at rest.

## Implementation

### 1. Generating a Scoped Key
Restrict a key to specific roles and scopes.

```python
# Key that acts as 'Editor' only in 'project/x'
key = await auth_service.api.create_key(
    user_id="user123",
    name="CI Pipeline",
    key_type="SECRET",
    scopes=["Editor:project/x"], # Format -> Role:Scope
    valid_seconds=3600 * 24 * 30 # 30 days
)
print(f"Your secret key is: {key.plaintext}")
```

### 2. Protecting Endpoints
The standard `get_current_user` and `PermissionChecker` dependencies support API keys automatically if `STRATEGY` includes `BEARER`.

```python
@app.get("/data")
async def get_data(user = Depends(get_current_user)):
    # works with both Session Cookie and Authorization: Bearer <key>
    return {"data": "..."}
```

### 3. Master Keys
Use Master keys for internal CLI tools or scripts that need full owner access.

```python
master_key = await auth_service.api.create_key(
    user_id="admin_id",
    name="Admin CLI",
    key_type="MASTER"
)
```

## Security Flow
1.  Middleware detects `Authorization: Bearer <token>`.
2.  `validate_key` splits the token into ID and Secret.
3.  Secret is verified against the hash in the DB.
4.  The associated `user_id` and `scopes` are injected into the request state.

## Best Practices
- **Rotation**: Encourage users to rotate keys regularly using `expires_at`.
- **Public Keys**: Use public keys for client-side operations that only need to identify the user (e.g., analytics).
- **Naming**: Always give keys descriptive names for the audit trail.
