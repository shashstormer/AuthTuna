import asyncio
from authtuna.integrations import auth_service

async def manage_api_keys():
    user_id = "user123"
    
    # 1. Create a new API Key
    # Scopes allow restricting the key to specific operations
    api_key = await auth_service.api.create_key(
        user_id=user_id,
        name="Server Integration",
        scopes=["posts:write", "analytics:read"],
        valid_seconds=3600 * 24 * 30  # 30 days
    )
    
    # IMPORTANT: The plaintext key is only available once
    print(f"Your API Key: {api_key.plaintext}")
    
    # 2. List keys
    keys = await auth_service.api.get_all_keys_for_user(user_id)
    for k in keys:
        print(f"Key: {k.name}, ID: {k.id}, Scopes: {k.scopes}")
        
    # 3. Revoke a key
    await auth_service.api.delete_key(api_key.id)
    print("Key revoked.")

if __name__ == "__main__":
    asyncio.run(manage_api_keys())
