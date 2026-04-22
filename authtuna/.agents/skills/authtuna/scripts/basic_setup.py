import uvicorn
from fastapi import FastAPI, Depends
from authtuna import init_app
from authtuna.integrations.fastapi_integration import get_current_user, auth_service
from authtuna.middlewares.session import DatabaseSessionMiddleware

app = FastAPI(title="AuthTuna Basic Setup")

# 1. Initialize AuthTuna
# This automatically mounts auth routes (/auth/login, /auth/register, etc.)
# and initializes the database tables.
init_app(app)

# 2. Add Session Middleware
app.add_middleware(DatabaseSessionMiddleware)

@app.get("/")
async def root():
    return {"message": "AuthTuna is running!"}

@app.get("/me")
async def get_me(user=Depends(get_current_user)):
    """
    This endpoint is protected. get_current_user will:
    - Check session cookies
    - Check Bearer tokens
    - Check api_key query params
    Returns the User object or raises 401.
    """
    return {
        "id": user.id,
        "username": user.username,
        "email": user.get_email(),  # Handles PII decryption if enabled
        "roles": [role.name for role in user.roles]
    }

if __name__ == "__main__":
    # Ensure you have .env configured with:
    # API_BASE_URL, FERNET_KEYS, DEFAULT_DATABASE_URI
    uvicorn.run(app, host="0.0.0.0", port=8000)
