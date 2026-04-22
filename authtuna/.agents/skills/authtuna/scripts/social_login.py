from fastapi import FastAPI
from authtuna import init_app
from authtuna.routers import social

app = FastAPI()

# 1. Initialize AuthTuna
init_app(app)

# 2. Include the Social Router
# This mounts:
# - /auth/social/google/login
# - /auth/social/google/callback
# - /auth/social/github/login
# - /auth/social/github/callback
app.include_router(
    social.router, 
    prefix="/auth/social", 
    tags=["Authentication"]
)

# Configuration required in .env:
# GOOGLE_CLIENT_ID=...
# GOOGLE_CLIENT_SECRET=...
# GOOGLE_REDIRECT_URI=http://localhost:8000/auth/social/google/callback
# GITHUB_CLIENT_ID=...
# GITHUB_CLIENT_SECRET=...
# GITHUB_REDIRECT_URI=http://localhost:8000/auth/social/github/callback

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
