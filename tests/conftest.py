import sys
import asyncio
if sys.version_info < (3, 9):
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import os
from fastapi import FastAPI
os.environ["API_BASE_URL"] = "http://127.0.0.1:8000"
os.environ["FERNET_KEYS"] = f'["wZOUdnRNAbwg2CMn0J5akHdqVTxl64d-Hexi1HlGYQk="]'
os.environ["JWT_SECRET_KEY"] = "test-secret"
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
os.environ["DEFAULT_DATABASE_URI"] = TEST_DATABASE_URL
os.environ["GITHUB_CLIENT_ID"] = "test-github-client-id"
os.environ["GITHUB_CLIENT_SECRET"] = "test-github-client-secret"
os.environ["GOOGLE_CLIENT_ID"] = "test-google-client-id"
os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-client-secret"
from authtuna.core.database import Base, db_manager
from authtuna.manager.asynchronous import AuthTunaAsync


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def engine():
    """Create an async engine for the test database."""
    return create_async_engine(TEST_DATABASE_URL, echo=False)

@pytest.fixture(scope="session", autouse=True)
async def tables(engine):
    """Create all tables in the test database for the session."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def dbsession(engine):
    """Create a new database session for each test."""
    async_session_factory = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session_factory() as session:
        yield session

@pytest.fixture
def auth_tuna_async(dbsession):
    """Create an instance of the AuthTunaAsync class with a test session."""
    db_manager.AsyncSessionLocal = sessionmaker(
        dbsession.bind, class_=AsyncSession, expire_on_commit=False
    )
    return AuthTunaAsync(db_manager)


@pytest.fixture
async def authenticated_user(auth_tuna_async):
    """
    Creates and returns a new user for testing authenticated endpoints.
    """
    # Use a unique email/username for each test run to avoid conflicts
    import time
    timestamp = int(time.time() * 1000)
    user = await auth_tuna_async.users.create(
        email=f"testuser_{timestamp}@example.com",
        username=f"testuser_{timestamp}",
        password="password123",
        ip_address="127.0.0.1"
    )
    return user


@pytest.fixture(scope="session")
def app():
    """Define a minimal FastAPI app for testing."""
    from authtuna import init_app
    app = FastAPI()
    init_app(app)
    return app

@pytest.fixture
async def fastapi_client(app):
    """Provide an AsyncClient for testing the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
