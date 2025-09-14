import os
import asyncio
import pytest
from fastapi import FastAPI, Request
from typing import AsyncGenerator
import pytest_asyncio

# --- Test Database File Path ---
TEST_DB_FILE = "./authtuna_test.db"

# --- Set environment variables for the test session ---
os.environ.setdefault("API_BASE_URL", "http://localhost:8000")
os.environ.setdefault("DEFAULT_DATABASE_URI", f'sqlite+aiosqlite:///{TEST_DB_FILE}')
os.environ.setdefault("AUTO_CREATE_DATABASE", "true")  # Keep this for library logic
os.environ.setdefault("EMAIL_ENABLED", "false")
os.environ.setdefault("SESSION_SECURE", "false")
os.environ["FERNET_KEYS"] = '["wZOUdnRNAbwg2CMn0J5akHdqVTxl64d-Hexi1HlGYQk="]'

# --- Import library modules AFTER setting config ---
from authtuna.core.database import db_manager, Base, engine
from authtuna.middlewares.session import DatabaseSessionMiddleware


# NOTE: The incorrect 'import models' is now removed.


# --- Pytest Fixtures ---

@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def manage_db_lifecycle():
    """
    Manages the entire test database lifecycle for the session.
    1. Deletes the old DB file.
    2. Explicitly triggers the library's DB initialization to create the schema.
    3. Yields to let all tests run.
    4. Disposes the engine to release the file lock.
    5. Deletes the DB file.
    """
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

    # --- SOLUTION PART 1: Initialize DB before any tests run ---
    # We manually trigger your library's own setup logic once per session.
    # This creates the schema and all tables before the first cleanup fixture runs.
    await db_manager.initialize_database()

    yield

    # --- SOLUTION PART 2: Cleanly shut down the engine ---
    # This closes all connections, releasing the lock on the db file.
    await engine.dispose()

    # Now we can safely remove the file.
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)


@pytest_asyncio.fixture(autouse=True)
async def clean_db_between_tests():
    """Ensure each test runs on a clean database by deleting all data from tables."""
    async with engine.begin() as conn:
        if engine.dialect.name == 'sqlite':
            await conn.exec_driver_sql("PRAGMA foreign_keys=OFF;")
        # This loop now works because manage_db_lifecycle already created the tables.
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
        if engine.dialect.name == 'sqlite':
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON;")
    yield


@pytest.fixture()
def app() -> FastAPI:
    """Provide a fresh FastAPI app instance for each test that needs it."""
    app = FastAPI()
    app.add_middleware(DatabaseSessionMiddleware, public_docs=True)

    @app.get("/public")
    async def public():
        return {"ok": True}

    @app.get("/protected")
    async def protected(request: Request):
        print(request.state.user_id)
        print(request.state.session_id)
        return {"user_id": getattr(request.state, "user_id", None)}

    return app

